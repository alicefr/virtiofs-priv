#![feature(unix_socket_ancillary_data)]
use clap::Parser;
use libc::*;
use std::fs;
use std::io;
use std::io::IoSliceMut;
use std::os::fd::RawFd;
use std::os::unix::net::{AncillaryData, SocketAncillary};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::ptr;
use std::thread;
use syscalls::{syscall, SyscallArgs};

/// Monitor rootless virtiofs
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    socket: String,
}

const MAX_EVENTS: usize = 10;

/* Structs from linux kernel: include/uapi/linux/seccomp.h
*  struct seccomp_data {
*           int nr;
*          __u32 arch;
*          __u64 instruction_pointer;
*          __u64 args[6];
*  };
*
*  struct seccomp_notif {
*          __u64 id;
*          __u32 pid;
*          __u32 flags;
*          struct seccomp_data data;
*  };
*  struct seccomp_notif_resp {
*          __u64 id;
*          __s64 val;
*          __s32 error;
*          __u32 flags;
*  };
*/

// Only for x86_64
const SECCOMP_IOCTL_NOTIF_RECV: usize = 0xc0502100;
const SECCOMP_IOCTL_NOTIF_ID_VALID: usize = 0x40082102;
const SECCOMP_IOCTL_NOTIF_SEND: usize = 0xc0182101;

#[repr(C)]
#[derive(Default)]
struct SeccompData {
    nr: c_int,
    arch: u32,
    instruction_pointer: u64,
    args: [u64; 6],
}

#[repr(C)]
#[derive(Default)]
struct SeccompNotif {
    id: u64,
    pid: u32,
    flags: u32,
    data: SeccompData,
}

#[repr(C)]
#[derive(Default)]
struct SeccompNotifResp {
    id: u64,
    val: i64,
    error: i32,
    flags: u32,
}

fn ioctl_seccomp(arg0: usize, arg1: usize, arg2: usize) {
    unsafe {
        syscall(
            syscalls::Sysno::ioctl,
            &SyscallArgs::new(arg0, arg1, arg2, 0, 0, 0),
        )
        .expect("ioctl failed");
    }
    ()
}

fn epoll_create(fd: RawFd) -> io::Result<RawFd> {
    if fd < 0 {
        panic!("Invalid fd")
    }
    let epoll_fd = unsafe {
        syscall(
            syscalls::Sysno::epoll_create1,
            &SyscallArgs::new(0, 0, 0, 0, 0, 0),
        )
        .expect("epoll_create1 failed")
    };
    let event = libc::epoll_event {
        events: EPOLLIN as u32,
        u64: fd as u64,
    };
    unsafe {
        syscall(
            syscalls::Sysno::epoll_ctl,
            &SyscallArgs::new(
                epoll_fd as usize,
                libc::EPOLL_CTL_ADD as usize,
                fd as usize,
                ptr::addr_of!(event) as usize,
                0,
                0,
            ),
        )
        .expect("epoll_ctl failed");
    };

    Ok(epoll_fd as i32)
}

fn monitor_process(fd: RawFd) {
    let epoll_fd = epoll_create(fd).expect("failed to create events");
    // Start monitoring the process with the seccomp notifier
    loop {
        let events = [libc::epoll_event { events: 0, u64: 0 }; MAX_EVENTS];
        unsafe {
            syscall(
                syscalls::Sysno::epoll_wait,
                &SyscallArgs::new(
                    epoll_fd as usize,
                    ptr::addr_of!(events) as usize,
                    MAX_EVENTS,
                    i32::from(-1) as usize,
                    0,
                    0,
                ),
            )
            .expect("epoll_create1 failed")
        };
        let req = SeccompNotif::default();
        let mut resp = SeccompNotifResp::default();
        ioctl_seccomp(
            fd as usize,
            SECCOMP_IOCTL_NOTIF_RECV,
            ptr::addr_of!(req) as usize,
        );
        if let Some(syscall) = syscalls::Sysno::new(req.data.nr as usize) {
            println!("recieved syscall: {}", syscall.name());
        } else {
            println!("recieved syscall nr: {}", req.data.nr);
        }
        // TODO: Execute the privileged operation
        println!("Execute privileged operation");

        // TODO: Return the corresponding result to the target process to unblock the syscall.
        // For now, we simply return success
        // Validate if the ID of the request is still valid
        let id = req.id;
        ioctl_seccomp(
            fd as usize,
            SECCOMP_IOCTL_NOTIF_ID_VALID,
            ptr::addr_of!(id) as usize,
        );
        resp.id = req.id;
        // Let the syscall of the target return
        ioctl_seccomp(
            fd as usize,
            SECCOMP_IOCTL_NOTIF_SEND,
            ptr::addr_of!(resp) as usize,
        )
    }
}

fn handle_client(socket: UnixStream) {
    println!("handle connection");
    // Read the fd from the ancillary data
    let mut buf1 = [1; 8];
    let mut buf2 = [2; 16];
    let mut buf3 = [3; 8];
    let bufs = &mut [
        IoSliceMut::new(&mut buf1),
        IoSliceMut::new(&mut buf2),
        IoSliceMut::new(&mut buf3),
    ][..];
    //    let mut fds = [0; 8];
    let mut ancillary_buffer = [0; 128];
    let mut ancillary = SocketAncillary::new(&mut ancillary_buffer[..]);
    match socket.recv_vectored_with_ancillary(bufs, &mut ancillary) {
        Ok(data) => data,
        Err(e) => panic!("wrong type of data recieved {e}"),
    };
    for ancillary_result in ancillary.messages() {
        if let AncillaryData::ScmRights(mut scm_rights) = match ancillary_result {
            Ok(data) => data,
            Err(_) => panic!("wrong type of data recieved"),
        } {
            // TODO: error if there are more then 1 fd
            if let Some(fd) = scm_rights.next() {
                println!("recieved fd: {}", fd);
                monitor_process(fd)
            };
        }
    }
}

fn main() -> std::io::Result<()> {
    let args = Args::parse();
    println!("Socket path file: {}", args.socket);
    if Path::new(&args.socket).exists() {
        fs::remove_file(args.socket.clone())?;
    }
    let listener = UnixListener::bind(args.socket.clone())?;
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                // Spawn thread to start monitoring each process
                thread::spawn(|| handle_client(stream));
            }
            Err(_) => {
                break;
            }
        }
    }
    Ok(())
}
