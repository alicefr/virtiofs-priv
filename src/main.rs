#![feature(unix_socket_ancillary_data)]
use clap::Parser;
use libc::*;
use std::error::Error;
use std::fs;
use std::io::IoSliceMut;
use std::os::fd::RawFd;
use std::os::unix::net::{AncillaryData, SocketAncillary};
use std::os::unix::net::{UnixListener, UnixStream};
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
struct SeccompData {
    nr: c_int,
    arch: c_uint,
    instruction_pointer: c_ulonglong,
    args: [c_ulonglong; 6],
}

impl Default for SeccompData {
    fn default() -> SeccompData {
        SeccompData {
            nr: 0,
            arch: 0,
            instruction_pointer: 0,
            args: [0, 0, 0, 0, 0, 0],
        }
    }
}

#[repr(C)]
struct SeccompNotif {
    id: c_ulonglong,
    pid: c_uint,
    flags: c_uint,
    data: SeccompData,
}

impl Default for SeccompNotif {
    fn default() -> SeccompNotif {
        SeccompNotif {
            id: 0,
            pid: 0,
            flags: 0,
            data: SeccompData::default(),
        }
    }
}

#[repr(C)]
struct SeccompNotifResp {
    id: c_ulonglong,
    val: c_long,
    error: c_int,
    flags: c_uint,
}

impl Default for SeccompNotifResp {
    fn default() -> SeccompNotifResp {
        SeccompNotifResp {
            id: 0,
            val: 0,
            error: 0,
            flags: 0,
        }
    }
}

fn ioctl_seccomp(arg0: usize, arg1: usize, arg2: usize) {
    let args = SyscallArgs {
        arg0: arg0,
        arg1: arg1,
        arg2: arg2,
        arg3: 0,
        arg4: 0,
        arg5: 0,
    };
    match unsafe { syscall(syscalls::Sysno::ioctl, &args) } {
        Ok(0) => println!("recieved notification"),
        Ok(ret) => println!("wrong return values: {}", ret),
        Err(err) => panic!("ioctl failed: {}", err),
    };
}

fn monitor_process(fd: RawFd) {
    // Start monitoring the process with the seccomp notifier
    let mut req = SeccompNotif::default();
    let mut resp = SeccompNotifResp::default();
    // TODO: create polling of events to serve multiple syscalls
    ioctl_seccomp(
        fd as usize,
        SECCOMP_IOCTL_NOTIF_RECV,
        ptr::addr_of!(req) as usize,
    );
    if let Some(syscall) = syscalls::Sysno::new(req.data.nr as usize) {
        println!("syscall: {}", syscall.name());
    }
    println!("syscall nr: {}", req.data.nr);
    // TODO: Execute the privileged operation
    println!("Execute privileged operation");

    // TODO: Return the corresponding result to the target process to unblock the syscall.
    // For now, we simply return success
    // Validate if the ID of the request is still valid
    let id = req.id;
    println!("test id:{:#x}", id);
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

fn handle_client(socket: UnixStream) {
    println!("handle connection");
    // Read the fd from the ancillary data
    let mut buf1 = [1; 8];
    let mut buf2 = [2; 16];
    let mut buf3 = [3; 8];
    let mut bufs = &mut [
        IoSliceMut::new(&mut buf1),
        IoSliceMut::new(&mut buf2),
        IoSliceMut::new(&mut buf3),
    ][..];
    let mut fds = [0; 8];
    let mut ancillary_buffer = [0; 128];
    let mut ancillary = SocketAncillary::new(&mut ancillary_buffer[..]);
    let size = match socket.recv_vectored_with_ancillary(bufs, &mut ancillary) {
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
    fs::remove_file(args.socket.clone())?;
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
