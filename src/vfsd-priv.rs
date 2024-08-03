#![feature(unix_socket_ancillary_data)]

mod oslib;
mod filehandle;

use crate::fs::File;
use clap::Parser;
use libc::*;
use std::fs;
use std::io;
use std::io::IoSliceMut;
use std::mem;
use std::os::fd::AsRawFd;
use std::os::fd::RawFd;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{AncillaryData, SocketAncillary};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::ptr;
use std::thread;
use syscalls::{syscall, SyscallArgs};

use crate::oslib::get_process_fd;
use filehandle::{CFileHandle, FileHandle};
use crate::filehandle::{MAX_HANDLE_SZ, MountId};

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
fn is_cookie_valid(fd: RawFd, id: u64) {
    ioctl_seccomp(
        fd as usize,
        SECCOMP_IOCTL_NOTIF_ID_VALID,
        ptr::addr_of!(id) as usize,
    );
}

/*
 * C struct from: include/linux/fs.h
 *
 *    struct file_handle {
 *          __u32 handle_bytes;
 *          int handle_type;
 *          /* file identifier */
 *          unsigned char f_handle[];
 *    };
 */

#[repr(C)]
#[derive(Debug, Default)]
struct FileHandleHeader {
    handle_bytes: u32,
    handle_type: c_int,
}

fn process_name_to_handle_at(pid: u32, fd: u64) -> FileHandle {
    // Note: get a FD dup, instead of using "pidfd_open/pidfd_getfd" we can open
    // "/proc/{pid}/fd/{fd}", we should check which one is faster, taking into account
    // that we can cache the "pidfd". (I think pidfd_getfd() is faster but I could be wrong,
    // so we need to benchmark it.
    let fd = get_process_fd(pid, fd).expect("file fd");

    // Note: name_to_handle_at() returns EOPNOTSUPP if the fs is overlayfs
    // Note: we allocate MAX_HANDLE_SZ, but we should set "handle_bytes: MAX_HANDLE_SZ - signature_size"
    // to make space for the signature and check for `EOVERFLOW`. Or make virtiofsd to allocate
    // "handle_bytes: MAX_HANDLE_SZ + signature_size", but we MUST send MAX_HANDLE_SZ bytes, because
    // we cannot allocate more the MAX_HANDLE_SZ bytes, from name_to_handle_at(2):
    //      "EINVAL handle->handle_bytes is greater than MAX_HANDLE_SZ."
    //
    // If we don't want to use an extra byte, instead of checking the signature we can
    // just XOR the signature at the end of the file handle, if the result is invalid
    // open_by_handle_at() will return an error, but we could get a valid FH just by (bad) luck
    FileHandle::from_fd(&fd).expect("get filename fh")
    // maybe we could return fd, to delay the close() syscall after writing the FH
}

fn is_mount_id_allowed(_mnt_id: MountId) -> bool {
    // TODO: we need to check if the mount id is the PVC in the POD
    return true
}

// ugly, but mutating the parameter will save us a memcopy
// (maybe is unnecessary if the compiler is smart enough(?))
fn sign(fh: &mut FileHandle) {
    // TODO: do a proper signing
    // Note: according to FIPS we can safely truncate a HMAC to 64 bit, but probably we
    // should include an extra byte to define the algorithm, just in case we need to change it
    // in the future, allowing updating virtiofsd "in-place" via migration (I think this is a
    // Kubevirt requirement).

    // for now lets just add a sum at the end of the fh_handle
    let sum: u64 = fh.handle.f_handle.iter().fold(0, |acc, x| acc + *x as u64);
    println!("FH signature: {:?}", sum.to_ne_bytes());
    const SIGN_SIZE_BYTES: usize = (u64::BITS / 8) as usize;
    const START: usize = MAX_HANDLE_SZ - SIGN_SIZE_BYTES;
    fh.handle.f_handle[START..].copy_from_slice(&sum.to_ne_bytes());
}

fn do_name_to_handle_at(fd: RawFd, req: &SeccompNotif) {
    println!("process pid: {}", req.pid);
    println!(
        "process args: dir_Fd {}, pathname addr: 0x{:x},  fh addr: 0x{:x}, mount_id addr: {:x}",
        req.data.args[0], req.data.args[1], req.data.args[2], req.data.args[3]
    );

    is_cookie_valid(fd, req.id);
    // Read file handle from proc
    // Note: we should use 'process_vm_readv/process_vm_writev' it should be faster since is just a single syscall
    let fh = FileHandleHeader::default();
    let file = File::options()
        .read(true)
        .write(true)
        .open(format!("/proc/{}/mem", req.pid))
        .expect("failed to open mem from proc");
    let mem_fd = file.as_fd().as_raw_fd();
    let addr = req.data.args[2].try_into().unwrap();

    // Note: If we need to read the pathname (I don't think so)
    // this can be tricky to make it safe

    // let's read just the header
    // Note: we don't really need to read it, we know virtiofsd will allocate 128 bytes
    unsafe {
        syscall(
            syscalls::Sysno::pread64,
            &SyscallArgs::new(
                mem_fd as usize,
                ptr::addr_of!(fh) as usize,
                mem::size_of::<FileHandleHeader>(),
                addr,
                0,
                0,
            ),
        )
        .expect("pread failed");
    }

    println!("\nFH header: {:?}\n", fh);

    let mut fh = process_name_to_handle_at(req.pid, req.data.args[0]);
    println!("Received FH : {:?}", fh);

    // check if mount id is allowed
    if !is_mount_id_allowed(fh.mnt_id) {
        // TODO: return EACCES or EBADF? (see openat(2))
    }

    // sign FH
    sign(&mut fh);

    // write the whole file handle at once
    unsafe {
        syscall(
            syscalls::Sysno::pwrite64,
            &SyscallArgs::new(
                mem_fd as usize,
                ptr::addr_of!(fh.handle) as usize,
                mem::size_of::<CFileHandle>(),
                req.data.args[2].try_into().unwrap(),
                0,
                0,
            ),
        )
        .expect("write failed");
    }
}

fn do_operations(fd: RawFd, nr: syscalls::Sysno, req: &SeccompNotif) {
    match nr {
        syscalls::Sysno::name_to_handle_at => do_name_to_handle_at(fd, req),
        syscalls::Sysno::open_by_handle_at => println!("open_by_handle_at not implemented yet"),
        _ => println!("no operation implemented for {}", nr.name()),
    }
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
        if let Some(s) = syscalls::Sysno::new(req.data.nr as usize) {
            println!("recieved syscall: {}", s.name());
            do_operations(fd, s, &req);
        } else {
            panic!("syscall nr: {} not recognized", req.data.nr)
        }

        // TODO: Return the corresponding result to the target process to unblock the syscall.
        // For now, we simply return success
        is_cookie_valid(fd, req.id);
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

    fs::set_permissions(args.socket, fs::Permissions::from_mode(0o777))
        .expect("set the socket permission");

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