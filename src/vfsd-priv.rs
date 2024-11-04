#![feature(unix_socket_ancillary_data)]

mod filehandle;
mod oslib;

use crate::fs::File;
use clap::Parser;
use libc::*;
use std::error::Error;
use std::fmt;
use std::fs;
use std::io;
use std::io::IoSliceMut;
use std::mem;
use std::os::fd::AsFd;
use std::os::fd::AsRawFd;
use std::os::fd::RawFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{AncillaryData, SocketAncillary};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::ptr;
use std::thread;
use syscalls::{syscall, SyscallArgs};

extern crate vmm_sys_util;
use vmm_sys_util::epoll::{ControlOperation, Epoll, EpollEvent, EventSet};

use crate::filehandle::{MountId, MAX_HANDLE_SZ};
use crate::oslib::get_process_fd;
use filehandle::{CFileHandle, FileHandle};

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
*
*  struct seccomp_notif_addfd {
*          __u64 id;           /* Cookie value */
*          __u32 flags;        /* Flags */
*          __u32 srcfd;        /* Local file descriptor number */
*          __u32 newfd;        /* 0 or desired file descriptor
*                                 number in target */
*          __u32 newfd_flags;  /* Flags to set on target file
*                            descriptor */
*  };
*/

// Only for x86_64
const SECCOMP_IOCTL_NOTIF_RECV: usize = 0xc0502100;
const SECCOMP_IOCTL_NOTIF_ID_VALID: usize = 0x40082102;
const SECCOMP_IOCTL_NOTIF_SEND: usize = 0xc0182101;
const SECCOMP_IOCTL_NOTIF_ADDFD: usize = 0x40182103;

#[repr(C)]
#[derive(Default, Debug)]
struct SeccompData {
    nr: c_int,
    arch: u32,
    instruction_pointer: u64,
    args: [u64; 6],
}

#[repr(C)]
#[derive(Default, Debug)]
struct SeccompNotif {
    id: u64,
    pid: u32,
    flags: u32,
    data: SeccompData,
}

#[repr(C)]
#[derive(Default, Debug)]
struct SeccompNotifResp {
    id: u64,
    val: i64,
    error: i32,
    flags: u32,
}

#[repr(C)]
#[derive(Default, Debug)]
struct SeccompNotifAddfd {
    id: u64,
    flags: u32,
    srcfd: u32,
    newfd: u32,
    newfd_flags: u32,
}

fn ioctl_seccomp(arg0: usize, arg1: usize, arg2: usize) -> Result<usize, OpError> {
    unsafe {
        match syscall(
            syscalls::Sysno::ioctl,
            &SyscallArgs::new(arg0, arg1, arg2, 0, 0, 0),
        ) {
            Ok(res) => Ok(res),
            Err(err) => Err(OpError::new(format!("ioctl failed: {}", err).as_str())),
        }
    }
}

fn is_cookie_valid(fd: RawFd, id: u64) -> bool {
    match ioctl_seccomp(
        fd as usize,
        SECCOMP_IOCTL_NOTIF_ID_VALID,
        ptr::addr_of!(id) as usize,
    ) {
        Ok(_) => true,
        Err(_) => false,
    }
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

struct ResultOp {
    val: i64,
    error: i32,
}

fn process_name_to_handle_at(pid: u32, fd: u64) -> io::Result<FileHandle> {
    // Note: get a FD dup, instead of using "pidfd_open/pidfd_getfd" we can open
    // "/proc/{pid}/fd/{fd}", we should check which one is faster, taking into account
    // that we can cache the "pidfd". (I think pidfd_getfd() is faster but I could be wrong,
    // so we need to benchmark it.
    let fd = get_process_fd(pid, fd)?;

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
    FileHandle::from_fd(&fd)
    // maybe we could return fd, to delay the close() syscall after writing the FH
}

fn is_mount_id_allowed(_mnt_id: MountId) -> bool {
    // TODO: we need to check if the mount id is the PVC in the POD
    return true;
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

#[derive(Debug)]
struct OpError {
    msg: String,
}

impl OpError {
    fn new(msg: &str) -> OpError {
        OpError {
            msg: msg.to_string(),
        }
    }
}

impl fmt::Display for OpError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.msg)
    }
}

impl Error for OpError {
    fn description(&self) -> &str {
        &self.msg
    }
}

fn write_file_handler(fh: &FileHandle, pid: u32, addr: u64) -> Result<(), OpError> {
    let remote = iovec {
        iov_base: addr as *mut c_void,
        iov_len: mem::size_of::<CFileHandle>(),
    };
    let local = iovec {
        iov_base: ptr::addr_of!(fh.handle) as *mut c_void,
        iov_len: mem::size_of::<CFileHandle>(),
    };
    unsafe {
        if let Err(err) = syscall(
            syscalls::Sysno::process_vm_writev,
            &SyscallArgs::new(
                pid as usize,
                ptr::addr_of!(local) as usize,
                1,
                ptr::addr_of!(remote) as usize,
                1,
                0,
            ),
        ) {
            return Err(OpError::new(
                format!("process_vm_writev failed: {}", err).as_str(),
            ));
        }
    }
    Ok(())
}

// FIXME: this function is redundant we should write the mount_id in a single
// process_vm_writev by adding a extra iovec element
fn write_mount_id(mntid: MountId, pid: u32, addr: u64) -> Result<(), OpError> {
    let remote = iovec {
        iov_base: addr as *mut c_void,
        iov_len: mem::size_of::<MountId>(),
    };
    let local = iovec {
        iov_base: ptr::addr_of!(mntid) as *mut c_void,
        iov_len: mem::size_of::<MountId>(),
    };
    unsafe {
        if let Err(err) = syscall(
            syscalls::Sysno::process_vm_writev,
            &SyscallArgs::new(
                pid as usize,
                ptr::addr_of!(local) as usize,
                1,
                ptr::addr_of!(remote) as usize,
                1,
                0,
            ),
        ) {
            return Err(OpError::new(
                format!("process_vm_writev failed: {}", err).as_str(),
            ));
        }
    }
    Ok(())
}

fn read_file_handler(pid: u32, addr: u64) -> Result<CFileHandle, OpError> {
    let fh = CFileHandle::default();
    let remote = iovec {
        iov_base: addr as *mut c_void,
        iov_len: mem::size_of::<CFileHandle>(),
    };
    let local = iovec {
        iov_base: ptr::addr_of!(fh) as *mut c_void,
        iov_len: mem::size_of::<CFileHandle>(),
    };
    unsafe {
        if let Err(err) = syscall(
            syscalls::Sysno::process_vm_readv,
            &SyscallArgs::new(
                pid as usize,
                ptr::addr_of!(local) as usize,
                1,
                ptr::addr_of!(remote) as usize,
                1,
                0,
            ),
        ) {
            return Err(OpError::new(
                format!("process_vm_read failed: {}", err).as_str(),
            ));
        }
    }
    Ok(fh)
}

fn do_name_to_handle_at(req: &SeccompNotif) -> ResultOp {
    println!("process req: {req:?}");

    println!("process pid: {}", req.pid);
    println!(
        "process args: dir_Fd {}, pathname addr: 0x{:x},  fh addr: 0x{:x}, mount_id addr: {:x}",
        req.data.args[0], req.data.args[1], req.data.args[2], req.data.args[3]
    );
    // Do we need this?
    // let fh = match read_file_handler(req.pid, req.data.args[2]) {
    //     Ok(fh) => fh,
    //     Err(err) => {
    //         println!("{}", err);
    //         return ResultOp { val: 0, error: -1 };
    //     }
    // };
    // println!("\nFH: {:?}\n", fh);

    let fh = match process_name_to_handle_at(req.pid, req.data.args[0]) {
        Ok(fh) => fh,
        Err(err) => {
            println!("process_name_to_handle_at error: {err:?}");
            return ResultOp { error: -1, val: 0 };
        }
    };

    println!("Received FH : {:?}", fh);

    // check if mount id is allowed
    if !is_mount_id_allowed(fh.mnt_id) {
        return ResultOp { error: -1, val: 0 };
    }

    // sign FH
    //sign(&mut fh);

    if let Err(err) = write_file_handler(&fh, req.pid, req.data.args[2]) {
        println!("failed to write the file handler: {}", err);
        return ResultOp { val: 0, error: -1 };
    }

    if let Err(err) = write_mount_id(fh.mnt_id, req.pid, req.data.args[3]) {
        println!("failed to write the mount id: {}", err);
        return ResultOp { val: 0, error: -1 };
    }

    ResultOp { val: 0, error: 0 }
}

fn create_fd_target(fd: RawFd, id: u64, srcfd: usize) -> Result<usize, OpError> {
    let resp = SeccompNotifAddfd {
        id: id,
        flags: 0,
        srcfd: srcfd as u32,
        newfd: 0,
        newfd_flags: 0,
    };
    match ioctl_seccomp(
        fd as usize,
        SECCOMP_IOCTL_NOTIF_ADDFD,
        ptr::addr_of!(resp) as usize,
    ) {
        Ok(fd) => Ok(fd),
        Err(err) => Err(err),
    }
}

fn do_open_by_handle_at(fd: RawFd, req: &SeccompNotif) -> ResultOp {
    if !is_cookie_valid(fd, req.id) {
        println!("cookie isn't valid");
        return ResultOp { val: 0, error: -1 };
    }
    let fhh = match read_file_handler(req.pid, req.data.args[1]) {
        Ok(fhh) => fhh,
        Err(err) => {
            println!("{}", err);
            return ResultOp { val: 0, error: -1 };
        }
    };
    // TODO: verify signature
    let mount_fd = match get_process_fd(req.pid, req.data.args[0]) {
        Ok(fd) => fd,
        Err(err) => {
            println!("failed to get mount fd: {}", err);
            return ResultOp { val: 0, error: -1 };
        }
    };

    let src_fd = unsafe {
        match syscall(
            syscalls::Sysno::open_by_handle_at,
            &SyscallArgs::new(
                mount_fd.as_fd().as_raw_fd() as usize,
                ptr::addr_of!(fhh) as usize,
                (req.data.args[2] & !(libc::O_PATH as u64)) as usize,
                0,
                0,
                0,
            ),
        ) {
            Ok(fd) => fd,
            Err(err) => {
                println!("open_by_handle_at error: {}", err);
                return ResultOp { val: 0, error: -1 };
            }
        }
    };

    println!("do_open_by_handle_at: src_fd = {}", src_fd);
    let target_fd = match create_fd_target(fd, req.id, src_fd) {
        Ok(fd) => fd,
        Err(err) => {
            println!("do_open_by_handle_at: create_fd_target error: {err:?}");
            return ResultOp { val: 0, error: -1 };
        }
    };
    println!("fd: {}", target_fd);
    ResultOp {
        val: target_fd as i64,
        error: 0,
    }
}

fn set_mount_ns(pid: u32) -> Result<(), OpError> {
    let path = format!("/proc/{}/ns/mnt", pid);
    println!("Set mount namespace to {}", path);
    let file = match File::options().read(true).open(path) {
        Ok(f) => f,
        Err(err) => {
            print!("failed opening proc mnt");
            return Err(OpError::new(
                format!("failed to open mount ns from proc: {}", err).as_str(),
            ));
        }
    };
    unsafe {
        if let Err(err) = syscall(
            syscalls::Sysno::unshare,
            &SyscallArgs::new(CLONE_FS as usize, 0, 0, 0, 0, 0),
        ) {
            return Err(OpError::new(format!("unshare failed: {}", err).as_str()));
        }
    }
    unsafe {
        match syscall(
            syscalls::Sysno::setns,
            &SyscallArgs::new(
                file.as_fd().as_raw_fd() as usize,
                CLONE_NEWNS as usize,
                0,
                0,
                0,
                0,
            ),
        ) {
            Ok(_) => Ok(()),
            Err(err) => Err(OpError::new(format!("setns failed: {}", err).as_str())),
        }
    }
}

fn send_response(fd: RawFd, req: &SeccompNotif, res: &ResultOp) {
    is_cookie_valid(fd, req.id);
    let resp = SeccompNotifResp {
        id: req.id,
        val: res.val,
        error: res.error,
        flags: 0,
    };
    // Let the syscall of the target return
    ioctl_seccomp(
        fd as usize,
        SECCOMP_IOCTL_NOTIF_SEND,
        ptr::addr_of!(resp) as usize,
    )
    .expect("ioctl failed");
}

fn do_operations(fd: RawFd, nr: syscalls::Sysno, req: &SeccompNotif) {
    if let Err(err) = set_mount_ns(req.pid) {
        print!("Failed to set the mount ns: {}", err);
        return;
    }
    let res = match nr {
        syscalls::Sysno::name_to_handle_at => do_name_to_handle_at(req),
        syscalls::Sysno::open_by_handle_at => do_open_by_handle_at(fd, req),
        _ => {
            println!("no operation implemented for {}", nr.name());
            ResultOp { val: 0, error: -1 }
        }
    };
    send_response(fd, req, &res);
}

fn monitor_process(fd: RawFd) {
    let epoll = Epoll::new().unwrap();
    epoll
        .ctl(
            ControlOperation::Add,
            fd as i32,
            EpollEvent::new(EventSet::IN, fd as u64),
        )
        .unwrap();
    // Start monitoring the process with the seccomp notifier
    loop {
        let mut ready_events = vec![EpollEvent::default(); MAX_EVENTS];
        println!("Waiting syscall...");
        let n = epoll.wait(-1, &mut ready_events[..]).unwrap();
        for _ in 0..n {
            let req = SeccompNotif::default();
            let _ = ioctl_seccomp(
                fd as usize,
                SECCOMP_IOCTL_NOTIF_RECV,
                ptr::addr_of!(req) as usize,
            );
            match syscalls::Sysno::new(req.data.nr as usize) {
                Some(s) => {
                    println!("recieved syscall: {}", s.name());
                    thread::spawn(move || do_operations(fd, s, &req));
                }
                _ => panic!("syscall nr: {} not recognized", req.data.nr),
            };
        }
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
