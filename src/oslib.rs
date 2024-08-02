use std::io;
use std::io::Error;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

unsafe fn pidfd_open(pid: libc::pid_t, flags: libc::c_uint) -> libc::c_int {
    libc::syscall(libc::SYS_pidfd_open, pid, flags) as _
}

unsafe fn pidfd_getfd(
    pidfd: libc::c_int,
    targetfd: libc::c_int,
    flags: libc::c_uint,
) -> libc::c_int {
    libc::syscall(libc::SYS_pidfd_getfd, pidfd, targetfd, flags) as _
}

pub fn get_process_fd(pid: u32, target_fd: u64) -> io::Result<OwnedFd> {
    let pid_fd = unsafe { pidfd_open(pid as _, 0) };
    if pid_fd == -1 {
        return Err(Error::last_os_error());
    }
    let pid_fd = unsafe { OwnedFd::from_raw_fd(pid_fd) };

    let res = unsafe { pidfd_getfd(pid_fd.as_raw_fd(), target_fd as libc::c_int, 0) };
    if res == -1 {
        return Err(Error::last_os_error());
    }
    let res = unsafe { OwnedFd::from_raw_fd(res) };

    Ok(res)
}
