use std::ffi::CString;
use std::fs::File;
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
    println!("get_process_fd: pid: {pid} target_fd: {target_fd}");
    // Note: we should cache the process pidfd, so getting the fd will
    // be single syscall "pidfd_getfd"
    let pid_fd = unsafe { pidfd_open(pid as _, 0) };
    if pid_fd == -1 {
        return Err(Error::last_os_error());
    }
    let pid_fd = unsafe { OwnedFd::from_raw_fd(pid_fd) };

    println!("get_process_fd: pidfd_getfd: {:?}", pid_fd);
    let res = unsafe { pidfd_getfd(pid_fd.as_raw_fd(), target_fd as libc::c_int, 0) };
    if res == -1 {
        return Err(Error::last_os_error());
    }
    let res = unsafe { OwnedFd::from_raw_fd(res) };

    Ok(res)
}

/// Safe wrapper around libc::openat().
pub fn openat(dir_fd: &impl AsRawFd, path: &str, flags: libc::c_int) -> io::Result<File> {
    let path_cstr =
        CString::new(path).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    // Safe because:
    // - CString::new() has returned success and thus guarantees `path_cstr` is a valid
    //   NUL-terminated string
    // - this does not modify any memory
    // - we check the return value
    // We do not check `flags` because if the kernel cannot handle poorly specified flags then we
    // have much bigger problems.
    let fd = unsafe { libc::openat(dir_fd.as_raw_fd(), path_cstr.as_ptr(), flags) };
    if fd >= 0 {
        // Safe because we just opened this fd
        Ok(unsafe { File::from_raw_fd(fd) })
    } else {
        Err(io::Error::last_os_error())
    }
}
