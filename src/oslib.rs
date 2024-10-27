use std::ffi::{CStr, CString};
use std::fs::File;
use std::io;
use std::io::Error;
use std::mem::MaybeUninit;
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

const PIDFD_THREAD: libc::c_int = libc::O_EXCL;
pub fn get_process_fd(pid: u32, target_fd: u64) -> io::Result<OwnedFd> {
    println!("get_process_fd: pid: {pid} target_fd: {target_fd}");
    // Note: we should cache the process pidfd, so getting the fd will
    // be single syscall "pidfd_getfd"
    let pid_fd = unsafe { pidfd_open(pid as _, 0) };
    // FIXME: we need to use PIDFD_THREAD so pidfd_open can accept the TID instead of the PID,
    // this is not currently available in centos 9
    //let pid_fd = unsafe { pidfd_open(pid as _, PIDFD_THREAD as libc::c_uint) };
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

pub use libc::statx as statx_st;
use libc::{pid_t, STATX_BASIC_STATS, STATX_MNT_ID};
use procfs::process::Process;
use procfs::ProcResult;

unsafe fn do_statx(
    dirfd: libc::c_int,
    pathname: *const libc::c_char,
    flags: libc::c_int,
    mask: libc::c_uint,
    statxbuf: *mut statx_st,
) -> libc::c_int {
    libc::syscall(libc::SYS_statx, dirfd, pathname, flags, mask, statxbuf) as libc::c_int
}

const EMPTY_CSTR: &[u8] = b"\0";
pub fn statx(dir: &impl AsRawFd) -> io::Result<statx_st> {
    let mut stx_ui = MaybeUninit::<statx_st>::zeroed();

    // Safe because this is a constant value and a valid C string.
    let path = unsafe { CStr::from_bytes_with_nul_unchecked(EMPTY_CSTR) };

    // Safe because the kernel will only write data in `stx_ui` and we
    // check the return value.
    let res = unsafe {
        do_statx(
            dir.as_raw_fd(),
            path.as_ptr(),
            libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
            STATX_BASIC_STATS | STATX_MNT_ID,
            stx_ui.as_mut_ptr(),
        )
    };

    if res >= 0 {
        // Safe because we are only going to use the SafeStatXAccess
        // trait methods
        let stx = unsafe { stx_ui.assume_init() };

        // if `statx()` doesn't provide the mount id (before kernel 5.8),
        // let's try `name_to_handle_at()`, if everything fails just use 0
        Ok(stx)
    } else {
        Err(io::Error::last_os_error())
    }
}

pub fn get_process_info(pid: u32) -> ProcResult<Process> {
    Process::new(pid as i32)
}