use std::ffi::CString;
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd};

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
