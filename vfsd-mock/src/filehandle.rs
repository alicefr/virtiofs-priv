use std::ffi::CStr;
use std::fs::File;
use std::io;
use std::io::Error;
use std::os::fd::{AsRawFd, FromRawFd};

pub use sys::CFileHandle;

const EMPTY_CSTR: &[u8] = b"\0";
pub type MountId = u64;

#[derive(Debug, Clone, PartialOrd, Ord, PartialEq, Eq)]
pub struct FileHandle {
    mnt_id: MountId,
    pub handle: CFileHandle,
}

impl FileHandle {
    /// Try to create a file handle for the given file.  In contrast to `from_name_at()`, this will
    /// always return a file handle or an error.
    pub fn from_name_at_fail_hard(dir: &impl AsRawFd, path: &CStr) -> io::Result<Self> {
        let mut mount_id: libc::c_int = 0;
        let mut c_fh = CFileHandle::default();

        name_to_handle_at(dir, path, &mut c_fh, &mut mount_id, libc::AT_EMPTY_PATH)?;
        Ok(FileHandle {
            mnt_id: mount_id as MountId,
            handle: c_fh,
        })
    }

    pub fn from_fd(fd: &impl AsRawFd) -> io::Result<Self> {
        // Safe because this is a constant value and a valid C string.
        let empty_path = unsafe { CStr::from_bytes_with_nul_unchecked(EMPTY_CSTR) };
        Self::from_name_at_fail_hard(fd, empty_path)
    }
}

// A helper function that check the return value of a C function call
// and wraps it in a `Result` type, returning the `errno` code as `Err`.
fn check_retval<T: From<i8> + PartialEq>(t: T) -> std::io::Result<T> {
    if t == T::from(-1_i8) {
        Err(Error::last_os_error())
    } else {
        Ok(t)
    }
}

pub fn name_to_handle_at(
    dirfd: &impl AsRawFd,
    pathname: &CStr,
    file_handle: &mut CFileHandle,
    mount_id: &mut libc::c_int,
    flags: libc::c_int,
) -> std::io::Result<()> {
    println!(
        "name_to_handle_at(dirfd: {}, pathname: {:?} (0x{:x}), fh addr: 0x{:x}, mount_id addr: 0x{:x})",
        dirfd.as_raw_fd(),
        pathname,
        pathname.as_ptr() as usize,
        file_handle as *mut CFileHandle as usize,
        mount_id as *mut libc::c_int as usize
    );
    // SAFETY: `dirfd` is a valid file descriptor, `file_handle`
    // is a valid reference to `CFileHandle`, and `mount_id` is
    // valid reference to an `int`
    check_retval(unsafe {
        sys::name_to_handle_at(
            dirfd.as_raw_fd(),
            pathname.as_ptr(),
            file_handle,
            mount_id,
            flags,
        )
    })?;
    Ok(())
}

pub fn open_by_handle_at(
    mount_fd: &impl AsRawFd,
    file_handle: &CFileHandle,
    flags: libc::c_int,
) -> std::io::Result<File> {
    println!(
        "open_by_handle_at(mount_fd: {}, fh addr: 0x{:x})",
        mount_fd.as_raw_fd(),
        file_handle as *const CFileHandle as usize
    );

    // SAFETY: `mount_fd` is a valid file descriptor and `file_handle`
    // is a valid reference to `CFileHandle`
    let fd =
        check_retval(unsafe { sys::open_by_handle_at(mount_fd.as_raw_fd(), file_handle, flags) })?;

    // SAFETY: `open_by_handle_at()` guarantees `fd` is a valid file descriptor
    Ok(unsafe { File::from_raw_fd(fd) })
}

mod sys {
    const MAX_HANDLE_SZ: usize = 128;

    #[derive(Debug, Clone, PartialOrd, Ord, PartialEq, Eq)]
    #[repr(C)]
    pub struct CFileHandle {
        handle_bytes: libc::c_uint,
        handle_type: libc::c_int,
        f_handle: [u8; MAX_HANDLE_SZ],
    }

    impl Default for CFileHandle {
        fn default() -> Self {
            CFileHandle {
                handle_bytes: MAX_HANDLE_SZ as libc::c_uint,
                handle_type: 0,
                f_handle: [0; MAX_HANDLE_SZ],
            }
        }
    }

    extern "C" {
        pub fn name_to_handle_at(
            dirfd: libc::c_int,
            pathname: *const libc::c_char,
            file_handle: *mut CFileHandle,
            mount_id: *mut libc::c_int,
            flags: libc::c_int,
        ) -> libc::c_int;

        // Technically `file_handle` should be a `mut` pointer, but `open_by_handle_at()` is specified
        // not to change it, so we can declare it `const`.
        pub fn open_by_handle_at(
            mount_fd: libc::c_int,
            file_handle: *const CFileHandle,
            flags: libc::c_int,
        ) -> libc::c_int;
    }
}
