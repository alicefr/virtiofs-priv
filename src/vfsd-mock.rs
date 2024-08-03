use clap::Parser;
use std::fs::File;
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::{fs, io};
use oslib::openat;
use crate::filehandle::{FileHandle, open_by_handle_at};

mod oslib;
mod filehandle;

#[derive(Parser)]
struct Cli {
    /// Shared directory path
    #[arg(long)]
    shared_dir: String,

    #[arg(long)]
    file: String,
}

fn open(path: PathBuf) -> io::Result<File> {
    let root_file = openat(
        &libc::AT_FDCWD,
        path.to_str().unwrap(),
        libc::O_NOFOLLOW | libc::O_CLOEXEC, // libc::O_PATH don't use for open_by_handle_at
    )?;
    Ok(root_file)
}

fn main() {
    let args = Cli::parse();

    // open virtiofsd "root" directory
    let shared_dir = fs::canonicalize(args.shared_dir).expect("valid shared dir");
    let root_dir_fd = open(shared_dir).expect("open shared dir");

    // access file
    let file_fh = {
        let shared_file = fs::canonicalize(args.file).expect("valid filename");
        let file_fd = open(shared_file).expect("open file");
        FileHandle::from_fd(&file_fd).expect("name_to_handle_at")
    };
    println!("\n(name_to_handle_at) received FH: {:?}\n", file_fh);

    let f = open_by_handle_at(&root_dir_fd, &file_fh.handle, 0).expect("open_by_handle_at");
    println!("\n(open_by_handle_at) received FD: {}\n", f.as_raw_fd());
    println!("it works!");
}
