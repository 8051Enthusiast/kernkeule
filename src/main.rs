mod auxv;
mod load;
mod process;

use std::os::fd::{AsRawFd, BorrowedFd};

use load::setup_proc;
use nix::{
    poll::{poll, PollFd, PollFlags, PollTimeout},
    unistd::Pid,
};
use process::Process;
use which::which;

fn main() {
    let args = std::env::args_os().collect::<Vec<_>>();
    let [_, pid, command, args @ ..] = args.as_slice() else {
        eprintln!("Usage: kernkeule <pid> <command> [args...]",);
        std::process::exit(127);
    };
    let Some(pid) = pid.to_str().and_then(|x| x.parse().ok()) else {
        eprintln!("Invalid pid: {:?}", pid);
        std::process::exit(127);
    };
    let pid = Pid::from_raw(pid);
    let mut proc = match Process::new_cloned(pid) {
        Ok(syscall) => syscall,
        Err(e) => {
            eprintln!("Failed to get syscall: {}", e);
            std::process::exit(127);
        }
    };
    let command = match which(command) {
        Ok(cmd) => cmd,
        Err(e) => {
            eprintln!(
                "Failed to find command \"{}\": {}",
                command.to_string_lossy(),
                e
            );
            std::process::exit(127);
        }
    };
    match setup_proc(&mut proc, &command, args) {
        Ok(_) => (),
        Err(e) => {
            eprintln!("Failed to load ELF: {}", e);
            std::process::exit(127);
        }
    }
    let pidfd = match proc.cont() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to run process: {}", e);
            std::process::exit(127);
        }
    };
    let borrowed_fd = unsafe { BorrowedFd::borrow_raw(pidfd.as_raw_fd()) };
    // wait for process to exit
    let pollfd = PollFd::new(borrowed_fd, PollFlags::POLLIN);
    match poll(&mut [pollfd], PollTimeout::NONE) {
        Ok(_) => (),
        Err(e) => {
            eprintln!("Failed to poll: {}", e);
            std::process::exit(127);
        }
    }
}
