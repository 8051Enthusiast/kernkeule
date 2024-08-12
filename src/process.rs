use std::os::fd::{AsRawFd, RawFd};
use std::time::Duration;
use std::{io, mem};

use libc::{
    user_fpregs_struct, user_regs_struct, CLONE_CLEAR_SIGHAND, CLONE_PTRACE, PTRACE_EVENT_CLONE,
    PTRACE_EVENT_STOP,
};
use nix::errno::Errno;
use nix::sys::ptrace::regset::NT_PRFPREG;
use nix::sys::ptrace::{self, Options};
use nix::sys::signal::Signal;
use nix::sys::uio::{process_vm_readv, process_vm_writev};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::Pid;
use nix::Result;
use pidfd::PidFd;

const TRACE: bool = false;

// quick and dirty implementation of ptrace_sigset
// since it's not available in nix yet

#[repr(C)]
struct KernelSigSet {
    sig: [u64; 1],
}

impl KernelSigSet {
    fn all() -> Self {
        Self { sig: [!0] }
    }
    fn empty() -> Self {
        Self { sig: [0] }
    }
}

// request must be either PTRACE_GETSIGMASK or PTRACE_SETSIGMASK
unsafe fn ptrace_sigset(
    request: ptrace::RequestType,
    pid: Pid,
    data: *mut KernelSigSet,
) -> Result<()> {
    let size = std::mem::size_of::<KernelSigSet>();
    unsafe { Errno::result(libc::ptrace(request, libc::pid_t::from(pid), size, data)).map(|_| ()) }
}

fn get_sigmask(pid: Pid) -> Result<KernelSigSet> {
    let mut mask = KernelSigSet::empty();
    unsafe {
        ptrace_sigset(libc::PTRACE_GETSIGMASK, pid, &mut mask)?;
    }
    Ok(mask)
}

fn set_sigmask(pid: Pid, mut mask: KernelSigSet) -> Result<()> {
    unsafe {
        ptrace_sigset(libc::PTRACE_SETSIGMASK, pid, &mut mask)?;
    }
    Ok(())
}

fn restore(
    pid: Pid,
    regs: user_regs_struct,
    mask: KernelSigSet,
    sig: Option<Signal>,
) -> Result<()> {
    ptrace::setregs(pid, regs)?;
    set_sigmask(pid, mask)?;
    ptrace::detach(pid, sig)
}

fn setup_syscall(
    pid: Pid,
    regs: &user_regs_struct,
    syscall_addr: u64,
    syscall: i64,
    args: &[u64],
) -> Result<()> {
    let mut new_regs = *regs;
    let arg_regs = [
        &mut new_regs.rdi,
        &mut new_regs.rsi,
        &mut new_regs.rdx,
        &mut new_regs.r10,
        &mut new_regs.r8,
        &mut new_regs.r9,
    ];
    for (reg, arg) in arg_regs.into_iter().zip(args.iter()) {
        *reg = *arg;
    }
    new_regs.rax = syscall as u64;
    new_regs.rip = syscall_addr;
    ptrace::setregs(pid, new_regs)
}

// finds a thread id for a given pid
fn thread_id(pid: Pid) -> Option<Pid> {
    let proc_path = format!("/proc/{}/task", pid);
    let thread = std::fs::read_dir(proc_path)
        .ok()?
        .find_map(|x| x.ok()?.file_name().to_str()?.parse().ok())?;
    Some(Pid::from_raw(thread))
}

fn fork_remote(pid: Pid, syscall_addr: u64) -> std::io::Result<Pid> {
    loop {
        let thread = thread_id(pid).ok_or(nix::errno::Errno::ENOENT)?;
        ptrace::seize(thread, Options::PTRACE_O_TRACESYSGOOD)?;
        ptrace::interrupt(thread)?;
        loop {
            match waitpid(pid, None)? {
                // ESRCH is also the error we would get with unexpected SIGKILL
                WaitStatus::Exited(_, _) | WaitStatus::Signaled(_, _, _) => {
                    return Err(nix::errno::Errno::ESRCH.into())
                }
                // reinject the signals thrown before the interrupt
                WaitStatus::Stopped(_, sig) => ptrace::cont(thread, Some(sig))?,
                // we got interrupted
                WaitStatus::PtraceEvent(_, _, PTRACE_EVENT_STOP) => break,
                WaitStatus::Continued(_) => {}
                // we do not trace these events, nor do we have WNOHANG
                WaitStatus::PtraceEvent(_, _, _)
                | WaitStatus::PtraceSyscall(_)
                | WaitStatus::StillAlive => unreachable!(),
            }
        }

        let old_sigmask = get_sigmask(thread)?;
        set_sigmask(thread, KernelSigSet::all())?;
        let regs = ptrace::getregs(thread)?;

        setup_syscall(
            thread,
            &regs,
            syscall_addr,
            libc::SYS_clone,
            &[CLONE_CLEAR_SIGHAND as u64 | CLONE_PTRACE as u64, 0, 0, 0, 0],
        )?;
        // the only clone we should be tracing now is our own, since we
        // hopefully disabled all signals
        ptrace::setoptions(
            thread,
            Options::PTRACE_O_TRACECLONE | Options::PTRACE_O_TRACESYSGOOD,
        )?;
        ptrace::syscall(thread, None)?;

        let mut first = true;
        let mut child = None;
        // the happy path here is PTraceSyscall -> PTraceEvent(PTRACE_EVENT_CLONE) -> PTraceSyscall
        let sig = loop {
            match waitpid(pid, None)? {
                WaitStatus::Stopped(_, Signal::SIGSTOP) => {}
                // we got a signal before we could set the mask
                WaitStatus::Stopped(_, sig) => break sig,
                WaitStatus::PtraceEvent(_, _, PTRACE_EVENT_CLONE) => {
                    child = Some(ptrace::getevent(thread)? as i32);
                    // we cannot yet restore since we are still in a syscall context
                    ptrace::syscall(thread, None)?;
                }
                WaitStatus::PtraceEvent(_, _, PTRACE_EVENT_STOP) => {}
                WaitStatus::Continued(_) => {}
                WaitStatus::PtraceSyscall(_) => {
                    if first {
                        // syscall entry
                        ptrace::syscall(thread, None)?;
                        first = false;
                    } else {
                        // syscall exit
                        restore(thread, regs, old_sigmask, None)?;
                        let Some(child) = child else {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::Other,
                                "Fork failed",
                            ));
                        };
                        return Ok(Pid::from_raw(child));
                    }
                }
                WaitStatus::PtraceEvent(_, _, _) | WaitStatus::StillAlive => unreachable!(),
                WaitStatus::Exited(_, _) | WaitStatus::Signaled(_, _, _) => {
                    return Err(nix::errno::Errno::ESRCH.into())
                }
            }
        };
        // if we got a signal before we could set the mask, retry everything
        restore(thread, regs, old_sigmask, Some(sig))?;
    }
}

pub struct Vdso {
    pub base: usize,
    pub syscall: usize,
}

// we would like to do syscalls without modifying the existing process
// memory, so we bet that the vdso has at least one syscall instruction
fn get_syscall(pid: Pid) -> std::io::Result<Vdso> {
    // syscall instruction on x86_64
    const SYSCALL: [u8; 2] = [0x0f, 0x05];
    let maps = proc_maps::get_process_maps(pid.as_raw())?;
    let vdso = maps
        .iter()
        .find(|x| x.filename().and_then(|x| x.to_str()) == Some("[vdso]"))
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::Other, "vdso not found"))?;

    let mut buf = vec![0; vdso.size()];
    let mut local = [std::io::IoSliceMut::new(&mut buf)];
    let remote = [nix::sys::uio::RemoteIoVec {
        base: vdso.start(),
        len: vdso.size(),
    }];

    process_vm_readv(pid, &mut local, &remote)?;
    match buf.windows(SYSCALL.len()).position(|x| x == SYSCALL) {
        Some(i) => {
            let base = vdso.start();
            let syscall = base + i;
            Ok(Vdso { base, syscall })
        }
        None => Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "syscall not found",
        )),
    }
}

fn as_err(ret: i64) -> Result<i64> {
    if ret < 0 {
        Err(Errno::from_raw(-ret as i32))
    } else {
        Ok(ret)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct RemoteFd(pub RawFd);

impl RemoteFd {
    pub fn as_raw(&self) -> RawFd {
        self.0
    }

    fn as_u64(&self) -> u64 {
        self.0 as u64
    }
}

pub struct Process {
    pid: Pid,
    thread: Pid,
    vdso: Vdso,
    tracer_pidfd: RemoteFd,
}

impl Process {
    pub fn new_cloned(pid: Pid) -> std::io::Result<Self> {
        let vdso = get_syscall(pid)?;
        let pid = fork_remote(pid, vdso.syscall as u64)?;
        let mut duration = Duration::from_millis(1);
        // while we did get the event that the clone occured and the syscall exited,
        // somehow that is not enough for the pid of the cloned process to exist yet,
        // even if we sched_yield
        // i cannot really come up with a better way to wait for the pid to exist,
        // so we just wait for up to ~8 seconds
        let mut res = ptrace::setoptions(pid, Options::PTRACE_O_TRACESYSGOOD);
        while duration < Duration::from_millis(1 << 13) && matches!(res, Err(Errno::ESRCH)) {
            res = ptrace::setoptions(pid, Options::PTRACE_O_TRACESYSGOOD);
            std::thread::sleep(duration);
            duration *= 2;
        }
        res?;

        let mut proc = Self {
            pid,
            // after a fork, pid == thread id
            thread: pid,
            vdso,
            tracer_pidfd: RemoteFd(0),
        };

        let current_pid = Pid::this();
        let mut pidfd = RemoteFd(as_err(
            proc.do_syscall(libc::SYS_pidfd_open, &[current_pid.as_raw() as u64, 0])?,
        )? as i32);
        while pidfd.as_raw() <= 3 {
            pidfd = proc.dup(&pidfd)?;
        }
        proc.tracer_pidfd = pidfd;
        proc.close_range(0, pidfd.as_raw() as u32 - 1)?;
        proc.close_range(pidfd.as_raw() as u32 + 1, u32::MAX)?;
        proc.get_tracer_fd(&io::stdin())?;
        proc.get_tracer_fd(&io::stdout())?;
        proc.get_tracer_fd(&io::stderr())?;
        if let Ok(tty) = std::fs::File::open("/dev/tty") {
            proc.get_tracer_fd(&tty)?;
        }

        Ok(proc)
    }

    /// returns the base address of the vdso in the target process
    pub fn vdso_base(&self) -> usize {
        self.vdso.base
    }

    fn do_syscall(&mut self, syscall: i64, args: &[u64]) -> Result<i64> {
        assert!(args.len() <= 6);
        if TRACE {
            eprintln!("syscall: {} {:?}", syscall, args);
        }

        let regs = ptrace::getregs(self.thread)?;
        setup_syscall(self.thread, &regs, self.vdso.syscall as u64, syscall, args)?;
        ptrace::syscall(self.thread, None)?;

        let mut first = true;
        let res = loop {
            match waitpid(self.pid, None)? {
                // we suppress all signals
                WaitStatus::Stopped(_, _) => ptrace::cont(self.thread, None)?,
                WaitStatus::PtraceSyscall(_) => {
                    if first {
                        // syscall entry
                        ptrace::syscall(self.thread, None)?;
                        first = false;
                    } else {
                        // syscall exit
                        break ptrace::getregs(self.thread)?.rax as i64;
                    }
                }
                WaitStatus::Exited(_, _) | WaitStatus::Signaled(_, _, _) => {
                    return Err(nix::errno::Errno::ESRCH)
                }
                _ => {}
            }
        };
        Ok(res)
    }

    /// sends a fd to the target process
    pub fn get_tracer_fd<T: AsRawFd>(&mut self, fd: &T) -> Result<RemoteFd> {
        let ret = self.do_syscall(
            libc::SYS_pidfd_getfd,
            &[self.tracer_pidfd.as_u64(), fd.as_raw_fd() as u64, 0],
        )?;
        Ok(RemoteFd(as_err(ret)? as RawFd))
    }

    pub fn dup(&mut self, fd: &RemoteFd) -> Result<RemoteFd> {
        let ret = self.do_syscall(libc::SYS_dup, &[fd.as_u64()])?;
        Ok(RemoteFd(as_err(ret)? as RawFd))
    }

    /// closes a range (inclusive) of file descriptors in the target process
    pub fn close_range(&mut self, start: u32, end: u32) -> Result<()> {
        as_err(self.do_syscall(libc::SYS_close_range, &[start as u64, end as u64, 0])?)?;
        Ok(())
    }

    pub fn mmap(
        &mut self,
        addr: usize,
        len: usize,
        prot: i32,
        flags: i32,
        fd: Option<RemoteFd>,
        offset: usize,
    ) -> Result<usize> {
        let fd = fd.map(|x| x.as_raw()).unwrap_or(-1);
        let ret = self.do_syscall(
            libc::SYS_mmap,
            &[
                addr as u64,
                len as u64,
                prot as u64,
                flags as u64,
                fd as u64,
                offset as u64,
            ],
        )?;
        Ok(as_err(ret)? as usize)
    }

    /// mmap in the target process, with anonymous private memory
    pub fn mmap_anon(&mut self, addr: usize, len: usize, prot: i32, flags: i32) -> Result<usize> {
        self.mmap(
            addr,
            len,
            prot,
            flags | libc::MAP_ANONYMOUS | libc::MAP_PRIVATE,
            None,
            0,
        )
    }

    pub fn mprotect(&mut self, addr: usize, len: usize, prot: i32) -> Result<()> {
        as_err(self.do_syscall(libc::SYS_mprotect, &[addr as u64, len as u64, prot as u64])?)?;
        Ok(())
    }

    pub fn close(&mut self, fd: RemoteFd) -> Result<()> {
        loop {
            let ret = self.do_syscall(libc::SYS_close, &[fd.as_u64()])?;
            match as_err(ret) {
                Ok(_) => return Ok(()),
                Err(Errno::EINTR) => {}
                Err(e) => return Err(e),
            }
        }
    }

    pub fn getuid(&mut self) -> Result<u32> {
        let ret = self.do_syscall(libc::SYS_getuid, &[])?;
        Ok(ret as u32)
    }

    pub fn getgid(&mut self) -> Result<u32> {
        let ret = self.do_syscall(libc::SYS_getgid, &[])?;
        Ok(ret as u32)
    }

    pub fn geteuid(&mut self) -> Result<u32> {
        let ret = self.do_syscall(libc::SYS_geteuid, &[])?;
        Ok(ret as u32)
    }

    pub fn getegid(&mut self) -> Result<u32> {
        let ret = self.do_syscall(libc::SYS_getegid, &[])?;
        Ok(ret as u32)
    }

    /// write the given data to the target process at the given address
    pub fn write(&self, addr: usize, data: &[u8]) -> Result<()> {
        let local = [std::io::IoSlice::new(data)];
        let remote = [nix::sys::uio::RemoteIoVec {
            base: addr,
            len: data.len(),
        }];
        if TRACE {
            eprintln!("write: {} {}", addr, data.len());
        }
        process_vm_writev(self.pid, &local, &remote)?;
        Ok(())
    }

    /// prepare the target process for execution at rip.
    /// rsp should point to the auxiliary vector
    pub fn init_entry(&mut self, rsp: usize, rip: usize) -> Result<()> {
        let regs = user_regs_struct {
            rip: rip as u64,
            rsp: rsp as u64,
            // apparently the gdt is still a thing on x86_64
            // and the kernel sets cs and ss to entries of the gdt
            // on exec
            cs: 6 << 3 | 3,
            ss: 5 << 3 | 3,
            eflags: 0x202,
            r15: 0,
            r14: 0,
            r13: 0,
            r12: 0,
            rbp: 0,
            rbx: 0,
            r11: 0,
            r10: 0,
            r9: 0,
            r8: 0,
            rax: 0,
            rcx: 0,
            rdx: 0,
            rsi: 0,
            rdi: 0,
            orig_rax: 0,
            fs_base: 0,
            gs_base: 0,
            ds: 0,
            es: 0,
            fs: 0,
            gs: 0,
        };
        let mut fpregs: user_fpregs_struct = unsafe { mem::zeroed() };
        fpregs.mxcsr = 0x1f80;
        fpregs.cwd = 0x37f;
        ptrace::setregset::<NT_PRFPREG>(self.pid, fpregs)?;
        ptrace::setregs(self.pid, regs)?;
        Ok(())
    }

    /// continue the target process. returns a pidfd to the target process
    /// that can be polled for exit
    pub fn cont(self) -> std::io::Result<PidFd> {
        let mask = KernelSigSet::empty();
        set_sigmask(self.thread, mask)?;
        let pidfd = unsafe { PidFd::open(self.pid.as_raw(), 0) }?;
        ptrace::detach(self.pid, None)?;
        Ok(pidfd)
    }
}
