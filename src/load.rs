use std::{
    ffi::{OsStr, OsString},
    fs::File,
    io::Read,
    os::unix::ffi::OsStrExt,
    path::Path,
};

use libc::{c_ulong, getauxval};
use nix::sys::resource::{getrlimit, Resource};
use xmas_elf::{
    header,
    program::{ProgramHeader, Type},
    ElfFile,
};

use crate::{
    auxv::AuxVec,
    process::{Process, RemoteFd},
};

pub struct LoadInfo {
    pub base: usize,
    pub entry: usize,
    pub interp_info: Option<Box<LoadInfo>>,
    pub phent: u16,
    pub phnum: u16,
    pub phdr: usize,
}

fn get_elf(buf: &[u8]) -> std::io::Result<ElfFile> {
    let elf =
        ElfFile::new(buf).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    if ![header::Type::Executable, header::Type::SharedObject]
        .contains(&elf.header.pt2.type_().as_type())
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Invalid ELF type",
        ));
    }
    if elf.header.pt2.machine().as_machine() != header::Machine::X86_64 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Invalid ELF architecture",
        ));
    }
    if elf.header.pt1.version.as_version() != header::Version::Current {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Invalid ELF version",
        ));
    }
    Ok(elf)
}

fn segment_memory_range(ph: ProgramHeader) -> [usize; 2] {
    let start = ph.virtual_addr() as usize;
    let end = start + ph.mem_size() as usize;
    let align_mask = ph.align() as usize - 1;
    let end_aligned = (end + align_mask) & !align_mask;
    [start, end_aligned]
}

fn segment_file_range(ph: ProgramHeader) -> [usize; 2] {
    let start = ph.offset() as usize;
    let end = start + ph.file_size() as usize;
    [start, end]
}

// gets the range of memory that the memory-mapped ELF file will occupy
// and the interpreter path if there is one
fn elf_program_data<'a>(
    elf: &ElfFile,
    buf: &'a [u8],
    allow_interp: bool,
) -> std::io::Result<(Option<&'a OsStr>, [usize; 2])> {
    let mut range: Option<[usize; 2]> = None;
    let mut interp: Option<&OsStr> = None;

    for ph in elf.program_iter() {
        if ph.get_type().map_or(false, |t| t == Type::Load) {
            let [start, end] = segment_memory_range(ph);
            range = Some(match range {
                Some([nstart, nend]) => [nstart.min(start), nend.max(end)],
                None => [start, end],
            });
        }
        if ph.get_type().map_or(false, |t| t == Type::Interp) {
            let offset = ph.offset();
            let size = ph.file_size();
            let range = &buf[offset as usize..(offset + size - 1) as usize];
            interp = Some(OsStr::from_bytes(range));
        }
    }

    let [start, end] = range.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "No loadable segments found",
        )
    })?;
    if interp.is_some() && !allow_interp {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Invalid interpreter",
        ));
    }
    Ok((interp, [start, end]))
}

fn map_segment(
    proc: &mut Process,
    segment: ProgramHeader,
    fd: RemoteFd,
    map_diff: usize,
) -> std::io::Result<()> {
    const ALIGN: usize = 4096;
    const ZERO_PAGE: [u8; ALIGN] = [0; ALIGN];
    let [filestart, fileend] = segment_file_range(segment);
    let [vstart, vend] = segment_memory_range(segment);
    if filestart % ALIGN != vstart % ALIGN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Segment alignment mismatch",
        ));
    }
    let aligned_filestart = filestart & !(ALIGN - 1);
    let aligned_vstart = vstart & !(ALIGN - 1);
    let mut prot = 0;
    if segment.flags().is_read() {
        prot |= libc::PROT_READ;
    }
    if segment.flags().is_write() {
        prot |= libc::PROT_WRITE;
    }
    if segment.flags().is_execute() {
        prot |= libc::PROT_EXEC;
    }
    let flags = libc::MAP_FIXED | libc::MAP_PRIVATE;
    let memsize = vend - aligned_vstart;
    let size = fileend - aligned_filestart;
    let real_start = aligned_vstart.wrapping_add(map_diff);
    // we add PROT_WRITE here to allow zeroing out the padding that might be at the start
    // and end of the mapping
    proc.mmap(
        real_start,
        size,
        prot | libc::PROT_WRITE,
        flags,
        Some(fd),
        aligned_filestart,
    )?;
    // mappings can have a non-aligned file offset as long as the memory offset is non-aligned
    // in the same way, but we do need to zero out the padding
    if aligned_filestart < filestart {
        let offset = filestart - aligned_filestart;
        proc.write(real_start, &ZERO_PAGE[..offset])?;
    }
    // also zero out the padding at the end
    let aligned_fileend = (fileend + ALIGN - 1) & !(ALIGN - 1);
    if aligned_fileend > fileend {
        let offset = fileend - aligned_filestart;
        proc.write(real_start + offset, &ZERO_PAGE[..aligned_fileend - fileend])?;
    }
    // this removes the PROT_WRITE flag if necessary, but also makes sure that adjacent zero pages
    // have the same protection flags
    proc.mprotect(real_start, memsize, prot)?;
    Ok(())
}

fn load_elf(proc: &mut Process, file: &mut File, allow_interp: bool) -> std::io::Result<LoadInfo> {
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;
    let elf = get_elf(&buf)?;
    let (interp, [base, end]) = elf_program_data(&elf, &buf, allow_interp)?;
    let interp_info = if let Some(interp) = interp {
        let path = std::path::Path::new(interp);
        let mut file = File::open(path)?;
        Some(Box::new(load_elf(proc, &mut file, false)?))
    } else {
        None
    };

    let phent = elf.header.pt2.ph_entry_size();
    let phnum = elf.header.pt2.ph_count();
    let phdr = base + elf.header.pt2.ph_offset() as usize;
    let entry = elf.header.pt2.entry_point() as usize;

    let map_diff = if elf.header.pt2.type_().as_type() == header::Type::Executable {
        proc.mmap_anon(base, end - base, libc::PROT_NONE, libc::MAP_FIXED_NOREPLACE)?;
        0
    } else {
        let res = proc.mmap_anon(0, end - base, libc::PROT_NONE, 0)?;
        res.wrapping_sub(base)
    };

    let fd = proc.get_tracer_fd(file)?;

    for ph in elf.program_iter() {
        if ph.get_type().map_or(false, |t| t == Type::Load) {
            map_segment(proc, ph, fd, map_diff)?;
        }
    }

    proc.close(fd)?;

    Ok(LoadInfo {
        base: base.wrapping_add(map_diff),
        entry: entry.wrapping_add(map_diff),
        interp_info,
        phent,
        phnum,
        phdr: phdr.wrapping_add(map_diff),
    })
}

fn initialize_stack(proc: &mut Process) -> Result<usize, std::io::Error> {
    let (mut stack_size, _) = getrlimit(Resource::RLIMIT_STACK)?;
    stack_size = stack_size.min(1 << 32);
    let stack = proc.mmap_anon(
        0,
        stack_size as usize,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_STACK,
    )?;
    Ok(stack + stack_size as usize)
}

struct UserInfo {
    pub uid: u32,
    pub gid: u32,
    pub euid: u32,
    pub egid: u32,
}

impl UserInfo {
    fn new_from_proc(proc: &mut Process) -> std::io::Result<Self> {
        let uid = proc.getuid()?;
        let gid = proc.getgid()?;
        let euid = proc.geteuid()?;
        let egid = proc.getegid()?;
        Ok(UserInfo {
            uid,
            gid,
            euid,
            egid,
        })
    }
}

const PLATFORM: &str = "x86_64";

fn construct_auxvec(
    exec: &Path,
    args: &[OsString],
    load: &LoadInfo,
    vdso_base: usize,
    user: &UserInfo,
) -> std::io::Result<AuxVec> {
    let mut auxv = crate::auxv::AuxVec::new();
    auxv.push_arg(exec.as_os_str());
    for arg in args {
        auxv.push_arg(arg);
    }
    for (key, val) in std::env::vars_os() {
        auxv.push_env(&key, &val);
    }
    let mut random_bytes: [u8; 16] = [0; 16];
    match getrandom::getrandom(&mut random_bytes) {
        Ok(_) => (),
        Err(e) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("could not get randomness: {e}"),
            ))
        }
    }
    let base = load.interp_info.as_ref().map_or(load.base, |x| x.base);
    auxv.push_aux_val(libc::AT_SYSINFO_EHDR, vdso_base);
    auxv.push_aux_val(libc::AT_BASE, base);
    auxv.push_aux_val(libc::AT_PHDR, load.phdr);
    auxv.push_aux_val(libc::AT_PHENT, load.phent as usize);
    auxv.push_aux_val(libc::AT_PHNUM, load.phnum as usize);
    auxv.push_aux_val(libc::AT_ENTRY, load.entry);
    auxv.push_aux_val(libc::AT_FLAGS, 0);
    auxv.push_aux_val(libc::AT_SECURE, 0);
    auxv.push_aux_bytes(libc::AT_RANDOM, &random_bytes);
    auxv.push_aux_str(libc::AT_EXECFN, exec.as_os_str());
    auxv.push_aux_str(libc::AT_PLATFORM, OsStr::new(PLATFORM));
    auxv.push_aux_val(libc::AT_UID, user.uid as usize);
    auxv.push_aux_val(libc::AT_GID, user.gid as usize);
    auxv.push_aux_val(libc::AT_EUID, user.euid as usize);
    auxv.push_aux_val(libc::AT_EGID, user.egid as usize);
    // these values should not change between different processes,
    // so we just copy them from our current one
    for host_val in [
        libc::AT_HWCAP,
        libc::AT_HWCAP2,
        libc::AT_PAGESZ,
        libc::AT_CLKTCK,
        libc::AT_MINSIGSTKSZ,
    ] {
        let val = unsafe { getauxval(host_val as c_ulong) };
        if val == 0 {
            continue;
        }
        auxv.push_aux_val(host_val, val as usize);
    }

    Ok(auxv)
}

fn initialize_auxvec(
    proc: &mut Process,
    auxv: &AuxVec,
    stack_top: usize,
) -> std::io::Result<usize> {
    let data = auxv.build(stack_top);
    let auxv_start = stack_top - data.len();
    proc.write(auxv_start, &data)?;
    Ok(auxv_start)
}

pub fn setup_proc(proc: &mut Process, exec: &Path, args: &[OsString]) -> std::io::Result<()> {
    let mut file = File::open(exec)?;
    let load = load_elf(proc, &mut file, true)?;
    let user = UserInfo::new_from_proc(proc)?;
    let stack_top = initialize_stack(proc)?;
    let vdso_base = proc.vdso_base();
    let auxv = construct_auxvec(exec, args, &load, vdso_base, &user)?;
    let sp = initialize_auxvec(proc, &auxv, stack_top)?;
    let real_entry = load.interp_info.as_ref().map_or(load.entry, |x| x.entry);
    proc.init_entry(sp, real_entry)?;
    Ok(())
}
