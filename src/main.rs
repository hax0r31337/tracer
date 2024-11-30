use std::{ffi::CString, io::Read};

use nix::libc;
use procfs::process::{MMPermissions, MMapPath};
use rand::Rng;

pub mod proc;
pub mod ptrace;

/// the size of each chunk of library data to write into the target process
/// to avoid directly opening the library file in the target process
const CHUNK_SIZE: usize = 0x1000;
/// use a fake memfd name to avoid detection from dl_iterate_phdr
const MEMFD_NAME: &str = "pipewire-memfd";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = std::env::args().collect::<Vec<_>>();
    if args.len() != 3 {
        eprintln!("Usage: {} <process_name/pid:pid> <library_path>", args[0]);
        std::process::exit(1);
    }

    let process = if args[1].starts_with("pid:") {
        procfs::process::Process::new(args[1][4..].parse()?)?
    } else {
        proc::pidof(&args[1])?
    };
    let library_path_str = &args[2];
    let mut rng = rand::thread_rng();

    // we want to avoid attaching to the main thread as much as possible
    // some anti-cheat only checks for TracerPid for the main thread
    // *cough* VAC *cough*
    // and checking for the tracer pid on all threads is more expensive
    // which may checked less frequently
    // lower the chance of detected by external anti-cheat while injecting
    let pid = nix::unistd::Pid::from_raw({
        let tasks = process.tasks()?.flatten().collect::<Vec<_>>();
        if tasks.len() == 1 {
            tasks[0].tid
        } else {
            let mut tid = process.pid;
            while tid == process.pid {
                tid = tasks[rng.gen_range(0..tasks.len())].tid;
            }

            tid
        }
    });

    // find offset of the module before attaching
    let (module, offset) = {
        let offset = unsafe {
            libc::dlsym(
                std::ptr::null_mut(),
                c"dlopen".as_ptr() as *const libc::c_char,
            )
        };
        if offset.is_null() {
            return Err("dlopen not found".into());
        }

        let current_process = proc::current_process()?;
        proc::get_module_from_offset(&current_process, offset as u64)?
    };

    println!(
        "dlopen offset: {} 0x{:x}",
        module.to_string_lossy(),
        offset as usize
    );

    let module_name = &module.file_name().unwrap().to_string_lossy();
    let Ok(module_offset) = proc::get_module_offset(&process, module_name) else {
        return Err("Module not found in target process".into());
    };
    proc::verify_module_integrity(&process, module_name, Some(&module))?;

    println!("Module offset: 0x{:x}", module_offset);

    // we gotta find a place to inject our shellcode
    // we can't just inject it anywhere (e.g. rip)
    // as the rip register may be in the middle of essential libc functions used by dlopen
    let free_addr = {
        let maps = process.maps()?;
        let v = MMPermissions::EXECUTE | MMPermissions::READ;
        let vec = maps
            .iter()
            .filter(|m| m.perms & v == v)
            .filter(|m| {
                if let MMapPath::Path(ref path) = m.pathname {
                    path.file_name().unwrap().to_string_lossy() != *module_name
                } else {
                    false
                }
            })
            .collect::<Vec<_>>();

        let a = vec[rng.gen_range(0..vec.len())];
        a.address.0
    };

    println!(
        "Attaching to PID: {} (is_main_thread: {})",
        pid,
        pid.as_raw() == process.pid
    );

    let mut tracer = ptrace::Tracer::new(pid)?;
    tracer.interrupt_and_waitpid()?;
    let original_regs = tracer.getregs()?;

    // create a memfd in the target process
    let memfd_name = ptrace::align_data(
        CString::new(MEMFD_NAME)
            .unwrap()
            .as_bytes_with_nul()
            .to_vec(),
    );
    tracer.write(free_addr as usize, &memfd_name)?;

    let mut regs = original_regs;
    regs.rip = free_addr + memfd_name.len() as u64;
    regs.rax = libc::SYS_memfd_create as u64;
    regs.rdi = free_addr;
    regs.rsi = 0;

    tracer.setregs(regs)?;
    tracer.wait_execute(
        regs.rip as usize,
        &[
            0x0f, 0x05, // syscall
        ],
    )?;

    // write the library to the memfd
    let fd = tracer.getregs()?.rax;
    {
        let mut file = std::fs::File::open(library_path_str)?;
        let mut buf = [0; CHUNK_SIZE];
        loop {
            let n = file.read(&mut buf)?;
            if n == 0 {
                break;
            }

            tracer.write(free_addr as usize, &buf[..n])?;

            regs.rip = free_addr + CHUNK_SIZE as u64;
            regs.rax = libc::SYS_write as u64;
            regs.rdi = fd;
            regs.rsi = free_addr;
            regs.rdx = n as u64;

            tracer.setregs(regs)?;
            tracer.wait_execute(
                regs.rip as usize,
                &[
                    0x0f, 0x05, // syscall
                ],
            )?;
        }
    }

    // write library path first
    // but we have to pad it with null bytes to 8 bytes alignment
    let library_path = ptrace::align_data(
        CString::new(format!("/proc/self/fd/{}", fd))?
            .as_bytes_with_nul()
            .to_vec(),
    );

    tracer.write(free_addr as usize, &library_path)?;

    regs.rip = free_addr + library_path.len() as u64;
    regs.rax = module_offset + offset;
    regs.rdi = free_addr as u64; // filename
    regs.rsi = libc::RTLD_NOW as u64; // flag
    regs.rsp &= 0xffff_ffff_ffff_f000; // align rsp to 8 bytes

    tracer.setregs(regs)?;
    tracer.wait_execute(
        regs.rip as usize,
        &[
            0xff, 0xd0, // call rax
        ],
    )?;

    // wipe elf header
    // to avoid memory walking detection
    let mut header_wiped = false;
    let expected_mmap_name = format!("/memfd:{} (deleted)", MEMFD_NAME);
    for map in process.maps()? {
        if let MMapPath::Path(ref path) = map.pathname {
            if path.to_string_lossy() == expected_mmap_name && map.offset == 0 {
                let mut buffer = [0u8; 0x40];
                rng.fill(&mut buffer);
                tracer.write(map.address.0 as usize, &buffer)?;
                header_wiped = true;
                break;
            }
        }
    }

    if !header_wiped {
        println!("Warning: Failed to wipe ELF header");
    }

    tracer.restore()?;
    tracer.setregs(original_regs)?;

    println!("Injected!");

    tracer.detach()?;

    Ok(())
}
