use std::ffi::CString;

use nix::libc;
use procfs::process::{MMPermissions, MMapPath};
use rand::Rng;

pub mod proc;
pub mod ptrace;

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

    // write library path first
    // but we have to pad it with null bytes to 8 bytes alignment
    let library_path = {
        let mut path = CString::new(library_path_str.to_string())?
            .as_bytes_with_nul()
            .to_vec();
        let len = path.len();
        let rem = len % 8;
        if rem != 0 {
            path.extend_from_slice(&vec![0; 8 - rem]);
        }

        path
    };

    tracer.write(free_addr as usize, &library_path)?;

    let mut regs = original_regs;
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

    // remap the module with anonymous mmap to avoid detection
    // back up the original module first
    let (module_frags, min_addr, max_addr) = {
        let mut v = Vec::new();
        let mut min_addr = u64::MAX;
        let mut max_addr = 0;

        for map in process.maps()? {
            if let MMapPath::Path(ref path) = map.pathname {
                if path.to_string_lossy() == *library_path_str {
                    let mut buffer = proc::dump_module(&process, &map)?;
                    if map.offset == 0 {
                        // wipe ELF header
                        // this is to avoid detection by anti-cheat
                        rng.fill(&mut buffer[..0x40]);
                    }
                    v.push((map.address.0, buffer));

                    if map.address.0 < min_addr {
                        min_addr = map.address.0;
                    }

                    if map.address.1 > max_addr {
                        max_addr = map.address.1;
                    }
                }
            }
        }

        if v.is_empty() {
            // recover to original state
            tracer.restore()?;
            tracer.setregs(original_regs)?;
            tracer.detach()?;

            return Err("Module not found, injection failed".into());
        }

        (v, min_addr, max_addr)
    };

    println!("Remapping module: 0x{:x} - 0x{:x}", min_addr, max_addr);
    regs.rip = free_addr;
    regs.rax = libc::SYS_munmap as u64;
    regs.rdi = min_addr;
    regs.rsi = max_addr - min_addr;
    regs.rdx = (libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) as u64;
    regs.r10 = (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED) as u64;
    regs.r8 = -1i64 as u64;
    regs.r9 = 0;

    tracer.setregs(regs)?;
    tracer.wait_execute(
        regs.rip as usize,
        &[
            0x0f, 0x05, // syscall
            0x48, 0xc7, 0xc0, 0x09, 0x00, 0x00, 0x00, // mov rax, 0x9 (mmap)
            0x0f, 0x05, // syscall
        ],
    )?;

    // rename the mmaped module to [anon:v8]
    // to make it seems like a JIT region generated by the v8 engine
    regs.rip = free_addr + 8;
    regs.rax = libc::SYS_prctl as u64;
    regs.rdi = libc::PR_SET_VMA as u64;
    regs.rsi = libc::PR_SET_VMA_ANON_NAME as u64;
    regs.rdx = min_addr;
    regs.r10 = max_addr - min_addr;
    regs.r8 = free_addr;

    tracer.write(free_addr as usize, &[b'v', b'8', 0, 0, 0, 0, 0, 0])?;

    tracer.setregs(regs)?;
    tracer.wait_execute(
        regs.rip as usize,
        &[
            0x0f, 0x05, // syscall
        ],
    )?;

    // write the module back
    for (addr, data) in module_frags {
        proc::write_memory(&process, addr as usize, &data)?;
    }

    tracer.restore()?;
    tracer.setregs(original_regs)?;

    println!("Injected!");

    tracer.detach()?;

    Ok(())
}
