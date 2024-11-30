use std::{
    io::{Read, Seek},
    path::PathBuf,
};

use nix::libc::{c_void, iovec, process_vm_readv, process_vm_writev};
use procfs::process::{MMPermissions, MMapPath, MemoryMap, Process};
use xxhash_rust::xxh3::xxh3_128;

pub fn current_process() -> Result<Process, procfs::ProcError> {
    let pid = std::process::id() as i32;
    Process::new(pid)
}

pub fn pidof(comm: &str) -> Result<Process, procfs::ProcError> {
    let processes = procfs::process::all_processes()?;

    for proc in processes {
        let Ok(proc) = proc else {
            continue;
        };
        let stat = proc.stat()?;
        if comm == stat.comm {
            return Ok(proc);
        }
    }

    Err("Process not found")?
}

pub fn get_module_offset(proc: &Process, module: &str) -> Result<u64, procfs::ProcError> {
    for map in proc.maps()? {
        if let MMapPath::Path(ref path) = map.pathname {
            if path.file_name().unwrap() == module {
                return Ok(map.address.0 - map.offset);
            }
        }
    }

    Err(procfs::ProcError::NotFound(None))
}

pub fn get_module_from_offset(
    proc: &Process,
    offset: u64,
) -> Result<(PathBuf, u64), procfs::ProcError> {
    for map in proc.maps()? {
        if offset >= map.address.0 && offset <= map.address.1 {
            let offset_from_base = offset - map.address.0 + map.offset;

            if let MMapPath::Path(ref path) = map.pathname {
                return Ok((path.clone(), offset_from_base));
            }
        }
    }

    Err(procfs::ProcError::NotFound(None))
}

pub fn dump_module(proc: &Process, map: &MemoryMap) -> Result<Vec<u8>, std::io::Error> {
    let mut buffer = vec![0u8; (map.address.1 - map.address.0) as usize];

    unsafe {
        let local_iov = iovec {
            iov_base: buffer.as_mut_ptr() as *mut c_void,
            iov_len: buffer.len(),
        };
        let remote_iov = iovec {
            iov_base: map.address.0 as *mut c_void,
            iov_len: buffer.len(),
        };
        let nread = process_vm_readv(proc.pid, &local_iov, 1, &remote_iov, 1, 0);
        if nread == -1 {
            Err(std::io::Error::last_os_error())?;
        }
    }

    Ok(buffer)
}

pub fn write_memory(
    proc: &Process,
    addr: usize,
    data: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    unsafe {
        let local_iov = iovec {
            iov_base: data.as_ptr() as *mut c_void,
            iov_len: data.len(),
        };
        let remote_iov = iovec {
            iov_base: addr as *mut c_void,
            iov_len: data.len(),
        };
        let nread = process_vm_writev(proc.pid, &local_iov, 1, &remote_iov, 1, 0);
        if nread == -1 {
            Err(std::io::Error::last_os_error())?;
        }
    }

    Ok(())
}

/// anti-cheats may place hooks in the libc/ld library
/// to detect if some library is loaded
///
/// haven't seen this in the wild but it's a possibility
///
/// at least VAC did something similar on Windows
pub fn verify_module_integrity(
    proc: &Process,
    module: &str,
    path_override: Option<&PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    for map in proc.maps()? {
        if let MMapPath::Path(ref path) = map.pathname {
            if path.file_name().unwrap() == module
                && map.perms & MMPermissions::EXECUTE == MMPermissions::EXECUTE
            {
                if map.perms & MMPermissions::WRITE == MMPermissions::WRITE {
                    println!("sus! module is writable");
                }

                let file = std::fs::File::open(if let Some(path) = path_override {
                    path
                } else {
                    path
                })?;
                let mut reader = std::io::BufReader::new(file);

                let mut buffer = dump_module(proc, &map)?;
                let hash_memory = xxh3_128(&buffer);

                reader.seek(std::io::SeekFrom::Start(map.offset))?;
                reader.read_exact(&mut buffer)?;
                let hash_original = xxh3_128(&buffer);

                if hash_original != hash_memory {
                    Err("Module integrity check failed")?;
                }
            }
        }
    }

    Ok(())
}
