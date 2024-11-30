use nix::{
    libc,
    sys::ptrace::{self, AddressType, Options},
};

/// a wrapper around ptrace syscalls to reduce boilerplate
pub struct Tracer {
    pub pid: nix::unistd::Pid,

    backup: Vec<(AddressType, libc::c_long)>,
}

impl Tracer {
    pub fn new(pid: nix::unistd::Pid) -> Result<Self, nix::Error> {
        // by using PTRACE_SEIZE, we can pause and resume the process multiple times
        // this is useful as we intend to avoid emitting signals
        // which may be detected by the anti-cheat
        ptrace::seize(pid, Options::empty())?;

        Ok(Self {
            pid,
            backup: vec![],
        })
    }

    pub fn interrupt_and_waitpid(&self) -> Result<(), nix::Error> {
        nix::sys::ptrace::interrupt(self.pid)?;
        nix::sys::wait::waitpid(self.pid, None)?;

        Ok(())
    }

    pub fn cont(&self) -> Result<(), nix::Error> {
        ptrace::cont(self.pid, None)?;

        Ok(())
    }

    pub fn getregs(&self) -> Result<libc::user_regs_struct, nix::Error> {
        ptrace::getregs(self.pid)
    }

    pub fn setregs(&self, regs: libc::user_regs_struct) -> Result<(), nix::Error> {
        ptrace::setregs(self.pid, regs)?;

        Ok(())
    }

    pub fn detach(&self) -> Result<(), nix::Error> {
        ptrace::detach(self.pid, None)?;

        Ok(())
    }

    pub fn write(&mut self, addr: usize, data: &[u8]) -> Result<(), nix::Error> {
        // ptrace only allows writing 8 bytes at a time
        // pad the remaining bytes with NOPsa time
        // and pad the remaining bytes with NOPs
        let mut offset = 0;
        while offset < data.len() {
            let word = if data.len() - offset < 8 {
                let mut word = [0x90; 8];
                word[..data.len() - offset].copy_from_slice(&data[offset..]);
                unsafe { std::mem::transmute::<[u8; 8], libc::c_long>(word) }
            } else {
                unsafe {
                    std::mem::transmute::<[u8; 8], libc::c_long>(
                        data[offset..offset + 8].try_into().unwrap(),
                    )
                }
            };

            let ptr = (addr + offset) as AddressType;
            // this doesn't handle overlapping writes
            // but it's fine for our use case
            if !self.backup.iter().any(|(a, _)| *a == ptr) {
                let backup = ptrace::read(self.pid, ptr)?;
                self.backup.push((ptr, backup));
            }

            ptrace::write(self.pid, ptr, word)?;
            offset += 8;
        }

        Ok(())
    }

    pub fn restore(&mut self) -> Result<(), nix::Error> {
        for (addr, data) in self.backup.drain(..) {
            ptrace::write(self.pid, addr, data)?;
        }

        Ok(())
    }

    pub fn wait_execute(&mut self, addr: usize, data: &[u8]) -> Result<(), nix::Error> {
        // add a infinite loop at the end of the shellcode
        // so we can wait for the shellcode to execute
        // without emitting signals
        let mut data = data.to_vec();
        let loop_addr = addr + data.len();
        data.extend_from_slice(&[
            0xf3, 0x90, // pause
            0xeb, 0xfe,
        ]);

        self.write(addr, &data)?;
        self.cont()?;

        loop {
            std::thread::sleep(std::time::Duration::from_millis(5));

            // we have to pause the process to read the registers
            self.interrupt_and_waitpid()?;
            let regs = self.getregs()?;
            // println!("RIP: 0x{:x}", regs.rip);
            let rip = regs.rip as usize;
            if rip >= loop_addr && rip <= loop_addr + 4 {
                self.restore()?;
                break;
            }

            self.cont()?;
        }

        Ok(())
    }
}

pub fn align_data(mut data: Vec<u8>) -> Vec<u8> {
    let rem = data.len() % 8;
    if rem != 0 {
        data.extend_from_slice(&vec![0; 8 - rem]);
    }

    data
}
