//! Pre-exec kernel restrictions; O(R + A) setup for rules R and arguments A.
use std::io;

#[cfg(windows)]
mod windows;

/// Parse launcher options without invoking a shell; O(A) time and space.
fn arguments() -> io::Result<(Vec<String>, u64, Vec<String>)> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let split = args
        .iter()
        .position(|value| value == "--")
        .ok_or_else(|| io::Error::other("expected -- followed by executable and arguments"))?;
    let mut memory = 16 * 1024 * 1024;
    let mut roots = Vec::new();
    let mut index = 0;
    while index < split {
        if index + 1 >= split {
            return Err(io::Error::other("option requires a value"));
        }
        match args[index].as_str() {
            "--memory-bytes" => memory = args[index + 1].parse().map_err(io::Error::other)?,
            "--read-root" => roots.push(args[index + 1].clone()),
            _ => return Err(io::Error::other("unknown launcher option")),
        }
        index += 2;
    }
    if split + 1 == args.len() {
        return Err(io::Error::other("missing target executable"));
    }
    Ok((args[split + 1..].to_vec(), memory, roots))
}

#[cfg(target_os = "linux")]
#[repr(C)]
/// Landlock ruleset attribute; O(1) layout.
struct Ruleset {
    handled: u64,
}
#[cfg(target_os = "linux")]
#[repr(C)]
/// Landlock path-beneath attribute; O(1) layout.
struct PathRule {
    access: u64,
    descriptor: i32,
    padding: u32,
}

/// Apply Landlock read/execute roots if requested; O(R) syscalls and O(1) scratch.
#[cfg(target_os = "linux")]
fn landlock(roots: &[String]) -> io::Result<()> {
    if roots.is_empty() {
        return Ok(());
    }
    let abi = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            core::ptr::null::<u8>(),
            0,
            1,
        )
    };
    if abi < 1 {
        return Err(io::Error::last_os_error());
    }
    let attributes = Ruleset {
        handled: ((1u64 << 13) - 1)
            | if abi >= 2 { 1 << 13 } else { 0 }
            | if abi >= 3 { 1 << 14 } else { 0 },
    };
    let fd = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            &attributes,
            core::mem::size_of::<Ruleset>(),
            0,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let result = (|| -> io::Result<()> {
        for root in roots {
            let path = std::ffi::CString::new(root.as_str()).map_err(io::Error::other)?;
            let parent = unsafe { libc::open(path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
            if parent < 0 {
                return Err(io::Error::last_os_error());
            }
            let access = if std::path::Path::new(root).is_dir() {
                1 | 4 | 8
            } else {
                1 | 4
            };
            let rule = PathRule {
                access,
                descriptor: parent,
                padding: 0,
            };
            let code = unsafe { libc::syscall(libc::SYS_landlock_add_rule, fd, 1, &rule, 0) };
            let error = io::Error::last_os_error();
            unsafe {
                libc::close(parent);
            }
            if code < 0 {
                return Err(error);
            }
        }
        if unsafe { libc::syscall(libc::SYS_landlock_restrict_self, fd, 0) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    })();
    unsafe {
        libc::close(fd as i32);
    }
    result
}

/// Restrict before exec, so no target instruction precedes policy; O(R + A) setup.
#[cfg(target_os = "linux")]
fn run() -> io::Result<()> {
    let (args, memory, roots) = arguments()?;
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } < 0 {
        return Err(io::Error::last_os_error());
    }
    if memory > 0 {
        let limit = libc::rlimit {
            rlim_cur: memory,
            rlim_max: memory,
        };
        if unsafe { libc::setrlimit(libc::RLIMIT_AS, &limit) } < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    landlock(&roots)?;
    #[cfg(target_arch = "aarch64")]
    let (architecture, denied) = (0xc00000b7, vec![198, 220, 435]);
    #[cfg(target_arch = "x86_64")]
    let (architecture, denied) = (0xc000003e, vec![41, 56, 57, 58, 435]);
    let mut instructions = vec![
        libc::sock_filter {
            code: 0x20,
            jt: 0,
            jf: 0,
            k: 4,
        },
        libc::sock_filter {
            code: 0x15,
            jt: 1,
            jf: 0,
            k: architecture,
        },
        libc::sock_filter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: 0x80000000,
        },
        libc::sock_filter {
            code: 0x20,
            jt: 0,
            jf: 0,
            k: 0,
        },
        libc::sock_filter {
            code: 0x35,
            jt: 0,
            jf: 1,
            k: 0x40000000,
        },
        libc::sock_filter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: 0x00050000 | 13,
        },
    ];
    for number in denied {
        instructions.push(libc::sock_filter {
            code: 0x15,
            jt: 0,
            jf: 1,
            k: number,
        });
        instructions.push(libc::sock_filter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: 0x00050000 | 13,
        });
    }
    instructions.push(libc::sock_filter {
        code: 0x06,
        jt: 0,
        jf: 0,
        k: 0x7fff0000,
    });
    let program = libc::sock_fprog {
        len: instructions.len() as u16,
        filter: instructions.as_mut_ptr(),
    };
    if unsafe { libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &program) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let strings: Result<Vec<std::ffi::CString>, _> = args
        .iter()
        .map(|value| std::ffi::CString::new(value.as_str()))
        .collect();
    let strings = strings.map_err(io::Error::other)?;
    let mut pointers: Vec<*const libc::c_char> =
        strings.iter().map(|value| value.as_ptr()).collect();
    pointers.push(core::ptr::null());
    unsafe {
        libc::execv(strings[0].as_ptr(), pointers.as_ptr());
    }
    Err(io::Error::last_os_error())
}

/// Apply native NT kernel job limits; O(A) setup and O(1) handles.
#[cfg(windows)]
fn run() -> io::Result<()> {
    let (args, memory, roots) = arguments()?;
    if !roots.is_empty() {
        return Err(io::Error::other("read roots require Linux Landlock"));
    }
    windows::launch(&args, memory)
}

/// Refuse unsupported kernels explicitly; O(1) time and space.
#[cfg(not(any(windows, target_os = "linux")))]
fn run() -> io::Result<()> {
    Err(io::Error::other(
        "pre-exec confinement requires Windows NT or Linux",
    ))
}

/// Fail closed on setup errors; O(A + R) setup work.
fn main() -> () {
    if let Err(error) = run() {
        eprintln!("kernel confinement setup: {error}");
        std::process::exit(125);
    }
}
