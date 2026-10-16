//! Linux syscall notification supervision and Landlock policy installation.
use crate::fault_engine::should_inject_fault;
use crate::ratchet::ForwardSecureRatchet;
use crate::sandbox::{notification_filter, SandboxPolicy};
use landlock::{
    path_beneath_rules, Access, AccessFs, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus,
    ABI,
};
use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use verikernel_schema::KernelTelemetryEvent;

static INTERRUPTED: AtomicBool = AtomicBool::new(false);
/// Record a termination request for the supervisor loop. Complexity: O(n + W) time and O(n + M) space, including called operations W and retained state M.
extern "C" fn interrupt(_: i32) -> () {
    INTERRUPTED.store(true, Ordering::Relaxed);
}
/// Install termination handlers before starting supervision. Complexity: O(n + W) time and O(n + M) space, including called operations W and retained state M.
pub fn install_interrupt_handlers() -> () {
    unsafe {
        libc::signal(libc::SIGTERM, interrupt as usize);
        libc::signal(libc::SIGINT, interrupt as usize);
    }
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
/// State retained by SeccompData. Space O(n) in owned entries.
pub struct SeccompData {
    pub nr: i32,
    pub arch: u32,
    pub ip: u64,
    pub args: [u64; 6],
}
#[repr(C)]
#[derive(Default)]
/// State retained by Notification. Space O(n) in owned entries.
pub struct Notification {
    pub id: u64,
    pub pid: u32,
    pub flags: u32,
    pub data: SeccompData,
}
#[repr(C)]
#[derive(Default)]
/// State retained by Response. Space O(n) in owned entries.
pub struct Response {
    pub id: u64,
    pub value: i64,
    pub error: i32,
    pub flags: u32,
}

/// Capture the current operating-system error. Complexity: O(n + W) time and O(n + M) space, including called operations W and retained state M.
fn error(message: impl ToString) -> io::Error {
    io::Error::other(message.to_string())
}

/// Apply the declared Landlock filesystem rules before execution. Complexity: O(n + W) time and O(n + M) space, including called operations W and retained state M.
pub fn restrict_filesystem(policy: &SandboxPolicy) -> io::Result<()> {
    let abi = ABI::V3;
    let status = Ruleset::default()
        .handle_access(AccessFs::from_all(abi))
        .map_err(error)?
        .create()
        .map_err(error)?
        .add_rules(path_beneath_rules(
            &policy.read_only,
            AccessFs::from_read(abi),
        ))
        .map_err(error)?
        .add_rules(path_beneath_rules(
            &policy.read_write,
            AccessFs::from_all(abi),
        ))
        .map_err(error)?
        .restrict_self()
        .map_err(error)?;
    if status.ruleset != RulesetStatus::FullyEnforced || !status.no_new_privs {
        return Err(error("required Landlock rights are unavailable"));
    }
    Ok(())
}

/// Install a seccomp filter and return its notification descriptor. Complexity: O(n + W) time and O(n + M) space, including called operations W and retained state M.
pub fn install_listener(policy: &SandboxPolicy) -> io::Result<OwnedFd> {
    let instructions =
        notification_filter(&policy.notify_syscalls, policy.architecture).map_err(error)?;
    let program = libc::sock_fprog {
        len: instructions.len() as u16,
        filter: instructions.as_ptr() as *mut libc::sock_filter,
    };
    unsafe {
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = libc::syscall(libc::SYS_seccomp, 1, 8, &program);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(OwnedFd::from_raw_fd(fd as i32))
    }
}

/// Transfer the listener descriptor to the supervising process. Complexity: O(n + W) time and O(n + M) space, including called operations W and retained state M.
unsafe fn send_descriptor(socket: i32, fd: i32) -> io::Result<()> {
    let mut marker = [1u8];
    let mut iov = libc::iovec {
        iov_base: marker.as_mut_ptr().cast(),
        iov_len: 1,
    };
    let mut control = [0usize; 4];
    let mut msg: libc::msghdr = std::mem::zeroed();
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = libc::CMSG_SPACE(4) as _;
    let header = libc::CMSG_FIRSTHDR(&msg);
    (*header).cmsg_level = libc::SOL_SOCKET;
    (*header).cmsg_type = libc::SCM_RIGHTS;
    (*header).cmsg_len = libc::CMSG_LEN(4) as _;
    std::ptr::write_unaligned(libc::CMSG_DATA(header).cast::<i32>(), fd);
    if libc::sendmsg(socket, &msg, 0) != 1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Receive the listener descriptor from the confined child. Complexity: O(n + W) time and O(n + M) space, including called operations W and retained state M.
unsafe fn receive_descriptor(socket: i32) -> io::Result<OwnedFd> {
    let mut marker = [0u8];
    let mut iov = libc::iovec {
        iov_base: marker.as_mut_ptr().cast(),
        iov_len: 1,
    };
    let mut control = [0usize; 4];
    let mut msg: libc::msghdr = std::mem::zeroed();
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = std::mem::size_of_val(&control) as _;
    if libc::recvmsg(socket, &mut msg, libc::MSG_CMSG_CLOEXEC) != 1 {
        return Err(error("child confinement setup failed"));
    }
    let header = libc::CMSG_FIRSTHDR(&msg);
    if header.is_null()
        || (*header).cmsg_level != libc::SOL_SOCKET
        || (*header).cmsg_type != libc::SCM_RIGHTS
    {
        return Err(error("missing seccomp listener"));
    }
    Ok(OwnedFd::from_raw_fd(std::ptr::read_unaligned(
        libc::CMSG_DATA(header).cast::<i32>(),
    )))
}

/// Read a bounded path argument from the stopped workload. Complexity: O(n + W) time and O(n + M) space, including called operations W and retained state M.
pub fn remote_path(pid: u32, address: u64) -> io::Result<String> {
    let mut buffer = [0u8; 4096];
    let local = libc::iovec {
        iov_base: buffer.as_mut_ptr().cast(),
        iov_len: buffer.len(),
    };
    let remote = libc::iovec {
        iov_base: address as *mut libc::c_void,
        iov_len: buffer.len(),
    };
    let count = unsafe { libc::process_vm_readv(pid as i32, &local, 1, &remote, 1, 0) };
    if count < 0 {
        return Err(io::Error::last_os_error());
    }
    let end = buffer[..count as usize]
        .iter()
        .position(|b| *b == 0)
        .ok_or_else(|| error("unterminated remote path"))?;
    String::from_utf8(buffer[..end].to_vec()).map_err(error)
}

/// Map a native syscall number to the telemetry operation. Complexity: O(n + W) time and O(n + M) space, including called operations W and retained state M.
pub fn operation(nr: i32) -> u32 {
    if nr == libc::SYS_openat as i32 {
        2
    } else if nr == libc::SYS_execve as i32 {
        1
    } else if nr == libc::SYS_connect as i32 {
        3
    } else if nr == libc::SYS_read as i32 {
        9
    } else if nr == libc::SYS_write as i32 {
        10
    } else if nr == libc::SYS_clock_gettime as i32 {
        6
    } else if nr == libc::SYS_getrandom as i32 {
        7
    } else {
        0
    }
}

/// Resolve the policy target for a notified operation. Complexity: O(n + W) time and O(n + M) space, including called operations W and retained state M.
fn target(request: &Notification) -> String {
    let pid = request.pid;
    let args = request.data.args;
    let op = operation(request.data.nr);
    if op == 2 || op == 1 {
        let address = if op == 2 { args[1] } else { args[0] };
        if let Ok(path) = remote_path(pid, address) {
            let candidate = if Path::new(&path).is_absolute() {
                std::path::PathBuf::from(path)
            } else {
                let base = if op == 1 || args[0] as i32 == libc::AT_FDCWD {
                    format!("/proc/{pid}/cwd")
                } else {
                    format!("/proc/{pid}/fd/{}", args[0])
                };
                match std::fs::read_link(base) {
                    Ok(base) => base.join(path),
                    Err(_) => return format!("pid:{pid}:unresolved-path"),
                }
            };
            return std::fs::canonicalize(&candidate)
                .unwrap_or(candidate)
                .to_string_lossy()
                .into_owned();
        }
    }
    if op == 9 || op == 10 {
        return std::fs::read_link(format!("/proc/{pid}/fd/{}", args[0]))
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|_| format!("pid:{pid}:fd:{}", args[0]));
    }
    format!("pid:{pid}:syscall:{}", request.data.nr)
}

/// Evaluate a socket endpoint and prepare the notification response. Complexity: O(n + W) time and O(n + M) space, including called operations W and retained state M.
fn connect_response(request: &Notification, allowed: &[String]) -> Response {
    let mut response = Response {
        id: request.id,
        error: -libc::EACCES,
        ..Default::default()
    };
    let length = request.data.args[2] as usize;
    if length < 2 || length > 128 {
        return response;
    }
    let mut address = [0usize; 16];
    let local = libc::iovec {
        iov_base: address.as_mut_ptr().cast(),
        iov_len: length,
    };
    let remote = libc::iovec {
        iov_base: request.data.args[1] as *mut libc::c_void,
        iov_len: length,
    };
    if unsafe { libc::process_vm_readv(request.pid as i32, &local, 1, &remote, 1, 0) }
        != length as isize
    {
        return response;
    }
    let bytes = unsafe { std::slice::from_raw_parts(address.as_ptr().cast::<u8>(), length) };
    let family = u16::from_ne_bytes([bytes[0], bytes[1]]) as i32;
    let endpoint = if family == libc::AF_INET && length >= 16 {
        format!(
            "{}:{}",
            std::net::Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7]),
            u16::from_be_bytes([bytes[2], bytes[3]])
        )
    } else if family == libc::AF_INET6 && length >= 28 {
        let mut octets = [0u8; 16];
        octets.copy_from_slice(&bytes[8..24]);
        format!(
            "[{}]:{}",
            std::net::Ipv6Addr::from(octets),
            u16::from_be_bytes([bytes[2], bytes[3]])
        )
    } else {
        return response;
    };
    if !allowed.contains(&endpoint) {
        return response;
    }
    let status = match std::fs::read_to_string(format!("/proc/{}/status", request.pid)) {
        Ok(status) => status,
        Err(_) => return response,
    };
    let tgid = status.lines().find_map(|line| {
        line.strip_prefix("Tgid:")
            .and_then(|value| value.trim().parse::<i32>().ok())
    });
    let Some(tgid) = tgid else {
        return response;
    };
    let descriptor = unsafe { libc::syscall(libc::SYS_pidfd_open, tgid, 0) };
    if descriptor < 0 {
        response.error = -io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO);
        return response;
    }
    let process = unsafe { OwnedFd::from_raw_fd(descriptor as i32) };
    let duplicate = unsafe {
        libc::syscall(
            libc::SYS_pidfd_getfd,
            process.as_raw_fd(),
            request.data.args[0] as i32,
            0,
        )
    };
    if duplicate < 0 {
        response.error = -io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO);
        return response;
    }
    let socket = unsafe { OwnedFd::from_raw_fd(duplicate as i32) };
    let result = unsafe { libc::connect(socket.as_raw_fd(), address.as_ptr().cast(), length as _) };
    response.value = result as i64;
    response.error = if result < 0 {
        -io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO)
    } else {
        0
    };
    if result < 0 {
        response.value = 0;
    }
    response
}

/// State retained by SupervisedRun. Space O(n) in owned entries.
pub struct SupervisedRun {
    pub events: Vec<KernelTelemetryEvent>,
    pub terminal: [u8; 32],
    pub commitment: [u8; 32],
    pub status: i32,
}

/// Mediate syscall notifications until the workload exits. Complexity: O(n + W) time and O(n + M) space, including called operations W and retained state M.
pub fn supervise(
    policy: &SandboxPolicy,
    command: &[String],
    seed: [u8; 32],
    fault_seed: u64,
    probability_ppm: u32,
) -> io::Result<SupervisedRun> {
    supervise_stream(
        policy,
        command,
        seed,
        fault_seed,
        probability_ppm,
        |_, _| Ok(()),
    )
}

struct RunningChild(i32);
impl Drop for RunningChild {
    /// Release the resource owned by this value. Complexity: O(n + W) time and O(n + M) space, including called operations W and retained state M.
    fn drop(&mut self) -> () {
        unsafe {
            libc::kill(-self.0, libc::SIGKILL);
            libc::kill(self.0, libc::SIGKILL);
            libc::waitpid(self.0, std::ptr::null_mut(), 0);
        }
    }
}

/// Run confinement and stream the captured execution records. Complexity: O(n + W) time and O(n + M) space, including called operations W and retained state M.
pub fn supervise_stream(
    policy: &SandboxPolicy,
    command: &[String],
    seed: [u8; 32],
    fault_seed: u64,
    probability_ppm: u32,
    mut sink: impl FnMut(&KernelTelemetryEvent, &str) -> io::Result<()>,
) -> io::Result<SupervisedRun> {
    if command.is_empty() {
        return Err(error("empty command"));
    }
    let args: Vec<CString> = command
        .iter()
        .map(|s| CString::new(s.as_bytes()).map_err(error))
        .collect::<Result<_, _>>()?;
    let mut pointers: Vec<_> = args.iter().map(|s| s.as_ptr()).collect();
    pointers.push(std::ptr::null());
    let mut sockets = [-1i32; 2];
    unsafe {
        if libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
            sockets.as_mut_ptr(),
        ) != 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    let parent = unsafe { OwnedFd::from_raw_fd(sockets[0]) };
    let child = unsafe { OwnedFd::from_raw_fd(sockets[1]) };
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(io::Error::last_os_error());
    }
    if pid == 0 {
        drop(parent);
        unsafe {
            if libc::setpgid(0, 0) != 0 || libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                libc::_exit(124);
            }
        }
        unsafe {
            libc::dup2(libc::STDERR_FILENO, libc::STDOUT_FILENO);
        }
        let setup = restrict_filesystem(policy).and_then(|()| install_listener(policy));
        match setup {
            Ok(listener) => unsafe {
                if send_descriptor(child.as_raw_fd(), listener.as_raw_fd()).is_err() {
                    libc::_exit(125);
                }
                drop(listener);
                drop(child);
                libc::execvp(args[0].as_ptr(), pointers.as_ptr());
                libc::_exit(127);
            },
            Err(_) => unsafe { libc::_exit(126) },
        }
    }
    let _child_lifetime = RunningChild(pid);
    drop(child);
    let listener = match unsafe { receive_descriptor(parent.as_raw_fd()) } {
        Ok(fd) => fd,
        Err(e) => {
            unsafe {
                libc::waitpid(pid, std::ptr::null_mut(), 0);
            }
            return Err(e);
        }
    };
    drop(parent);
    let mut ratchet = ForwardSecureRatchet::new(seed);
    let mut events = Vec::new();
    let mut status = 0;
    let mut ordinal = 0;
    loop {
        if INTERRUPTED.load(Ordering::Relaxed) {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "supervision interrupted",
            ));
        }
        let finished = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if finished == pid {
            break;
        }
        if finished < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut pollfd = libc::pollfd {
            fd: listener.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let ready = unsafe { libc::poll(&mut pollfd, 1, 10) };
        if ready < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(io::Error::last_os_error());
        }
        if ready == 0 || pollfd.revents & libc::POLLIN == 0 {
            continue;
        }
        let mut notification = Notification::default();
        if unsafe { libc::ioctl(listener.as_raw_fd(), 0xc0502100u32 as _, &mut notification) } != 0
        {
            let e = io::Error::last_os_error();
            if [libc::EINTR, libc::ENOENT].contains(&e.raw_os_error().unwrap_or(0)) {
                continue;
            }
            return Err(e);
        }
        let mut response = Response {
            id: notification.id,
            flags: 1,
            ..Default::default()
        };
        let op = operation(notification.data.nr);
        let name = target(&notification);
        if op == 3 && !policy.network.iter().any(|endpoint| endpoint == "*") {
            response = connect_response(&notification, &policy.network);
        }
        let mut clock = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        unsafe {
            libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut clock);
        }
        let mut event = KernelTelemetryEvent {
            seq_no: events.len() as u64,
            timestamp_ns: clock.tv_sec as u64 * 1_000_000_000 + clock.tv_nsec as u64,
            pid: notification.pid,
            tid: notification.pid,
            syscall_nr: op,
            call_stack_hash: notification.data.ip,
            target_digest: *blake3::hash(name.as_bytes()).as_bytes(),
            ..Default::default()
        };
        if let Ok(meta) = std::fs::metadata(&name) {
            event.dev_id = meta.dev();
            event.inode_nr = meta.ino();
            event.mtime_ns = (meta.mtime() as u64)
                .wrapping_mul(1_000_000_000)
                .wrapping_add(meta.mtime_nsec() as u64);
        }
        if should_inject_fault(
            fault_seed,
            event.call_stack_hash,
            op,
            ordinal,
            probability_ppm,
        ) {
            let code = if op == 10 {
                -28
            } else if op == 3 {
                -110
            } else {
                -11
            };
            response.error = code;
            response.flags = 0;
            event.fault_injected = code;
        }
        ordinal += 1;
        ratchet.tag(&mut event);
        sink(&event, &name)?;
        events.push(event);
        if unsafe { libc::ioctl(listener.as_raw_fd(), 0xc0182101u32 as _, &response) } != 0
            && io::Error::last_os_error().raw_os_error() != Some(libc::ENOENT)
        {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(SupervisedRun {
        events,
        terminal: ratchet.terminal(),
        commitment: ratchet.commitment,
        status,
    })
}
