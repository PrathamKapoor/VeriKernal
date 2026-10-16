//! Native checkpoint workload with cooperative boundary authorization.
//! Complexity: O(B) I/O and checksum time, O(B) read-back memory.
use std::io::{self, BufRead, BufReader, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};

/// Attempt direct OS operations without consulting supervision variables; O(B) I/O/memory.
fn uncooperative(args: &[String]) -> Option<i32> {
    if let Some(marker) = argument(args, "--uncooperative-child-marker") {
        return Some(match std::fs::write(marker, b"native-child-executed") {
            Ok(()) => 0,
            Err(_) => 1,
        });
    }
    if args.iter().any(|arg| {
        [
            "--uncooperative-spawn",
            "--uncooperative-fork",
            "--attack-fork-bomb",
        ]
        .contains(&arg.as_str())
    }) {
        let marker = argument(args, "--marker").unwrap_or("child.marker");
        let result = std::env::current_exe().and_then(|exe| {
            std::process::Command::new(exe)
                .args(["--uncooperative-child-marker", marker])
                .status()
        });
        return Some(match result {
            Ok(status) => {
                println!(
                    "{}",
                    serde_json::json!({"attack":"spawn","denied":!status.success(),"child_exit":status.code()})
                );
                if status.success() {
                    0
                } else {
                    77
                }
            }
            Err(error) => {
                println!(
                    "{}",
                    serde_json::json!({"attack":"spawn","denied":true,"errno":error.raw_os_error(),"error":error.to_string()})
                );
                77
            }
        });
    }
    if args.iter().any(|arg| {
        [
            "--uncooperative-memory-hog",
            "--uncooperative-alloc",
            "--attack-memory-spike",
        ]
        .contains(&arg.as_str())
    }) {
        let mut allocation = Vec::<u8>::new();
        return Some(match allocation.try_reserve_exact(128 * 1024 * 1024) {
            Ok(()) => {
                allocation.resize(128 * 1024 * 1024, 1);
                std::hint::black_box(&allocation);
                println!(
                    "{}",
                    serde_json::json!({"attack":"memory","denied":false,"touched_bytes":allocation.len()})
                );
                0
            }
            Err(error) => {
                println!(
                    "{}",
                    serde_json::json!({"attack":"memory","denied":true,"error":error.to_string()})
                );
                77
            }
        });
    }
    if args.iter().any(|arg| {
        ["--uncooperative-banned-syscall", "--uncooperative-net"].contains(&arg.as_str())
    }) {
        return Some(match std::net::TcpListener::bind(("127.0.0.1", 0)) {
            Ok(socket) => {
                println!(
                    "{}",
                    serde_json::json!({"attack":"socket","denied":false,"address":socket.local_addr().ok().map(|value|value.to_string())})
                );
                0
            }
            Err(error) => {
                println!(
                    "{}",
                    serde_json::json!({"attack":"socket","denied":true,"errno":error.raw_os_error()})
                );
                77
            }
        });
    }
    if let Some(path) = argument(args, "--uncooperative-read") {
        return Some(match std::fs::read(path) {
            Ok(bytes) => {
                println!(
                    "{}",
                    serde_json::json!({"attack":"read","denied":false,"bytes":bytes.len()})
                );
                0
            }
            Err(error) => {
                println!(
                    "{}",
                    serde_json::json!({"attack":"read","denied":true,"errno":error.raw_os_error()})
                );
                77
            }
        });
    }
    None
}

/// Return the real operating-system thread identifier; O(1) time and space.
fn thread_id() -> u64 {
    #[cfg(windows)]
    {
        #[link(name = "kernel32")]
        extern "system" {
            fn GetCurrentThreadId() -> u32;
        }
        unsafe { GetCurrentThreadId() as u64 }
    }
    #[cfg(target_os = "linux")]
    {
        unsafe { libc::syscall(libc::SYS_gettid) as u64 }
    }
    #[cfg(target_os = "macos")]
    {
        let mut tid = 0;
        unsafe { libc::pthread_threadid_np(0, &mut tid) };
        tid
    }
}

/// Authorize one real operation at the linked boundary; O(B) IPC time/space.
fn authorize(operation: u32, target: &str) -> io::Result<()> {
    if let Ok(address) = std::env::var("VK_NATIVE_IPC") {
        let token = std::env::var("VK_NATIVE_TOKEN").map_err(io::Error::other)?;
        let mut stream = TcpStream::connect(address)?;
        stream.set_read_timeout(Some(std::time::Duration::from_secs(10)))?;
        let request = serde_json::json!({"token":token,"operation":operation,"target":target,
            "pid":std::process::id(),"tid":thread_id()});
        writeln!(stream, "{}", request)?;
        let mut answer = String::new();
        BufReader::new(stream).read_line(&mut answer)?;
        let code: i32 = answer.trim().parse().map_err(io::Error::other)?;
        if code != 0 {
            return Err(io::Error::other(format!(
                "boundary rejected operation {operation}: errno {}",
                -code
            )));
        }
    }
    Ok(())
}

/// Fetch an optional command argument; O(A) time and O(1) borrowed space.
fn argument<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.windows(2)
        .find(|pair| pair[0] == name)
        .map(|pair| pair[1].as_str())
}

/// Run durable write/read-back checkpoint work; O(B) I/O time and memory.
fn run() -> io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let directory = PathBuf::from(
        argument(&args, "--work-dir").ok_or_else(|| io::Error::other("--work-dir is required"))?,
    );
    if !directory.is_dir() {
        return Err(io::Error::other("work directory must already exist"));
    }
    authorize(1, &std::env::current_exe()?.to_string_lossy())?;
    if let Some(variable) = argument(&args, "--read-env") {
        authorize(5, variable)?;
        println!(
            "environment_bytes={}",
            std::env::var(variable).unwrap_or_default().len()
        );
    }
    if let Some(path) = argument(&args, "--simulate-undeclared-file") {
        authorize(2, path)?;
        let bytes = std::fs::read(path)?;
        println!("additional_bytes={}", bytes.len());
    }
    let name = Path::new(argument(&args, "--write-checkpoint").unwrap_or("checkpoint.dat"));
    if name.components().count() != 1 || name.file_name().is_none() {
        return Err(io::Error::other("checkpoint must be a single filename"));
    }
    let destination = directory.join(name);
    let target = destination.to_string_lossy();
    authorize(2, &target)?;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&destination)?;
    authorize(10, &target)?;
    file.write_all(b"VK-CHECKPOINT-V1\ntransaction=1\ncommitted=true\n")?;
    file.sync_all()?;
    drop(file);
    authorize(9, &target)?;
    let content = std::fs::read(&destination)?;
    let checksum = content.iter().fold(0xcbf29ce484222325u64, |sum, byte| {
        (sum ^ *byte as u64).wrapping_mul(0x100000001b3)
    });
    println!(
        "checkpoint_bytes={} checksum={checksum:016x}",
        content.len()
    );
    Ok(())
}

/// Exit nonzero on a real operation or injected boundary error; O(B) work.
fn main() -> () {
    let args: Vec<String> = std::env::args().collect();
    if let Some(code) = uncooperative(&args) {
        std::process::exit(code);
    }
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    /// Validate argument and real thread identity handling; O(1) space/time.
    #[test]
    fn arguments_and_identity() -> () {
        let args = vec![
            "target".to_owned(),
            "--work-dir".to_owned(),
            "work".to_owned(),
        ];
        assert_eq!(super::argument(&args, "--work-dir"), Some("work"));
        assert_eq!(super::argument(&args, "--missing"), None);
        assert!(super::thread_id() > 0);
    }
}
