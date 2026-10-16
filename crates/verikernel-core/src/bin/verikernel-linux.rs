//! Native command-line execution and source verification utilities.
#[cfg(target_os = "linux")]
/// Execute the selected native supervision mode. Complexity: O(n + W) time and O(n + M) space, including called operations W and retained state M.
fn execute() -> Result<(), Box<dyn std::error::Error>> {
    use std::io::{Read, Write};
    use verikernel_core::{linux, sandbox::SandboxPolicy};
    let args: Vec<String> = std::env::args().collect();
    if args.len() >= 6 && args[1] == "probes" {
        let pid = args[3].parse::<u32>()?;
        let milliseconds = args[4].parse::<u64>()?;
        return verikernel_core::probes::trace(
            &args[2],
            pid,
            &args[6..],
            std::time::Duration::from_millis(milliseconds),
            &mut std::fs::File::create(&args[5])?,
        );
    }
    if args.len() < 4 || !matches!(args[1].as_str(), "run" | "stream") {
        return Err("usage: verikernel-linux run|stream POLICY.json COMMAND [ARGS]".into());
    }
    linux::install_interrupt_handlers();
    let policy: SandboxPolicy = serde_json::from_slice(&std::fs::read(&args[2])?)?;
    let mut seed = [0u8; 32];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut seed)?;
    let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    if args[1] == "stream" {
        let mut output = std::io::stdout().lock();
        let commitment = verikernel_core::ratchet::ForwardSecureRatchet::new(seed).commitment;
        writeln!(
            output,
            "{}",
            serde_json::json!({"kind":"header","backend":"linux-landlock-seccomp","hash_algorithm":"blake3","audit_seed":hex(&seed),"commitment":hex(&commitment)})
        )?;
        output.flush()?;
        let result = linux::supervise_stream(&policy, &args[3..], seed, 0, 0, |event, target| {
            writeln!(
                output,
                "{}",
                serde_json::json!({"kind":"event","bytes":hex(&event.to_bytes()),"target":target})
            )?;
            output.flush()
        })?;
        writeln!(
            output,
            "{}",
            serde_json::json!({"kind":"terminal","status":result.status,"event_count":result.events.len(),"terminal":hex(&result.terminal)})
        )?;
        output.flush()?;
        return Ok(());
    }
    let result = linux::supervise(&policy, &args[3..], seed, 0, 0)?;
    let records: Vec<_> = result.events.iter().map(|e| hex(&e.to_bytes())).collect();
    println!(
        "{}",
        serde_json::json!({"backend":"linux-landlock-seccomp","status":result.status,"events":records,"audit_seed":hex(&seed),"commitment":hex(&result.commitment),"terminal":hex(&result.terminal)})
    );
    Ok(())
}
#[cfg(target_os = "linux")]
/// Parse command-line arguments and return the workflow status. Complexity: O(n + W) time and O(n + M) space, including called operations W and retained state M.
fn main() -> () {
    if let Err(error) = execute() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
#[cfg(not(target_os = "linux"))]
/// Parse command-line arguments and return the workflow status. Complexity: O(n + W) time and O(n + M) space, including called operations W and retained state M.
fn main() -> () {
    eprintln!("this executable requires a Linux kernel");
    std::process::exit(78);
}
