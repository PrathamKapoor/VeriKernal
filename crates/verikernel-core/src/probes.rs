//! CO-RE probe loading and authenticated kernel telemetry collection.
use aya::maps::{Array, HashMap, PerCpuArray, PerCpuValues, RingBuf};
use aya::programs::{KProbe, Lsm};
use aya::{Btf, EbpfLoader};
use std::io::{self, Read, Write};
use std::os::unix::fs::MetadataExt;
use std::time::{Duration, Instant};

/// Load the probes and stream their authenticated telemetry. Complexity: O(n + W) time and O(n + M) space, including called operations W and retained state M.
pub fn trace(
    object: &str,
    pid: u32,
    allow: &[String],
    duration: Duration,
    output: &mut impl Write,
) -> Result<(), Box<dyn std::error::Error>> {
    if pid == 0 {
        return Err("target process id must be nonzero".into());
    }
    let mut bpf = EbpfLoader::new()
        .set_global("target_tgid", &pid, true)
        .load_file(object)?;
    {
        let mut permitted = HashMap::<_, u64, u8>::try_from(
            bpf.map_mut("contract_allow_map")
                .ok_or("missing contract map")?,
        )?;
        for path in allow {
            let metadata = std::fs::metadata(path)?;
            let identity = metadata.ino() ^ (metadata.dev() << 32);
            permitted.insert(identity, 1, 0)?;
        }
    }
    let cpus = aya::util::nr_cpus().map_err(|(_, error)| error)?;
    let mut seeds = vec![[0u8; 32]; cpus];
    let mut random = std::fs::File::open("/dev/urandom")?;
    for seed in &mut seeds {
        random.read_exact(seed)?;
    }
    {
        let mut state = PerCpuArray::<_, [u8; 32]>::try_from(
            bpf.map_mut("ratchet_state_map")
                .ok_or("missing ratchet state")?,
        )?;
        state.set(0, PerCpuValues::try_from(seeds.clone())?, 0)?;
        let mut ready = Array::<_, u32>::try_from(
            bpf.map_mut("ratchet_ready_map")
                .ok_or("missing ratchet readiness")?,
        )?;
        ready.set(0, 1, 0)?;
    }
    let btf = Btf::from_sys_fs()?;
    for (name, hook) in [
        ("vk_file", "file_open"),
        ("vk_exec", "bprm_check_security"),
        ("vk_connect", "socket_connect"),
    ] {
        let program: &mut Lsm = bpf
            .program_mut(name)
            .ok_or("missing LSM program")?
            .try_into()?;
        program.load(hook, &btf)?;
        program.attach()?;
    }
    let program: &mut KProbe = bpf
        .program_mut("vk_read")
        .ok_or("missing read probe")?
        .try_into()?;
    program.load()?;
    program.attach("ksys_read", 0)?;
    let mut ring = RingBuf::try_from(bpf.take_map("events_ringbuf").ok_or("missing event ring")?)?;
    let hex = |data: &[u8]| {
        data.iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    writeln!(
        output,
        "{}",
        serde_json::json!({"kind":"header","profile":"blake2b-256-percpu","seeds":seeds.iter().map(|s|hex(s)).collect::<Vec<_>>()})
    )?;
    let deadline = Instant::now() + duration;
    while Instant::now() < deadline {
        while let Some(event) = ring.next() {
            if event.len() != 128 {
                return Err("incorrect kernel event size".into());
            }
            writeln!(
                output,
                "{}",
                serde_json::json!({"kind":"event","bytes":hex(&event)})
            )?;
        }
        output.flush()?;
        std::thread::sleep(Duration::from_millis(1));
    }
    let states =
        PerCpuArray::<_, [u8; 32]>::try_from(bpf.map("ratchet_state_map").ok_or("missing state")?)?
            .get(&0, 0)?;
    let losses =
        PerCpuArray::<_, u64>::try_from(bpf.map("loss_count_map").ok_or("missing loss counters")?)?
            .get(&0, 0)?;
    writeln!(
        output,
        "{}",
        serde_json::json!({"kind":"terminal","states":states.iter().map(|s|hex(s)).collect::<Vec<_>>(),"losses":losses.iter().copied().sum::<u64>()})
    )?;
    if losses.iter().any(|loss| *loss != 0) {
        return Err(io::Error::other("kernel event reservations were lost").into());
    }
    Ok(())
}
