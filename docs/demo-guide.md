# VeriKernel demonstration playbook

I run every command from the repository root. I keep caches, compiled libraries and demonstration receipts inside this directory.

```powershell
Set-Location C:\Pratham\VeriKernel
. .\scripts\env.ps1
.\.venv\Scripts\python.exe scripts/build_native.py
.\.venv\Scripts\python.exe -m pytest -v
.\.venv\Scripts\python.exe -m benchmarks.run_benchmarks
.\.venv\Scripts\python.exe -m verikernel.cli.main demo
.\.venv\Scripts\python.exe -m verikernel.cli.main ui --port 8765
```

I open `http://127.0.0.1:8765` and retain the terminal for shutdown with Ctrl+C.
The standalone [dashboard](../benchmarks/results/demo_mission_control.html) works without a server or network connection, displaying recorded verified traces. The server's attack buttons perform fresh cryptographic checks against the demonstration bundle.

1. I start at telemetry and identify the measured runtime and FNV buffer size before discussing speedup. Throughput is workload-specific.
2. I open the dependency graph, inspect the undeclared native library and loopback connection, and show the applied patch and successful strict rerun.
3. I move through the actual subset-oracle trace. Thirty-two faults reduce to sites 7 and 23; I explain 1-minimality rather than promising global optimality.
4. I trigger all four attacks. I inspect event bytes 0–63 for metadata, 64–95 for target digest and 96–127 for the ratchet tag. The payload mutation flips one target-digest bit; truncation and swapping break the checkpointed chain. The response-vector mutation violates the signature norm bound.
5. I inspect physical qubit 2's T2 reduction, the healthy replacement layout and the matrix fidelity. I explicitly identify the snapshot as a local synthetic model.

I can run each case independently, with complete results and receipts written under ignored `dist/`:

```powershell
.\.venv\Scripts\python.exe -m examples.ghost_native_dependency --output-dir dist/case1
.\.venv\Scripts\python.exe -m examples.wal_heisenbug_shrink --output-dir dist/case2
.\.venv\Scripts\python.exe -m examples.quantum_drift_reroute --output-dir dist/case3
.\.venv\Scripts\python.exe -m verikernel.cli.main ui --port 0 --self-test
.\.venv\Scripts\python.exe scripts/verify_linux_env.py
.\.venv\Scripts\python.exe scripts/preflight_ci.py
```

I stop the UI before rebuilding its loaded native library on Windows. Each receipt uses a new name; publication refuses to overwrite existing evidence. I retain audit-seed sidecars privately and do not publish them as trusted identity evidence.

The Linux harness chooses a real available runtime and records its kernel, uid, actual syscall results and authentication outcome. Missing WSL or Docker is reported honestly; a configured CI matrix does not constitute completed remote execution.

I diagnose any failed gate through `dist/preflight/` logs and `benchmarks/results/preflight_ci.json`. I do not replace failed measurements with target values. The report separates repository containment from unrelated pre-existing files beside the workspace.

I inspect a newly created receipt from the terminal and can select cooperative Python process-tree capture:

```powershell
verikernel trace .tmp/workload.py --contract .tmp/contract.vk.json --backend multiprocess --bundle .tmp/process-tree.vkr
verikernel inspect .tmp/process-tree.vkr --event-seq 0 --show-merkle --show-diff --show-ddmin
verikernel inspect .tmp/process-tree.vkr --format json
python scripts/quality_audit.py
```

I create the workload and contract with the README commands first and choose an unused bundle name.
The inspector verifies before rendering; I never treat decoded bytes from an invalid bundle as verified evidence.
I run the standalone quality audit after preflight has cleared `.tmp`; active test or demo artifacts otherwise correctly fail that custody check.
I identify SHA-256 batch receipts separately from older BLAKE3 profiles and retain external ledger checkpoints for rollback detection.
The timing table reports current observations alongside the retained pre-hardening result, without implying certification.
