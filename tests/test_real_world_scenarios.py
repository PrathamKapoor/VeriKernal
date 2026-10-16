def test_ghost_library_and_socket_patch_heals_real_operations(tmp_path):
    from examples.ghost_native_dependency import run
    result = run(tmp_path)
    assert {'GHOST_SHARED_LIB','GHOST_NETWORK'} <= set(result['ghost_kinds'])
    assert result['healed'] and result['patch']['add']['shared_libraries']


def test_real_wal_compound_failure_is_minimized_and_replayable(tmp_path):
    from examples.wal_heisenbug_shrink import run
    from verikernel.cli.main import verify_bundle
    result = run(tmp_path)
    assert result['initial_fault_count'] == 32
    assert result['minimal_sites'] == [7,23]
    assert result['replay_runs'] == result['reproductions'] == 20
    assert result['acknowledged_without_durability']
    assert verify_bundle(result['bundle'])['valid']


def test_quantum_drift_recovery_is_signed_and_logically_equivalent(tmp_path):
    from examples.quantum_drift_reroute import run
    from verikernel.cli.main import verify_bundle
    result = run(tmp_path)
    assert result['firewall']['verdict'] == 'ABSTAIN_HARDWARE_DRIFT'
    assert 2 not in result['reroute']['layout']
    assert result['reroute']['recovered_fidelity'] > result['reroute']['drifted_fidelity']
    assert result['reroute']['unitary_fidelity'] >= 1-1e-9
    assert verify_bundle(result['bundle'])['valid']
