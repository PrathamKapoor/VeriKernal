"""Independent finite differential campaigns for compiled arithmetic."""
from scripts.differential_oracles import verify_ntt_reference, verify_ddmin_reference, verify_hash_reference


def test_ntt_matches_schoolbook_reference():
    result = verify_ntt_reference(100)
    assert result['verified'] and result['pairs'] == 100
    assert result['coefficients_checked'] == 25600


def test_ddmin_matches_exhaustive_minimal_sets():
    result = verify_ddmin_reference(20)
    assert result['verified'] and result['subsets_per_predicate'] == 1024
    assert result['max_oracle_evaluations'] < 250
    assert len(result['cases']) == 20


def test_hash_and_tree_match_independent_reference():
    result = verify_hash_reference()
    assert result['verified'] and result['hash_cases'] == 14
    assert result['tree_cases'] == 8
