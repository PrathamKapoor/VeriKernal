"""Drift firewall."""
from __future__ import annotations
import math


def entropy(probabilities: object) -> object:
    """entropy. Complexity: O(g * 4^q + P) time and O(4^q + P) space as an upper bound; g counts gates and P is enumerated layout work."""
    return -sum(p*math.log(p) for p in probabilities if p)


def audit_uncertainty(predictions: object, shots: int, reference: object, calibration: object, ignorance_limit: float=.1, drift_limit: float=.1, variance_limit: float=.001) -> object:
    """audit uncertainty. Complexity: O(g * 4^q + P) time and O(4^q + P) space as an upper bound; g counts gates and P is enumerated layout work."""
    if shots <= 0 or not predictions or any(not math.isfinite(p) or not 0 <= p <= 1 for p in predictions):
        raise ValueError("invalid ensemble or shot count")
    for probabilities in (reference, calibration):
        if not probabilities or any(not math.isfinite(p) or p < 0 for p in probabilities) or not math.isclose(sum(probabilities), 1.0, abs_tol=1e-9):
            raise ValueError("calibration distributions must be normalized")
    if len(reference) != len(calibration):
        raise ValueError("calibration dimensions differ")
    mean = sum(predictions)/len(predictions)
    total = entropy([mean, 1-mean])
    ignorance = max(0.0, total - sum(entropy([p, 1-p]) for p in predictions)/len(predictions))
    variance = mean*(1-mean)/shots
    drift = sum(p*math.log(p/q) if q else math.inf for p, q in zip(calibration, reference) if p)
    verdict = "ABSTAIN_HARDWARE_DRIFT" if drift > drift_limit else "ABSTAIN_OOD_IGNORANCE" if ignorance > ignorance_limit else "ADD_SHOTS" if variance > variance_limit else "PREDICT_CERTIFIED"
    return {"H_total": total, "I_epistemic": ignorance, "sigma2_shot": variance, "D_drift": drift, "shots": shots, "verdict": verdict, "thresholds": {"ignorance": ignorance_limit, "drift": drift_limit, "variance": variance_limit}, "ensemble_predictions": list(predictions), "reference_calibration": list(reference), "current_calibration": list(calibration)}
