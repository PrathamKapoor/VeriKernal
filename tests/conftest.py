import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for name in ("TEMP", "TMP", "TMPDIR"):
    os.environ[name] = str(ROOT / ".tmp")
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
