"""SawOne-SI runs on the Sawone engine: SAWONE_ENGINE points to its scanner directory (CI checks out the pinned
Sawone release next to this repository; locally a sibling checkout ../sawone works)."""
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
for cand in [os.environ.get("SAWONE_ENGINE"), ROOT / "engine" / "scanner", ROOT.parent / "sawone" / "scanner",
             "/opt/sawone"]:
    if cand and (Path(cand) / "sawone_scan.py").exists():
        os.environ["SAWONE_ENGINE"] = str(Path(cand).resolve())
        break
else:
    raise SystemExit("Sawone engine not found: set SAWONE_ENGINE to the sawone/scanner directory")
os.environ["SAWONE_PROFILE"] = str(ROOT / "scanner" / "profile.yml")
sys.path[:0] = [str(ROOT / "scanner"), os.environ["SAWONE_ENGINE"]]
