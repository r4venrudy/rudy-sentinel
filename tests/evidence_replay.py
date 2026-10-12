import json
from pathlib import Path
import subprocess
import sys
import tempfile
exe, root = sys.argv[1], Path(sys.argv[2])
with tempfile.TemporaryDirectory() as temp:
    out = Path(temp) / "replay"
    subprocess.run([exe, "--replay", str(root / "examples/demo.ndjson"), "--rules", str(root / "rules/default.json"), "--out", str(out)], check=True, capture_output=True, timeout=30)
    alerts = out / "alerts.ndjson"
    raw = subprocess.check_output([exe, "--export-evidence", str(alerts), "--scope", "fixture:host:boot:one"], timeout=30)
    bundle = json.loads(raw)
    expected = sum(json.loads(row).get("kind") == "alert" for row in alerts.read_text().splitlines())
    assert expected > 0 and bundle["summary"]["findings"] == expected
    assert all(f["scope"] == "fixture:host:boot:one" and f["asset"]["kind"] == "process" for f in bundle["findings"])
    assert all("not a malware verdict" in " ".join(f["evidence"]) for f in bundle["findings"])
    assert '"command":' not in raw.decode() and '"event":' not in raw.decode()
    other = json.loads(subprocess.check_output([exe, "--export-evidence", str(alerts), "--scope", "fixture:host:boot:two"], timeout=30))
    assert {f["fingerprint"] for f in bundle["findings"]}.isdisjoint(f["fingerprint"] for f in other["findings"])
    for extra in [[], ["--scope", "test", "--live"]]:
        result = subprocess.run([exe, "--export-evidence", str(alerts), *extra], capture_output=True, timeout=30)
        assert result.returncode == 1 and not result.stdout
print(f"Native evidence export passed for {expected} real replay alerts, scope separation and invalid modes.")
