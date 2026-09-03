import shutil
import subprocess
from pathlib import Path

import pytest


def test_traffic_alert_modal_interactions():
    node = shutil.which("node")
    if node is None:
        pytest.skip("Frontend davranış testi Node.js gerektirir.")
    script = Path(__file__).parent / "js" / "traffic_alert_modal.cjs"
    subprocess.run([node, str(script)], check=True, capture_output=True, text=True, timeout=30)
