"""The offline demo: the synthetic pipeline, and the board page it can write."""
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEMO = ROOT / "tools" / "demo.py"


def run_demo(cwd, *args):
    return subprocess.run([sys.executable, str(DEMO), *args], cwd=cwd, capture_output=True, text=True,
                          encoding="utf-8", timeout=120)


def test_demo_prints_the_pipeline_without_writing_a_page(tmp_path):
    result = run_demo(tmp_path)
    assert result.returncode == 0, result.stderr
    assert "SYNTHETIC DEMO" in result.stdout
    assert "4 P1" in result.stdout
    assert "config not enabled in demo: us-east-1" in result.stdout
    assert "aws_s3_bucket_public_access_block.exports" in result.stdout
    assert not list(tmp_path.glob("*.html"))


def test_html_flag_writes_the_real_board_page(tmp_path):
    out = tmp_path / "board.html"
    result = run_demo(tmp_path, "--html", str(out))
    assert result.returncode == 0, result.stderr
    page = out.read_text(encoding="utf-8")
    assert "<title>RemediGenius board — demo (synthetic data)</title>" in page
    assert '<span class="pill ">recent snapshot</span>' in page
    assert 'class="pill p1"' in page
    assert "Config.1 AWS Config should be enabled" in page
    assert "config not enabled in demo: us-east-1" in page
    assert "<script" not in page
    assert "http://" not in page and "https://" not in page
    assert '<span class="ref">python tools/demo.py --html</span>' in page
    assert f"Board page: {out.resolve()}" in result.stdout


def test_html_defaults_to_demo_board_html(tmp_path):
    result = run_demo(tmp_path, "--html")
    assert result.returncode == 0, result.stderr
    out = tmp_path / "demo-board.html"
    assert out.exists()
    assert "Security attention board" in out.read_text(encoding="utf-8")