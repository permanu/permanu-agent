#!/usr/bin/env python3
"""Build a disposable offline fixture harness against explicit local runner source."""
import argparse
import json
import os
import shutil
from pathlib import Path
import subprocess
import tempfile

parser = argparse.ArgumentParser()
parser.add_argument("--runner", required=True, type=Path)
parser.add_argument("--target-dir", type=Path, default=Path("/tmp/permanu-compose-compat-target"))
args = parser.parse_args()
agent = Path(__file__).resolve().parents[2]
runner = args.runner.resolve(strict=True)
if not (runner / "Cargo.toml").is_file() or not (runner / "src/compose_release.rs").is_file():
    parser.error("runner must contain the experimental Compose fixture module")
paths = {
    "STRICT_JSON": agent / "src/signed_plan/strict_json.rs",
    "JCS": agent / "src/signed_plan/jcs.rs",
    "CRYPTO": agent / "src/signed_plan/crypto.rs",
    "AGENT_MODULE": agent / "src/compose_release_v1/mod.rs",
    "FIXTURE": agent / "tests/vectors/compose-release-v1/structural-only.fake.json",
}
harness = Path(__file__).with_name("harness.rs.in").read_text()
for name, path in paths.items():
    harness = harness.replace("@" + name + "@", json.dumps(str(path), ensure_ascii=False))
manifest = '''[package]
name="permanu-compose-crosscomponent-fixture"
version="0.0.0"
edition="2024"
[dependencies]
permanu-runner={path=RUNNER_PATH,features=["compose-release-v1"]}
serde={version="1",features=["derive"]}
serde_json="1"
base64="0.22"
p256={version="0.13.2",default-features=false,features=["ecdsa","std"]}
sha2="0.10"
hex="0.4"
'''.replace("RUNNER_PATH", json.dumps(str(runner), ensure_ascii=False))
with tempfile.TemporaryDirectory(prefix="permanu-compose-fixture-") as folder:
    root = Path(folder)
    (root / "src").mkdir()
    (root / "Cargo.toml").write_text(manifest)
    if (runner / "Cargo.lock").is_file():
        shutil.copyfile(runner / "Cargo.lock", root / "Cargo.lock")
    (root / "src/lib.rs").write_text(harness)
    env = os.environ.copy()
    env["CARGO_TARGET_DIR"] = str(args.target_dir.resolve())
    subprocess.run(["cargo", "test", "--offline", "--jobs", "2", "--manifest-path", str(root / "Cargo.toml")], env=env, check=True)
