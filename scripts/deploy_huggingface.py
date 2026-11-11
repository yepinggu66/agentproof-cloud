"""Deploy AgentProof.cloud to a free Hugging Face Space (Docker SDK).

Requires a Hugging Face account and a write token:
    https://huggingface.co/settings/tokens   (scope: write)

Usage:
    $env:HF_TOKEN = "hf_..."
    python scripts/deploy_huggingface.py
    python scripts/deploy_huggingface.py --name agentproof-cloud --private

The Space is built from deploy/huggingface/Dockerfile and serves the FastAPI app
on port 7860. Storage is ephemeral on the free tier: tenants and ledgers reset
when the Space restarts.
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys
import tempfile
from pathlib import Path

from huggingface_hub import HfApi

ROOT = Path(__file__).resolve().parent.parent
STAGE_FILES = ["requirements.txt"]
STAGE_DIRS = ["server", "site", "src"]
IGNORE = [".git", "**/__pycache__/**", "*.pyc", ".tmp", "data", "tests", "docs", "deploy", "scripts", "demo", "examples", "*.db"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Deploy to a Hugging Face Space.")
    parser.add_argument("--name", default="agentproof-cloud", help="Space repo name")
    parser.add_argument("--private", action="store_true", help="create a private Space")
    args = parser.parse_args(argv)

    token = os.environ.get("HF_TOKEN") or os.environ.get("HUGGINGFACE_TOKEN")
    if not token:
        print("missing HF_TOKEN (create one at https://huggingface.co/settings/tokens)", file=sys.stderr)
        return 2

    api = HfApi(token=token)
    user = api.whoami()["name"]
    repo_id = f"{user}/{args.name}"
    print(f"target Space: {repo_id}")

    with tempfile.TemporaryDirectory(prefix="agentproof-hf-") as tmp:
        stage = Path(tmp)
        shutil.copy2(ROOT / "deploy" / "huggingface" / "Dockerfile", stage / "Dockerfile")
        shutil.copy2(ROOT / "deploy" / "huggingface" / "README.md", stage / "README.md")
        for name in STAGE_FILES:
            shutil.copy2(ROOT / name, stage / name)
        for name in STAGE_DIRS:
            shutil.copytree(ROOT / name, stage / name, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))

        api.create_repo(repo_id=repo_id, repo_type="space", space_sdk="docker", private=args.private, exist_ok=True)
        api.upload_folder(
            folder_path=str(stage),
            repo_id=repo_id,
            repo_type="space",
            commit_message="Deploy AgentProof.cloud (site + API) to Hugging Face Space",
            ignore_patterns=IGNORE,
        )

    url = f"https://huggingface.co/spaces/{repo_id}"
    print(f"deployed: {url}")
    print(f"app URL (after build): https://{user}-{args.name}.hf.space")
    print("build usually takes 2-5 minutes; check the Space logs for progress")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
