"""Shared fixtures: one temp data dir, one FastAPI app instance per session."""

from __future__ import annotations

import os
import tempfile

# Must be set before importing server.config (it reads the env at import time).
_DATA_DIR = tempfile.mkdtemp(prefix="agentproof-cloud-tests-")
os.environ["AGENTPROOF_DATA_DIR"] = _DATA_DIR
os.environ.setdefault("PYTHONPATH", ".")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from server.app import app  # noqa: E402
from server import config  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@pytest.fixture(scope="session")
def client() -> TestClient:
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture(scope="session")
def tenant(client: TestClient) -> dict:
    """A Pro tenant created once for read-only assertions."""
    response = client.post(
        "/api/signup",
        json={
            "company": "Fixture Labs",
            "email": "fixture@example.dev",
            "plan": "pro",
            "billing": "monthly",
        },
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    return {"key": payload["api_key"], "tenant": payload["tenant"], "payload": payload}


@pytest.fixture()
def fresh_tenant(client: TestClient):
    """Factory for isolated tenants so tests do not share ledger state."""

    created: list[dict] = []

    def make(plan: str = "pro", billing: str = "monthly", company: str = "Isolated Co"):
        response = client.post(
            "/api/signup",
            json={
                "company": f"{company} {len(created)}",
                "email": f"user{len(created)}@isolated.dev",
                "plan": plan,
                "billing": billing,
            },
        )
        assert response.status_code == 200, response.text
        item = response.json()
        created.append(item)
        return item

    return make


@pytest.fixture(scope="session")
def sample_texts() -> dict[str, str]:
    def read(name: str) -> str:
        with open(os.path.join(ROOT, "tests", name), encoding="utf-8") as handle:
            return handle.read()

    return {
        "danger_mcp": read("sample-dangerous-mcp.json"),
        "safe_mcp": read("sample-safe-mcp.json"),
        "python": read("sample-python-agent.py"),
    }


@pytest.fixture(scope="session")
def db_path() -> str:
    return str(config.DB_PATH)
