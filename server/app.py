"""AgentProof.cloud HTTP service: the commercial site + the SaaS API.

* ``/`` serves the static commercial site from ``site/``.
* ``/api/*`` is the JSON API used by the site's four views.

The app is deliberately a single process with SQLite: enough to run the whole
commercial loop on one container (Railway/Render/Fly), and honest about it.
"""

from __future__ import annotations

import threading
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, AsyncIterator

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import config, db, exports, ledger, scan, service, signing

APP_DIR = Path(__file__).resolve().parent

RUNTIME: dict[str, Any] = {}

# --- naive per-IP rate limit for the free scanner (single process) ----------
_RATE_LOCK = threading.Lock()
_RATE: dict[str, list[float]] = {}
SCAN_RATE_LIMIT = 30
SCAN_RATE_WINDOW = 60.0


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    config.DATA_DIR.mkdir(parents=True, exist_ok=True)
    db.init_db(config.DB_PATH)
    master = signing.load_master_key(config.DATA_DIR)

    key_path = config.DATA_DIR / "platform.key.pem"
    pub_path = config.DATA_DIR / "platform.pub.pem"
    if key_path.exists() and pub_path.exists():
        platform_private_pem = key_path.read_bytes()
        platform_public_pem = pub_path.read_bytes()
    else:
        platform_private_pem, platform_public_pem = signing.generate_keypair_pem()
        key_path.write_bytes(platform_private_pem)
        pub_path.write_bytes(platform_public_pem)

    RUNTIME.update(
        {
            "master": master,
            "platform_private_pem": platform_private_pem,
            "platform_public_pem": platform_public_pem,
            "started_at": ledger.now_iso(),
        }
    )
    yield
    RUNTIME.clear()


app = FastAPI(
    title="AgentProof.cloud",
    version=config.APP_VERSION,
    description="Vendor-neutral compliance evidence for AI agents — commercial site + SaaS API.",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def security_headers(request: Request, call_next):  # type: ignore[no-untyped-def]
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
        "script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
    )
    return response


# ---------------------------------------------------------------------------
# error handling: every failure is machine-readable
# ---------------------------------------------------------------------------


@app.exception_handler(HTTPException)
async def http_error_handler(_request: Request, exc: HTTPException) -> JSONResponse:
    detail = exc.detail
    if isinstance(detail, dict):
        payload = {"code": detail.get("code", "http_error"), "message": detail.get("message", ""), **detail}
    else:
        payload = {"code": "http_error", "message": str(detail)}
    return JSONResponse(status_code=exc.status_code, content={"error": payload})


@app.exception_handler(RequestValidationError)
async def validation_error_handler(_request: Request, exc: RequestValidationError) -> JSONResponse:
    return JSONResponse(
        status_code=422,
        content={
            "error": {
                "code": "validation_error",
                "message": "请求字段不合法",
                "details": jsonable_encoder(exc.errors()),
            }
        },
    )


@app.exception_handler(scan.ScanInputError)
async def scan_input_error_handler(_request: Request, exc: scan.ScanInputError) -> JSONResponse:
    return JSONResponse(
        status_code=400,
        content={"error": {"code": "scan_input_error", "message": str(exc)}},
    )


@app.exception_handler(service.QuotaExceeded)
async def quota_error_handler(_request: Request, exc: service.QuotaExceeded) -> JSONResponse:
    return JSONResponse(
        status_code=429,
        content={
            "error": {
                "code": "quota_exceeded",
                "message": str(exc),
                "used": exc.used,
                "quota": exc.quota,
                "plan": exc.plan,
            }
        },
    )


# ---------------------------------------------------------------------------
# dependencies / request models
# ---------------------------------------------------------------------------


def get_conn():  # type: ignore[no-untyped-def]
    conn = db.connect(config.DB_PATH)
    try:
        yield conn
    finally:
        conn.close()


class ScanIn(BaseModel):
    kind: str = Field(default="mcp", max_length=16)
    content: str = Field(min_length=1)
    subject: str = Field(default="scanned-agent", max_length=80)
    api_key: str | None = None


class SignupIn(BaseModel):
    company: str = Field(min_length=1, max_length=80)
    email: str = Field(min_length=5, max_length=120)
    plan: str = Field(default="pro", max_length=16)
    billing: str = Field(default="monthly", max_length=16)


class LoginIn(BaseModel):
    api_key: str = Field(min_length=16, max_length=200)


class SimulateIn(BaseModel):
    action: str = Field(min_length=1, max_length=120)
    decision: str = Field(default="ALLOW", max_length=8)
    reason: str = Field(default="", max_length=400)
    actor: str = Field(default="production-agent", max_length=80)


def _api_key_from_headers(x_api_key: str | None, authorization: str | None) -> str:
    if x_api_key:
        return x_api_key.strip()
    if authorization and authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    return ""


def current_tenant(
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    authorization: str | None = Header(default=None),
    conn=Depends(get_conn),
) -> dict[str, Any]:
    key = _api_key_from_headers(x_api_key, authorization)
    if not key:
        raise HTTPException(
            status_code=401,
            detail={"code": "missing_api_key", "message": "缺少 API Key：请在控制台输入 ap_live_… 或 ap_free_… 密钥"},
        )
    tenant = service.find_tenant_by_api_key(conn, key)
    if tenant is None:
        raise HTTPException(
            status_code=401,
            detail={"code": "invalid_api_key", "message": "API Key 无效或已被停用"},
        )
    return tenant


def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _rate_limit(ip: str) -> None:
    now = time.monotonic()
    with _RATE_LOCK:
        hits = [t for t in _RATE.get(ip, []) if now - t < SCAN_RATE_WINDOW]
        if len(hits) >= SCAN_RATE_LIMIT:
            retry = int(SCAN_RATE_WINDOW - (now - hits[0])) + 1
            raise HTTPException(
                status_code=429,
                detail={
                    "code": "rate_limited",
                    "message": f"免费扫描限制为每分钟 {SCAN_RATE_LIMIT} 次，请 {retry} 秒后再试",
                    "retry_after_seconds": retry,
                },
                headers={"Retry-After": str(retry)},
            )
        hits.append(now)
        _RATE[ip] = hits


def _public_tenant(tenant: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": tenant["id"],
        "company": tenant["company"],
        "email": tenant["email"],
        "plan": tenant["plan"],
        "billing": tenant["billing"],
        "status": tenant["status"],
        "created_at": tenant["created_at"],
        "api_key_prefix": tenant["api_key_prefix"],
    }


# ---------------------------------------------------------------------------
# public endpoints
# ---------------------------------------------------------------------------


@app.get("/api/health")
def health(conn=Depends(get_conn)) -> dict[str, Any]:
    stats = service.platform_stats(conn)
    return {
        "ok": True,
        "service": "agentproof-cloud",
        "version": config.APP_VERSION,
        "mode": "sandbox-checkout",
        "started_at": RUNTIME.get("started_at"),
        "time": ledger.now_iso(),
        **stats,
    }


@app.get("/api/plans")
def plans() -> dict[str, Any]:
    data = []
    for plan in config.PLANS.values():
        item = dict(plan)
        item["annual_saving"] = config.annual_saving(plan)
        data.append(item)
    return {"currency": "USD", "plans": data, "vendors": exports.VENDORS}


@app.get("/api/stats")
def stats(conn=Depends(get_conn)) -> dict[str, Any]:
    return service.platform_stats(conn)


@app.get("/api/arr")
def arr(conn=Depends(get_conn)) -> dict[str, Any]:
    return service.arr_summary(conn)


@app.post("/api/scan")
def run_scan(payload: ScanIn, request: Request, conn=Depends(get_conn)) -> dict[str, Any]:
    _rate_limit(_client_ip(request))
    result = scan.scan(payload.kind, payload.content, subject=payload.subject or "scanned-agent")
    result_dict = result.as_dict()
    scan_id = service.record_scan(conn, result_dict, payload.subject or "scanned-agent")
    return {"scan_id": scan_id, "result": result_dict}


@app.post("/api/signup")
def signup(payload: SignupIn, conn=Depends(get_conn)) -> dict[str, Any]:
    company = payload.company.strip()
    email = payload.email.strip()
    if len(company) < 2:
        raise HTTPException(
            status_code=422,
            detail={"code": "validation_error", "message": "公司名称至少 2 个字符"},
        )
    if not config.EMAIL_RE.match(email):
        raise HTTPException(
            status_code=422,
            detail={"code": "validation_error", "message": "邮箱格式不合法"},
        )
    plan = None
    try:
        plan = config.plan_or_raise(payload.plan)
    except ValueError as exc:
        raise HTTPException(
            status_code=422,
            detail={"code": "validation_error", "message": str(exc)},
        ) from exc
    billing = "annual" if payload.billing.lower() == "annual" else "monthly"

    tenant, api_key = service.create_tenant(
        conn,
        master=RUNTIME["master"],
        platform_private_pem=RUNTIME["platform_private_pem"],
        company=company,
        email=email,
        plan_id=plan["id"],
        billing=billing,
    )
    usage = service.usage_for(conn, tenant)
    arr = service.arr_summary(conn)
    amount = plan["price_annual"] if billing == "annual" else plan["price_monthly"]
    return {
        "ok": True,
        "tenant": _public_tenant(tenant),
        "api_key": api_key,
        "plan": {
            "id": plan["id"],
            "name": plan["name"],
            "price": amount,
            "billing": billing,
            "currency": "USD",
            "quota_events": plan["quota_events"],
        },
        "checkout": {
            "mode": "sandbox",
            "charged": False,
            "amount": amount,
            "currency": "USD",
            "note": "演示环境：未接入支付网关，本次没有真实扣款。接入 Stripe 后这里会返回真实 Checkout 链接。",
        },
        "usage": usage,
        "arr": arr,
        "console_url": "#/console",
    }


# ---------------------------------------------------------------------------
# authenticated tenant endpoints
# ---------------------------------------------------------------------------


@app.get("/api/me")
def me(tenant: dict[str, Any] = Depends(current_tenant), conn=Depends(get_conn)) -> dict[str, Any]:
    usage = service.usage_for(conn, tenant)
    platform_fp = signing.public_key_fingerprint(RUNTIME["platform_public_pem"])
    tenant_fp = signing.public_key_fingerprint(tenant["tenant_public_pem"])
    return {
        "tenant": _public_tenant(tenant),
        "usage": usage,
        "fingerprints": {
            "platform": platform_fp,
            "tenant": tenant_fp,
            "platform_public_pem": RUNTIME["platform_public_pem"].decode("utf-8"),
            "tenant_public_pem": tenant["tenant_public_pem"],
        },
        "arr": service.arr_summary(conn),
    }


@app.post("/api/login")
def login(payload: LoginIn, conn=Depends(get_conn)) -> dict[str, Any]:
    tenant = service.find_tenant_by_api_key(conn, payload.api_key.strip())
    if tenant is None:
        raise HTTPException(
            status_code=401,
            detail={"code": "invalid_api_key", "message": "API Key 无效或已被停用"},
        )
    return {"ok": True, "tenant": _public_tenant(tenant), "usage": service.usage_for(conn, tenant)}


@app.get("/api/ledger")
def get_ledger(
    limit: int = 50,
    tenant: dict[str, Any] = Depends(current_tenant),
    conn=Depends(get_conn),
) -> dict[str, Any]:
    limit = max(1, min(limit, 200))
    events = ledger.load_events(conn, tenant["id"], limit=limit)
    return {
        "tenant_id": tenant["id"],
        "events": list(reversed(events)),
        "returned": len(events),
        "usage": service.usage_for(conn, tenant),
    }


@app.post("/api/ledger/simulate")
def simulate(
    payload: SimulateIn,
    tenant: dict[str, Any] = Depends(current_tenant),
    conn=Depends(get_conn),
) -> dict[str, Any]:
    decision = payload.decision.upper()
    if decision not in ledger.Decisions:
        raise HTTPException(
            status_code=422,
            detail={"code": "validation_error", "message": "decision 必须是 ALLOW / HALT / DENY"},
        )
    usage = service.usage_for(conn, tenant)
    if usage["used_this_month"] >= usage["quota_events"]:
        raise service.QuotaExceeded(usage["used_this_month"], usage["quota_events"], tenant["plan"])

    with db.write_lock():
        record = ledger.append_event(
            conn,
            tenant=tenant,
            master=RUNTIME["master"],
            platform_private_pem=RUNTIME["platform_private_pem"],
            actor=payload.actor or "production-agent",
            action=payload.action,
            decision=decision,
            reason=payload.reason or "模拟生产动作（demo）",
            policy_id="agentproof-cloud-demo",
            inputs={"source": "console-simulator"},
            source="simulated",
        )
    return {
        "ok": True,
        "record": record,
        "usage": service.usage_for(conn, tenant),
        "note": "该记录由 console 模拟器生成，source=simulated，可在账本中识别。",
    }


@app.get("/api/verify")
def verify(tenant: dict[str, Any] = Depends(current_tenant), conn=Depends(get_conn)) -> dict[str, Any]:
    return ledger.verify_tenant_chain(
        conn,
        tenant=tenant,
        platform_public_pem=RUNTIME["platform_public_pem"],
    )


@app.get("/api/export/{vendor}")
def export_vendor(
    vendor: str,
    tenant: dict[str, Any] = Depends(current_tenant),
    conn=Depends(get_conn),
) -> dict[str, Any]:
    if vendor.lower() not in exports.VENDORS:
        raise HTTPException(
            status_code=404,
            detail={
                "code": "unknown_vendor",
                "message": f"未知生态方 {vendor!r}；可选：{', '.join(exports.VENDORS)}",
            },
        )
    plan = config.plan_or_raise(tenant["plan"])
    usage = service.usage_for(conn, tenant)
    events = ledger.load_events(conn, tenant["id"])
    verification = ledger.verify_tenant_chain(
        conn,
        tenant=tenant,
        platform_public_pem=RUNTIME["platform_public_pem"],
    )
    payload = exports.build_export(
        vendor,
        tenant=tenant,
        plan=plan,
        usage=usage,
        events=events,
        verification=verification,
    )
    with db.write_lock():
        ledger.append_event(
            conn,
            tenant=tenant,
            master=RUNTIME["master"],
            platform_private_pem=RUNTIME["platform_private_pem"],
            actor="export-worker",
            action=f"export.{vendor.lower()}",
            decision="ALLOW",
            reason=f"生成 {exports.VENDORS[vendor.lower()]['name']} 证据报文",
            policy_id="agentproof-export-v1",
            inputs={"vendor": vendor.lower()},
            source="export",
        )
    return payload


# ---------------------------------------------------------------------------
# static site (must be mounted last so /api/* wins)
# ---------------------------------------------------------------------------

if config.SITE_DIR.is_dir():
    app.mount("/", StaticFiles(directory=str(config.SITE_DIR), html=True), name="site")
