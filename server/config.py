"""Plan catalogue and shared configuration for the AgentProof.cloud service."""

from __future__ import annotations

import os
import re
from pathlib import Path

APP_VERSION = "0.1.0"
BRAND = "AgentProof.cloud"

BASE_DIR = Path(__file__).resolve().parent.parent
SITE_DIR = BASE_DIR / "site"
DATA_DIR = Path(os.environ.get("AGENTPROOF_DATA_DIR", BASE_DIR / "data")).resolve()
DB_PATH = DATA_DIR / "agentproof.db"

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$")

# Quota is "signed decisions per calendar month". Scans are always free: the
# scanner is the marketing funnel, the ledger is what people pay for.
PLANS: dict[str, dict] = {
    "free": {
        "id": "free",
        "name": "Free 开发者版",
        "tagline": "验证可行性，个人项目与原型",
        "price_monthly": 0,
        "price_annual": 0,
        "quota_events": 100,
        "seats": 1,
        "retention_days": 7,
        "features": [
            "100 条签名决策 / 月",
            "离线 verify + 浏览器独立复算",
            "生成 policy.yaml 并本地校验",
            "7 天账本留存",
            "社区支持",
        ],
        "cta": "免费开始",
    },
    "pro": {
        "id": "pro",
        "name": "Pro 合规团队版",
        "tagline": "面向需要向客户/审计提交证据的团队",
        "price_monthly": 99,
        "price_annual": 950,
        "quota_events": 5000,
        "seats": 5,
        "retention_days": 365,
        "features": [
            "5,000 条签名决策 / 月",
            "Vanta / Drata / Datadog 一键导出",
            "EU AI Act 第 26 条证据包",
            "双签账本 + 链校验 API",
            "1 年账本留存 · 邮件支持",
        ],
        "cta": "开通 Pro",
    },
    "enterprise": {
        "id": "enterprise",
        "name": "Enterprise 保险核保版",
        "tagline": "承保、并购尽调与大规模部署",
        "price_monthly": 1500,
        "price_annual": 14400,
        "quota_events": 100_000,
        "seats": 50,
        "retention_days": 2555,
        "features": [
            "100,000 条签名决策 / 月",
            "Lloyd's AIUC-1 核保报文",
            "私有化部署 / 自带密钥（BYOK）",
            "企业版支持通道（SLA 可协商）",
            "7 年账本留存 · 审计陪同",
        ],
        "cta": "联系销售",
    },
}

DECISIONS = ("ALLOW", "HALT", "DENY")


def plan_or_raise(plan_id: str) -> dict:
    plan = PLANS.get((plan_id or "").lower())
    if plan is None:
        raise ValueError(f"未知套餐 {plan_id!r}；可选：{', '.join(PLANS)}")
    return plan


def annual_saving(plan: dict) -> int:
    return plan["price_monthly"] * 12 - plan["price_annual"]


def arr_for(plan_id: str, billing: str) -> int:
    plan = plan_or_raise(plan_id)
    if plan["price_monthly"] == 0:
        return 0
    if (billing or "monthly").lower() == "annual":
        return plan["price_annual"]
    return plan["price_monthly"] * 12


def mrr_for(plan_id: str, billing: str) -> int:
    return round(arr_for(plan_id, billing) / 12)
