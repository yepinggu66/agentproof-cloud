"""Example: instrument an agent so every decision is signed before it runs.

This is the integration shape the product is designed around. Note the
ordering: the receipt is issued *before* the tool is called. A tool that
raises still leaves a signed receipt behind saying "this was approved and we
tried", which is exactly the record an auditor wants.

Run it with::

    python examples/instrument.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from agentproof.core.chain import Chain, generate_keypair  # noqa: E402
from agentproof.core.canonical import digest_bytes  # noqa: E402
from agentproof.core.policy import load_policy  # noqa: E402
from agentproof.core.receipt import Decision  # noqa: E402

HERE = Path(__file__).resolve().parent


def main() -> None:
    policy = load_policy(HERE / "policy.yaml")
    private_key, public_key = generate_keypair()
    chain = Chain(private_key, subject=policy.subject)

    # Pretend these are the tools the agent wants to use.
    def kb_search(query: str) -> dict:
        return {"hits": 3, "top": "Refunds accepted within 30 days"}

    def db_write(sql: str) -> dict:
        return {"ok": True}

    available = {
        "kb.search": kb_search,
        "db.write": db_write,
    }

    requests = [
        ("support-agent", "kb.search", {"query": "refund policy"}),
        ("support-agent", "db.write", {"sql": "UPDATE customers SET status='refunded'"}),
    ]

    for actor, action, inputs in requests:
        evaluation = policy.evaluate(action, inputs=inputs)

        # ---- the receipt is issued BEFORE the action ----
        receipt = chain.append(
            actor=actor,
            action=action,
            decision=evaluation.decision,
            reason=evaluation.reason,
            policy_id=policy.policy_id,
            policy_digest=policy.policy_digest,
            inputs_digest=digest_bytes(inputs),
            context={"rule_id": evaluation.rule_id},
        )
        print(f"[{receipt.decision.value}] {action} — {evaluation.reason}")

        # ---- only now does the action run ----
        if evaluation.permitted and action in available:
            output = available[action](**inputs)
            print(f"        → {output}")

    seal = chain.seal_chain()
    print()
    print(f"chain {chain.chain_id} sealed with {seal.record_count} records")
    print(f"seal hash: {seal.seal_hash}")
    print(f"public key: {chain.public_key_hex}")
    print()
    print("Verify with:")
    print("  agentproof verify <chain.json>")


if __name__ == "__main__":
    main()
