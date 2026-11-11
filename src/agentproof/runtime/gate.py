"""RuntimeGate: 1-line decorator that enforces policy and signs a receipt BEFORE execution."""

from __future__ import annotations

import functools
import inspect
import json
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable, TypeVar

from ..core.canonical import digest_bytes
from ..core.chain import Chain, generate_keypair, load_private_key
from ..core.policy import Evaluation, Policy, load_policy
from ..core.receipt import Receipt

F = TypeVar("F", bound=Callable[..., Any])


class PolicyDeniedError(PermissionError):
    """Raised when a guarded tool or MCP action is denied or halted by policy.

    The signed pre-execution receipt is attached as ``self.receipt`` so the
    caller or audit harness can inspect the exact cryptographic refusal record.
    """

    def __init__(self, evaluation: Evaluation, receipt: Receipt) -> None:
        self.evaluation = evaluation
        self.receipt = receipt
        super().__init__(
            f"[{evaluation.decision.value}] Action {receipt.action!r} blocked by rule "
            f"{evaluation.rule_id!r}: {evaluation.reason} (receipt seq={receipt.seq})"
        )


class RuntimeGate:
    """Enforces a fail-closed policy and issues signed receipts before side effects run.

    Example::

        gate = RuntimeGate("policy.yaml", actor="support-agent")

        @gate.guard("db.write", scopes=["db:admin"])
        def update_customer(sql: str) -> dict:
            return {"ok": True}
    """

    def __init__(
        self,
        policy: str | Path | dict[str, Any] | Policy,
        *,
        private_key_path: str | Path | None = None,
        chain_path: str | Path | None = None,
        actor: str = "agent",
        default_scopes: list[str] | None = None,
        cloud_url: str | None = None,
        api_key: str | None = None,
        cloud_notary: Any | None = None,
    ) -> None:
        self.policy = policy if isinstance(policy, Policy) else load_policy(policy)
        self.actor = actor
        self.default_scopes = list(default_scopes or [])
        self.chain_path = Path(chain_path) if chain_path else None
        self.cloud_url = cloud_url.rstrip("/") if cloud_url else None
        self.api_key = api_key
        self.cloud_notary = cloud_notary
        self.notarized_receipts: list[dict[str, Any]] = []

        if private_key_path:
            priv = load_private_key(private_key_path)
        else:
            priv, _ = generate_keypair()

        if self.chain_path and self.chain_path.exists():
            self.chain = Chain.load(self.chain_path, priv)
        else:
            self.chain = Chain(priv, subject=self.policy.subject)

    def evaluate_and_record(
        self,
        action: str,
        *,
        inputs: dict[str, Any] | None = None,
        actor: str | None = None,
        scopes: list[str] | None = None,
        extra_context: dict[str, Any] | None = None,
    ) -> tuple[Evaluation, Receipt]:
        """Evaluate ``action`` and append a signed receipt *before* execution."""
        inputs = inputs or {}
        effective_scopes = scopes if scopes is not None else self.default_scopes
        evaluation = self.policy.evaluate(
            action,
            inputs=inputs,
            context={"scopes": effective_scopes, **(extra_context or {})},
        )

        ctx = {
            "rule_id": evaluation.rule_id,
            "scopes": effective_scopes,
            **(extra_context or {}),
        }
        receipt = self.chain.append(
            actor=actor or self.actor,
            action=action,
            decision=evaluation.decision,
            reason=evaluation.reason,
            policy_id=self.policy.policy_id,
            policy_digest=self.policy.policy_digest,
            inputs_digest=digest_bytes(inputs),
            context=ctx,
        )

        if self.chain_path:
            self.chain.save(self.chain_path)

        self._sync_to_cloud(receipt)
        return evaluation, receipt

    def guard(
        self,
        action: str | None = None,
        *,
        actor: str | None = None,
        scopes: list[str] | None = None,
    ) -> Callable[[F], F]:
        """Decorator that gates a synchronous or async function with a pre-action receipt."""

        def decorator(fn: F) -> F:
            action_name = action or fn.__name__.replace("_", ".")
            sig = inspect.signature(fn)

            if inspect.iscoroutinefunction(fn):

                @functools.wraps(fn)
                async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                    bound_inputs = _bind_inputs(sig, args, kwargs)
                    evaluation, receipt = self.evaluate_and_record(
                        action_name,
                        inputs=bound_inputs,
                        actor=actor,
                        scopes=scopes,
                    )
                    if not evaluation.permitted:
                        raise PolicyDeniedError(evaluation, receipt)
                    return await fn(*args, **kwargs)

                return async_wrapper  # type: ignore[return-value]

            @functools.wraps(fn)
            def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                bound_inputs = _bind_inputs(sig, args, kwargs)
                evaluation, receipt = self.evaluate_and_record(
                    action_name,
                    inputs=bound_inputs,
                    actor=actor,
                    scopes=scopes,
                )
                if not evaluation.permitted:
                    raise PolicyDeniedError(evaluation, receipt)
                return fn(*args, **kwargs)

            return sync_wrapper  # type: ignore[return-value]

        return decorator

    def wrap_tools(
        self,
        tools: dict[str, Callable[..., Any]],
        *,
        actor: str | None = None,
        scopes: list[str] | None = None,
    ) -> dict[str, Callable[..., Any]]:
        """Wrap a dictionary of ``{action_name: callable}`` with pre-execution gates."""
        return {
            name: self.guard(name, actor=actor, scopes=scopes)(fn)
            for name, fn in tools.items()
        }

    def _sync_to_cloud(self, receipt: Receipt) -> None:
        """Send the signed receipt to AgentProof Cloud for out-of-band Witness counter-signing."""
        payload = {
            "chain_id": self.chain.chain_id,
            "subject": self.chain.subject,
            "public_key": self.chain.public_key_hex,
            "receipt": receipt.to_dict(),
        }
        if self.cloud_notary is not None and self.api_key:
            notarized = self.cloud_notary.notarize_receipt(
                api_key=self.api_key,
                chain_id=self.chain.chain_id,
                subject=self.chain.subject,
                public_key_hex=self.chain.public_key_hex,
                receipt_dict=receipt.to_dict(),
            )
            self.notarized_receipts.append(notarized)
            return

        if self.cloud_url and self.api_key:
            req = urllib.request.Request(
                f"{self.cloud_url}/api/v1/notarize",
                data=json.dumps(payload).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "X-AgentProof-Key": self.api_key,
                },
                method="POST",
            )
            try:
                with urllib.request.urlopen(req, timeout=5) as resp:  # noqa: S310
                    body = json.loads(resp.read().decode("utf-8"))
                    self.notarized_receipts.append(body)
            except (urllib.error.URLError, ValueError):
                # Local fail-closed gate still holds even if network telemetry drops
                pass


def _bind_inputs(
    sig: inspect.Signature, args: tuple[Any, ...], kwargs: dict[str, Any]
) -> dict[str, Any]:
    try:
        bound = sig.bind_partial(*args, **kwargs)
        bound.apply_defaults()
        return dict(bound.arguments)
    except TypeError:
        return {"args": list(args), "kwargs": dict(kwargs)}
