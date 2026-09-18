"""Provider-neutral lifecycle for Deployment Validation capabilities.

The framework plans only providers required by rendered artifact evidence,
orders explicit provider dependencies, and records bootstrap/readiness/
reconciliation/cleanup independently.  A provider becoming ready is never
treated as proof that the artifact exercised the capability successfully.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import re
import time
from typing import Any, Callable, Mapping, Protocol, Sequence

from .provider_inventory import ProviderSpec


class BootstrapStatus(str, Enum):
    NOT_ATTEMPTED = "NOT_ATTEMPTED"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    BLOCKED = "BLOCKED"


class ReadinessStatus(str, Enum):
    NOT_CHECKED = "NOT_CHECKED"
    READY = "READY"
    NOT_READY = "NOT_READY"
    TIMED_OUT = "TIMED_OUT"
    BLOCKED = "BLOCKED"


class ReconciliationStatus(str, Enum):
    NOT_ATTEMPTED = "NOT_ATTEMPTED"
    VERIFIED = "VERIFIED"
    UNEXERCISED = "UNEXERCISED"
    FAILED = "FAILED"
    UNSUPPORTED = "UNSUPPORTED"


class CleanupStatus(str, Enum):
    NOT_ATTEMPTED = "NOT_ATTEMPTED"
    COMPLETE = "COMPLETE"
    FAILED = "FAILED"
    NOT_REQUIRED = "NOT_REQUIRED"


@dataclass(frozen=True, slots=True)
class CapabilityRequirement:
    """One manifest-derived requirement, retaining its exact provenance."""

    capability: str
    required: bool = True
    source_resource: str = ""
    source_namespace: str = ""
    source_field: str = ""
    provider_specific: bool = False
    generic_exercise: bool = True
    attributes: Mapping[str, Any] = field(default_factory=dict)

    @property
    def identity(self) -> str:
        source = self.source_resource or self.source_field or "artifact"
        namespace = f"{self.source_namespace}/" if self.source_namespace else ""
        return f"{self.capability}:{namespace}{source}"

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "CapabilityRequirement":
        known = {
            "capability", "required", "source_resource", "source_namespace",
            "source_field", "provider_specific", "generic_exercise",
        }
        return cls(
            capability=str(value.get("capability") or ""),
            required=bool(value.get("required")),
            source_resource=str(value.get("source_resource") or ""),
            source_namespace=str(value.get("source_namespace") or ""),
            source_field=str(value.get("source_field") or ""),
            provider_specific=bool(value.get("provider_specific")),
            generic_exercise=bool(value.get("generic_exercise", not value.get("provider_specific"))),
            attributes={key: item for key, item in value.items() if key not in known and key != "evidence"},
        )


Command = Callable[[Sequence[str], float, str | None, Mapping[str, str] | None], Any]


@dataclass(frozen=True, slots=True)
class ProviderContext:
    """Run-scoped inputs available to a provider without global state."""

    config: Any
    command: Command
    root: Path
    kubeconfig: Path
    namespace: str
    env: Mapping[str, str]
    timeout: float
    started_at: float = field(default_factory=time.monotonic)

    def remaining(self) -> float:
        remaining = self.timeout - (time.monotonic() - self.started_at)
        if remaining <= 0:
            raise TimeoutError("capability provider lifecycle timed out")
        return max(0.1, remaining)


_SENSITIVE_KEYS = {
    "authorization", "client_secret", "data", "password", "private_key",
    "secret_value", "stringdata", "token", "value",
}
_SECRET_TEXT = re.compile(
    r"(?i)\b(password|passwd|token|authorization|client[_-]?secret)\b(\s*[:=]\s*)\S+"
)


def _safe_text(value: Any, limit: int = 1600) -> str:
    text = str(value or "").replace("\x00", "")
    text = _SECRET_TEXT.sub(r"\1\2[REDACTED]", text)
    return text if len(text) <= limit else text[:limit] + "…"


def redact_evidence(value: Any) -> Any:
    """Recursively make provider evidence safe for persistence and API use.

    Kubernetes ``Secret.data`` and generic value/token/password fields are
    always removed.  Resource names and dependency provenance remain usable.
    """

    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key, item in value.items():
            name = str(key)
            normalized = name.casefold().replace("-", "_")
            result[name] = "[REDACTED]" if normalized in _SENSITIVE_KEYS else redact_evidence(item)
        return result
    if isinstance(value, (list, tuple, set)):
        return [redact_evidence(item) for item in value]
    if isinstance(value, str):
        return _safe_text(value)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return _safe_text(value)


@dataclass(slots=True)
class ProviderResult:
    """Evidence for one provider lifecycle; readiness is not verification."""

    spec: ProviderSpec
    bootstrap_status: BootstrapStatus = BootstrapStatus.NOT_ATTEMPTED
    readiness_status: ReadinessStatus = ReadinessStatus.NOT_CHECKED
    reconciliation_status: ReconciliationStatus = ReconciliationStatus.NOT_ATTEMPTED
    cleanup_status: CleanupStatus = CleanupStatus.NOT_ATTEMPTED
    failure_reason: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    duration_ms: int = 0

    @property
    def ready(self) -> bool:
        return (
            self.bootstrap_status is BootstrapStatus.SUCCEEDED
            and self.readiness_status is ReadinessStatus.READY
        )

    @property
    def verified(self) -> bool:
        return self.ready and self.reconciliation_status is ReconciliationStatus.VERIFIED

    def to_evidence(self) -> dict[str, Any]:
        result = self.spec.public_metadata()
        result.update({
            "bootstrap_status": self.bootstrap_status.value,
            "readiness_status": self.readiness_status.value,
            "reconciliation_result": self.reconciliation_status.value,
            "failure_reason": _safe_text(self.failure_reason),
            "evidence": redact_evidence(self.evidence),
            "cleanup_result": self.cleanup_status.value,
            "warnings": [_safe_text(item) for item in self.warnings],
            "duration_ms": max(0, int(self.duration_ms)),
        })
        return result


class CapabilityProvider(Protocol):
    """Lifecycle implemented by each sandbox capability provider."""

    spec: ProviderSpec

    def bootstrap(self, context: ProviderContext) -> ProviderResult | Mapping[str, Any]: ...

    def readiness(self, context: ProviderContext, result: ProviderResult) -> ProviderResult | Mapping[str, Any] | bool | None: ...

    def reconcile(
        self,
        context: ProviderContext,
        requirement: CapabilityRequirement,
        observations: Mapping[str, Any],
        result: ProviderResult,
    ) -> ProviderResult | Mapping[str, Any] | bool | None: ...

    def cleanup(self, context: ProviderContext, result: ProviderResult) -> ProviderResult | Mapping[str, Any] | bool | None: ...


LifecycleHook = Callable[..., ProviderResult | Mapping[str, Any] | bool | None]


@dataclass(slots=True)
class CallableProvider:
    """Small adapter for existing providers and focused provider modules."""

    spec: ProviderSpec
    bootstrap_hook: LifecycleHook
    readiness_hook: LifecycleHook | None = None
    reconcile_hook: LifecycleHook | None = None
    cleanup_hook: LifecycleHook | None = None

    def bootstrap(self, context: ProviderContext) -> ProviderResult | Mapping[str, Any]:
        return self.bootstrap_hook(context)

    def readiness(self, context: ProviderContext, result: ProviderResult) -> ProviderResult | Mapping[str, Any] | bool | None:
        if self.readiness_hook is None:
            return result.ready
        return self.readiness_hook(context, result)

    def reconcile(self, context: ProviderContext, requirement: CapabilityRequirement, observations: Mapping[str, Any], result: ProviderResult) -> ProviderResult | Mapping[str, Any] | bool | None:
        if self.reconcile_hook is None:
            return None
        return self.reconcile_hook(context, requirement, observations, result)

    def cleanup(self, context: ProviderContext, result: ProviderResult) -> ProviderResult | Mapping[str, Any] | bool | None:
        if self.cleanup_hook is None:
            return True
        return self.cleanup_hook(context, result)


@dataclass(frozen=True, slots=True)
class UnresolvedRequirement:
    requirement: CapabilityRequirement
    status: str
    reason: str


@dataclass(frozen=True, slots=True)
class ProviderPlan:
    """Dependency-ordered providers plus requirements CATS cannot emulate."""

    providers: tuple[CapabilityProvider, ...]
    requirements_by_provider: Mapping[str, tuple[CapabilityRequirement, ...]]
    unresolved: tuple[UnresolvedRequirement, ...] = ()

    @property
    def provider_ids(self) -> tuple[str, ...]:
        return tuple(provider.spec.provider_id for provider in self.providers)


class ProviderRegistry:
    """Provider selection and deterministic dependency ordering."""

    def __init__(self, providers: Sequence[CapabilityProvider] = ()) -> None:
        self._providers: dict[str, CapabilityProvider] = {}
        for provider in providers:
            self.register(provider)

    def register(self, provider: CapabilityProvider) -> None:
        provider_id = provider.spec.provider_id
        if provider_id in self._providers:
            raise ValueError(f"duplicate capability provider: {provider_id}")
        self._providers[provider_id] = provider

    def get(self, provider_id: str) -> CapabilityProvider:
        try:
            return self._providers[provider_id]
        except KeyError as exc:
            raise KeyError(f"capability provider is not registered: {provider_id}") from exc

    def plan(self, requirements: Sequence[CapabilityRequirement | Mapping[str, Any]]) -> ProviderPlan:
        converted = tuple(
            item if isinstance(item, CapabilityRequirement) else CapabilityRequirement.from_mapping(item)
            for item in requirements
        )
        assignments: dict[str, list[CapabilityRequirement]] = {}
        selected: set[str] = set()
        unresolved: list[UnresolvedRequirement] = []

        for requirement in converted:
            if not requirement.required:
                continue
            if requirement.provider_specific or not requirement.generic_exercise:
                unresolved.append(UnresolvedRequirement(
                    requirement, "UNSUPPORTED",
                    "The requirement is provider-specific and is not substituted in the local sandbox.",
                ))
                continue
            candidates = sorted(
                (provider for provider in self._providers.values() if provider.spec.capability.casefold() == requirement.capability.casefold()),
                key=lambda provider: (provider.spec.priority, provider.spec.provider_id),
            )
            if not candidates:
                unresolved.append(UnresolvedRequirement(
                    requirement, "UNAVAILABLE",
                    "No registered offline provider can satisfy this requirement.",
                ))
                continue
            provider = candidates[0]
            selected.add(provider.spec.provider_id)
            assignments.setdefault(provider.spec.provider_id, []).append(requirement)

        def include_dependencies(provider_id: str, trail: tuple[str, ...] = ()) -> None:
            if provider_id in trail:
                cycle = " -> ".join((*trail, provider_id))
                raise ValueError(f"capability provider dependency cycle: {cycle}")
            provider = self.get(provider_id)
            for dependency in provider.spec.dependencies:
                self.get(dependency)
                selected.add(dependency)
                include_dependencies(dependency, (*trail, provider_id))

        for provider_id in tuple(selected):
            include_dependencies(provider_id)

        ordered: list[CapabilityProvider] = []
        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(provider_id: str) -> None:
            if provider_id in visited:
                return
            if provider_id in visiting:
                raise ValueError(f"capability provider dependency cycle includes {provider_id}")
            visiting.add(provider_id)
            provider = self.get(provider_id)
            for dependency in provider.spec.dependencies:
                if dependency in selected:
                    visit(dependency)
            visiting.remove(provider_id)
            visited.add(provider_id)
            ordered.append(provider)

        for provider_id in sorted(selected):
            visit(provider_id)

        return ProviderPlan(
            providers=tuple(ordered),
            requirements_by_provider={key: tuple(value) for key, value in assignments.items()},
            unresolved=tuple(unresolved),
        )


def _coerce_result(spec: ProviderSpec, value: ProviderResult | Mapping[str, Any] | bool | None) -> ProviderResult:
    if isinstance(value, ProviderResult):
        if value.spec.provider_id != spec.provider_id:
            raise ValueError("provider returned evidence for a different provider")
        return value
    result = ProviderResult(spec=spec)
    if isinstance(value, Mapping):
        status = str(value.get("status") or "").upper()
        ready = bool(value.get("controller_ready") or value.get("ready"))
        result.bootstrap_status = BootstrapStatus.SUCCEEDED if status in {"AVAILABLE", "PROVISIONED", "READY", "SUCCEEDED"} or ready else BootstrapStatus.FAILED
        result.readiness_status = ReadinessStatus.READY if ready else ReadinessStatus.NOT_CHECKED
        result.failure_reason = _safe_text(value.get("failure_reason") or value.get("reason") or "")
        result.warnings = [_safe_text(item) for item in value.get("warnings", [])]
        result.duration_ms = int(value.get("duration_ms") or 0)
        result.evidence = dict(value)
        return result
    if value is True:
        result.bootstrap_status = BootstrapStatus.SUCCEEDED
        result.readiness_status = ReadinessStatus.READY
    elif value is False:
        result.bootstrap_status = BootstrapStatus.FAILED
        result.readiness_status = ReadinessStatus.NOT_READY
    return result


class ProviderManager:
    """Execute planned provider lifecycles without conflating their outcomes."""

    def bootstrap(self, plan: ProviderPlan, context: ProviderContext) -> dict[str, ProviderResult]:
        results: dict[str, ProviderResult] = {}
        for provider in plan.providers:
            spec = provider.spec
            blocked_by = [dependency for dependency in spec.dependencies if not results.get(dependency) or not results[dependency].ready]
            if blocked_by:
                results[spec.provider_id] = ProviderResult(
                    spec=spec,
                    bootstrap_status=BootstrapStatus.BLOCKED,
                    readiness_status=ReadinessStatus.BLOCKED,
                    failure_reason=f"Provider dependency was not ready: {', '.join(blocked_by)}",
                )
                continue
            started = time.monotonic()
            try:
                result = _coerce_result(spec, provider.bootstrap(context))
                if result.bootstrap_status is BootstrapStatus.SUCCEEDED and result.readiness_status is not ReadinessStatus.READY:
                    readiness = provider.readiness(context, result)
                    if isinstance(readiness, ProviderResult):
                        result = _coerce_result(spec, readiness)
                    elif isinstance(readiness, Mapping):
                        result.evidence.setdefault("readiness", {}).update(redact_evidence(readiness))
                        ready = bool(readiness.get("ready") or readiness.get("controller_ready"))
                        result.readiness_status = ReadinessStatus.READY if ready else ReadinessStatus.NOT_READY
                    elif readiness is True:
                        result.readiness_status = ReadinessStatus.READY
                    elif readiness is False:
                        result.readiness_status = ReadinessStatus.NOT_READY
                results[spec.provider_id] = result
            except TimeoutError as exc:
                results[spec.provider_id] = ProviderResult(
                    spec=spec,
                    bootstrap_status=BootstrapStatus.FAILED,
                    readiness_status=ReadinessStatus.TIMED_OUT,
                    failure_reason=_safe_text(exc),
                )
            except Exception as exc:  # Providers are best-effort validation infrastructure.
                results[spec.provider_id] = ProviderResult(
                    spec=spec,
                    bootstrap_status=BootstrapStatus.FAILED,
                    readiness_status=ReadinessStatus.NOT_READY,
                    failure_reason=_safe_text(exc),
                )
            results[spec.provider_id].duration_ms = max(
                results[spec.provider_id].duration_ms,
                max(1, round((time.monotonic() - started) * 1000)),
            )
        return results

    def reconcile(
        self,
        provider: CapabilityProvider,
        context: ProviderContext,
        requirement: CapabilityRequirement,
        observations: Mapping[str, Any],
        result: ProviderResult,
    ) -> ProviderResult:
        if not result.ready:
            result.reconciliation_status = ReconciliationStatus.NOT_ATTEMPTED
            return result
        try:
            evidence = provider.reconcile(context, requirement, observations, result)
            if isinstance(evidence, ProviderResult):
                return _coerce_result(provider.spec, evidence)
            if isinstance(evidence, Mapping):
                result.evidence.setdefault("reconciliation", {}).update(redact_evidence(evidence))
                status = str(evidence.get("status") or evidence.get("reconciliation_result") or "").upper()
                result.reconciliation_status = ReconciliationStatus(status) if status in ReconciliationStatus._value2member_map_ else ReconciliationStatus.UNEXERCISED
            elif evidence is True:
                result.reconciliation_status = ReconciliationStatus.VERIFIED
            elif evidence is False:
                result.reconciliation_status = ReconciliationStatus.FAILED
            else:
                result.reconciliation_status = ReconciliationStatus.UNEXERCISED
        except Exception as exc:
            result.reconciliation_status = ReconciliationStatus.FAILED
            result.failure_reason = _safe_text(exc)
        return result

    def cleanup(self, plan: ProviderPlan, context: ProviderContext, results: Mapping[str, ProviderResult]) -> dict[str, ProviderResult]:
        mutable = dict(results)
        for provider in reversed(plan.providers):
            result = mutable.get(provider.spec.provider_id)
            if result is None or result.bootstrap_status in {BootstrapStatus.NOT_ATTEMPTED, BootstrapStatus.BLOCKED}:
                if result is not None:
                    result.cleanup_status = CleanupStatus.NOT_REQUIRED
                continue
            try:
                cleanup = provider.cleanup(context, result)
                if isinstance(cleanup, ProviderResult):
                    result = _coerce_result(provider.spec, cleanup)
                    mutable[provider.spec.provider_id] = result
                elif isinstance(cleanup, Mapping):
                    result.evidence.setdefault("cleanup", {}).update(redact_evidence(cleanup))
                    status = str(cleanup.get("status") or "").upper()
                    result.cleanup_status = CleanupStatus.COMPLETE if status in {"COMPLETE", "SUCCEEDED", "PASS"} else CleanupStatus.FAILED
                else:
                    result.cleanup_status = CleanupStatus.COMPLETE if cleanup is not False else CleanupStatus.FAILED
            except Exception as exc:
                result.cleanup_status = CleanupStatus.FAILED
                result.warnings.append(f"Provider cleanup failed: {_safe_text(exc)}")
        return mutable
