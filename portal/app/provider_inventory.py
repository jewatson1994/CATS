"""Central inventory for CATS-managed Deployment Validation providers.

This module is deliberately data-only.  Runtime providers consume these
records, while distribution builders are responsible for supplying and
hash-verifying the referenced offline assets.  Keeping the provider identity,
version, images, and dependency declarations here prevents the validation
orchestrator from accumulating provider-specific constants.
"""
from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping


@dataclass(frozen=True, slots=True)
class ProviderImage:
    """One pinned image expected in an offline provider bundle."""

    reference: str
    archive: str
    digest: str | None = None
    platforms: tuple[str, ...] = ("linux/amd64",)

    def __post_init__(self) -> None:
        if not self.reference or not self.archive:
            raise ValueError("provider image reference and archive are required")
        reference = self.reference.casefold()
        if reference.endswith(":latest") or ":latest@" in reference:
            raise ValueError("provider images must not use the mutable latest tag")
        if self.digest is not None:
            algorithm, separator, value = self.digest.partition(":")
            if algorithm != "sha256" or separator != ":" or len(value) != 64 or any(char not in "0123456789abcdef" for char in value.casefold()):
                raise ValueError("provider image digests must be complete sha256 values")


@dataclass(frozen=True, slots=True)
class ProviderManifest:
    """A manifest shipped in the trusted, offline provider bundle."""

    path: str
    sha256: str | None = None

    def __post_init__(self) -> None:
        if not self.path or self.path.startswith(("/", "\\")) or ".." in self.path.replace("\\", "/").split("/"):
            raise ValueError("provider manifest must be a safe relative path")
        if self.sha256 is not None and (len(self.sha256) != 64 or any(char not in "0123456789abcdef" for char in self.sha256.casefold())):
            raise ValueError("provider manifest hashes must be 64 hexadecimal characters")


@dataclass(frozen=True, slots=True)
class ProviderSpec:
    """Stable provider metadata used for selection, evidence, and ordering."""

    provider_id: str
    capability: str
    name: str
    version: str
    verification_method: str
    provisioned_by_cats: bool = True
    dependencies: tuple[str, ...] = ()
    images: tuple[ProviderImage, ...] = ()
    manifests: tuple[ProviderManifest, ...] = ()
    bundle_directory: str | None = None
    priority: int = 100
    offline_capable: bool = True

    def __post_init__(self) -> None:
        if not self.provider_id or not self.capability or not self.name or not self.version:
            raise ValueError("provider id, capability, name, and version are required")
        if self.provider_id in self.dependencies:
            raise ValueError("a provider cannot depend on itself")
        if len(set(self.dependencies)) != len(self.dependencies):
            raise ValueError("provider dependencies must be unique")
        if len({image.reference for image in self.images}) != len(self.images):
            raise ValueError("provider image references must be unique")

    def public_metadata(self) -> dict[str, object]:
        """Return non-secret, persistence-safe identity and asset metadata."""

        return {
            "provider_id": self.provider_id,
            "provider": self.name,
            "capability": self.capability,
            "version": self.version,
            "provisioned_by_cats": self.provisioned_by_cats,
            "verification_method": self.verification_method,
            "dependencies": list(self.dependencies),
            "offline_capable": self.offline_capable,
            "images": [
                {
                    "reference": image.reference,
                    "digest": image.digest,
                    "archive": image.archive,
                    "platforms": list(image.platforms),
                }
                for image in self.images
            ],
            "manifests": [
                {"path": manifest.path, "sha256": manifest.sha256}
                for manifest in self.manifests
            ],
        }


METALLB = ProviderSpec(
    provider_id="metallb",
    capability="LoadBalancer",
    name="MetalLB",
    version="0.16.1",
    verification_method="Service address, provider pool, and owned EndpointSlice reconciliation",
    bundle_directory="/opt/cats/validation/loadbalancer",
    images=(
        ProviderImage(
            reference="quay.io/metallb/controller:v0.16.1",
            digest="sha256:5a3e101335f5ea2cfb0ddf51acdfa9538251e0623ffcd6cbfc1b274b7898790c",
            archive="controller.tar",
        ),
        ProviderImage(
            reference="quay.io/metallb/speaker:v0.16.1",
            digest="sha256:37a98a9d1cd970051c5dededb6f922c1e6c3b90fdd0fc1350d1686e67675af0e",
            archive="speaker.tar",
        ),
    ),
    manifests=(ProviderManifest(path="metallb-native.yaml"),),
    priority=10,
)


INGRESS_NGINX = ProviderSpec(
    provider_id="ingress-nginx",
    capability="Ingress",
    name="ingress-nginx",
    version="1.15.1",
    verification_method="Controller readiness plus Ingress-to-Service-to-ready-endpoint reconciliation",
    dependencies=("metallb",),
    bundle_directory="/opt/cats/validation/ingress",
    images=(
        ProviderImage(
            reference="registry.k8s.io/ingress-nginx/controller:v1.15.1",
            digest="sha256:594ceea76b01c592858f803f9ff4d2cb40542cae2060410b2c95f75907d659e1",
            archive="controller.tar",
        ),
        ProviderImage(
            reference="registry.k8s.io/ingress-nginx/kube-webhook-certgen:v1.6.9",
            digest="sha256:01038e7de14b78d702d2849c3aad72fd25903c4765af63cf16aa3398f5d5f2dd",
            archive="kube-webhook-certgen.tar",
        ),
    ),
    manifests=(ProviderManifest(path="ingress-nginx.yaml"),),
    priority=10,
)


KIND_LOCAL_STORAGE = ProviderSpec(
    provider_id="kind-local-path",
    capability="Storage",
    name="kind local-path storage",
    version="cluster-provided",
    provisioned_by_cats=False,
    verification_method="Default StorageClass discovery and PVC/PV/workload reconciliation",
    priority=50,
)


_PROVIDERS = {
    provider.provider_id: provider
    for provider in (METALLB, INGRESS_NGINX, KIND_LOCAL_STORAGE)
}

PROVIDER_INVENTORY: Mapping[str, ProviderSpec] = MappingProxyType(_PROVIDERS)


def provider_inventory() -> Mapping[str, ProviderSpec]:
    """Return the immutable built-in provider inventory."""

    return PROVIDER_INVENTORY


def provider_spec(provider_id: str) -> ProviderSpec:
    """Resolve a built-in provider by its stable identifier."""

    try:
        return PROVIDER_INVENTORY[provider_id]
    except KeyError as exc:
        raise KeyError(f"unknown validation provider: {provider_id}") from exc


def providers_for(capability: str) -> tuple[ProviderSpec, ...]:
    """Return deterministic provider candidates for a capability."""

    wanted = capability.casefold()
    return tuple(
        sorted(
            (item for item in PROVIDER_INVENTORY.values() if item.capability.casefold() == wanted),
            key=lambda item: (item.priority, item.provider_id),
        )
    )
