"""Typed, serialization-friendly NetMap inventory records."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class HostAsset:
    host_id: str
    scan_id: str
    scan_time: str
    ip_address: str
    address_type: str
    addresses: str
    host_status: str
    reason: str
    hostname: str

    def to_record(self) -> dict[str, str]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class ServiceObservation:
    service_id: str
    scan_id: str
    scan_time: str
    ip_address: str
    addresses: str
    host_status: str
    port: str
    protocol: str
    state: str
    service: str
    service_identification: str
    product: str
    version: str
    service_method: str
    service_confidence: str
    reason: str

    def to_record(self) -> dict[str, str]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class ScanInventory:
    scan_id: str
    scan_time: str
    rows: list[dict[str, str]]
    hosts: list[dict[str, str]]
    source: str
    source_kind: str
    scanner: str
    coverage: dict[str, list[int]]
    coverage_known: bool
    complete: bool | None

    def to_record(self) -> dict[str, Any]:
        return asdict(self)
