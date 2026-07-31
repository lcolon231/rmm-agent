# SPDX-License-Identifier: AGPL-3.0-only
"""Bounded Windows hardware inventory contract (issue #35).

The agent reports a *snapshot per section* rather than one document, so a CIM
failure in one area cannot void the rest, and so later inventory classes
(installed software, Defender, BitLocker, local administrators) become new
section names instead of schema changes.

Two rules run through everything here:

* **Absent is not empty.** A field the endpoint could not report stays ``None``
  and its section carries a non-``ok`` status. Nothing is defaulted to a
  plausible-looking value, because "serial number unknown" and "serial number
  is the empty string" are different facts to a technician.
* **Reject, never truncate.** Bounds are enforced by rejecting the submission.
  The agent is responsible for trimming its own lists and saying so with
  ``partial``; a server that silently dropped rows would store something the
  endpoint never reported.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime
from enum import Enum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator

#: Bump when a section's field set changes in a way consumers must notice.
INVENTORY_SCHEMA_VERSION = 1

#: Per-section cap on the canonical JSON encoding. Mirrors the per-stream
#: command output limit so one endpoint cannot spend more of the server's
#: storage on inventory than it can on captured output.
MAX_INVENTORY_SECTION_BYTES = 256 * 1024

#: Bounds on the repeated structures. A machine with more than this many memory
#: modules, disks, volumes, or adapters reports the excess as ``partial``.
MAX_MEMORY_MODULES = 64
MAX_DISKS = 64
MAX_VOLUMES = 128
MAX_NETWORK_ADAPTERS = 64
MAX_ADDRESSES_PER_ADAPTER = 32

#: Sanity bound on installed-software rows. Unlike the hardware caps, this is
#: *not* the binding constraint: at the 255-character field bounds an entry can
#: reach ~1 KiB, so ``MAX_INVENTORY_SECTION_BYTES`` is reached first. The agent
#: must fit its payload to the byte budget rather than to this count, or a
#: machine with unusually long program names would be rejected on every attempt
#: and would silently never report software at all.
MAX_SOFTWARE_ENTRIES = 1024

ShortText = Annotated[str, StringConstraints(max_length=255)]
Identifier = Annotated[str, StringConstraints(max_length=128)]


class InventorySection(str, Enum):
    """Section names. Later inventory issues add members here, not schemas."""

    system = "system"
    cpu = "cpu"
    memory = "memory"
    storage = "storage"
    network = "network"
    installed_software = "installed_software"


class InventorySectionStatus(str, Enum):
    """Why a section looks the way it does.

    ``ok``          collected completely.
    ``partial``     collected, but bounded away — some rows are missing.
    ``unavailable`` the platform supports this but collection failed.
    ``unsupported`` the platform cannot report it at all.
    """

    ok = "ok"
    partial = "partial"
    unavailable = "unavailable"
    unsupported = "unsupported"


class SystemInventory(BaseModel):
    model_config = ConfigDict(extra="forbid")
    manufacturer: ShortText | None = None
    model: ShortText | None = None
    serial: ShortText | None = None
    chassis: ShortText | None = None
    bios_vendor: ShortText | None = None
    bios_version: ShortText | None = None
    bios_release_date: datetime | None = None


class CpuInventory(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: ShortText | None = None
    architecture: Identifier | None = None
    physical_cores: int | None = Field(default=None, ge=0, le=4096)
    logical_cores: int | None = Field(default=None, ge=0, le=8192)
    max_clock_mhz: int | None = Field(default=None, ge=0, le=100_000)


class MemoryModule(BaseModel):
    model_config = ConfigDict(extra="forbid")
    capacity_bytes: int | None = Field(default=None, ge=0)
    speed_mhz: int | None = Field(default=None, ge=0, le=100_000)
    slot: ShortText | None = None
    manufacturer: ShortText | None = None
    part_number: ShortText | None = None


class MemoryInventory(BaseModel):
    model_config = ConfigDict(extra="forbid")
    total_bytes: int | None = Field(default=None, ge=0)
    modules: list[MemoryModule] = Field(default_factory=list, max_length=MAX_MEMORY_MODULES)


class Disk(BaseModel):
    model_config = ConfigDict(extra="forbid")
    model: ShortText | None = None
    serial: ShortText | None = None
    size_bytes: int | None = Field(default=None, ge=0)
    media_type: ShortText | None = None
    bus_type: ShortText | None = None


class Volume(BaseModel):
    model_config = ConfigDict(extra="forbid")
    mount_point: ShortText | None = None
    label: ShortText | None = None
    filesystem: Identifier | None = None
    size_bytes: int | None = Field(default=None, ge=0)
    free_bytes: int | None = Field(default=None, ge=0)


class StorageInventory(BaseModel):
    model_config = ConfigDict(extra="forbid")
    disks: list[Disk] = Field(default_factory=list, max_length=MAX_DISKS)
    volumes: list[Volume] = Field(default_factory=list, max_length=MAX_VOLUMES)


class NetworkAdapter(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: ShortText | None = None
    mac_address: Annotated[str, StringConstraints(max_length=64)] | None = None
    adapter_type: ShortText | None = None
    speed_bps: int | None = Field(default=None, ge=0)
    dhcp_enabled: bool | None = None
    addresses: list[Annotated[str, StringConstraints(max_length=64)]] = Field(
        default_factory=list, max_length=MAX_ADDRESSES_PER_ADAPTER
    )


class NetworkInventory(BaseModel):
    model_config = ConfigDict(extra="forbid")
    adapters: list[NetworkAdapter] = Field(
        default_factory=list, max_length=MAX_NETWORK_ADAPTERS
    )


class SoftwareArchitecture(str, Enum):
    """Which registry view the program was registered under.

    This is the *registration* architecture, not a claim about the binary — a
    64-bit installer can register a 32-bit program. ``unknown`` covers per-user
    entries, where the view does not imply an architecture.
    """

    x86 = "x86"
    x64 = "x64"
    arm64 = "arm64"
    unknown = "unknown"


class SoftwareScope(str, Enum):
    """Whether the program is registered for the machine or one user."""

    machine = "machine"
    user = "user"


class SoftwareEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")
    #: Display name. The only field an entry cannot be reported without — a row
    #: with no name is a registry artifact, not an installed program.
    name: ShortText
    version: ShortText | None = None
    publisher: ShortText | None = None
    architecture: SoftwareArchitecture = SoftwareArchitecture.unknown
    scope: SoftwareScope = SoftwareScope.machine
    #: Only populated when the registry value parsed cleanly. Windows stores
    #: InstallDate inconsistently (missing, localized, or malformed), so an
    #: unparseable value is omitted rather than guessed at.
    install_date: datetime | None = None
    #: Registry key name or product code, for correlating across snapshots.
    identifier: Identifier | None = None


class InstalledSoftwareInventory(BaseModel):
    model_config = ConfigDict(extra="forbid")
    entries: list[SoftwareEntry] = Field(
        default_factory=list, max_length=MAX_SOFTWARE_ENTRIES
    )


#: Section name -> payload model. The submission validator uses this to pick the
#: right model, so an unknown section is rejected rather than stored unparsed.
SECTION_MODELS: dict[InventorySection, type[BaseModel]] = {
    InventorySection.system: SystemInventory,
    InventorySection.cpu: CpuInventory,
    InventorySection.memory: MemoryInventory,
    InventorySection.storage: StorageInventory,
    InventorySection.network: NetworkInventory,
    InventorySection.installed_software: InstalledSoftwareInventory,
}


def canonical_inventory_bytes(payload: dict) -> bytes:
    """The exact byte sequence that is size-checked, hashed, and stored.

    Sorted keys and tight separators, matching the canonicalization the command
    envelope already uses, so an agent and the server can independently compute
    the same content hash and agree on whether anything changed.
    """
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")


def inventory_content_hash(payload: dict) -> str:
    return hashlib.sha256(canonical_inventory_bytes(payload)).hexdigest()


class InventorySectionIn(BaseModel):
    """One collected section as the agent reports it."""

    model_config = ConfigDict(extra="forbid")

    section: InventorySection
    status: InventorySectionStatus
    collected_at: datetime
    payload: dict = Field(default_factory=dict)

    @field_validator("collected_at")
    @classmethod
    def collected_at_must_include_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("collected_at must include a timezone offset")
        return value

    @field_validator("payload")
    @classmethod
    def payload_must_be_bounded(cls, value: dict) -> dict:
        size = len(canonical_inventory_bytes(value))
        if size > MAX_INVENTORY_SECTION_BYTES:
            raise ValueError(
                f"inventory section exceeds {MAX_INVENTORY_SECTION_BYTES} bytes"
            )
        return value

    def typed_payload(self) -> BaseModel:
        """Parse against this section's model, rejecting unknown fields.

        Called after field validation so the size bound is applied to whatever
        arrived, before the more expensive structural parse.
        """
        return SECTION_MODELS[self.section].model_validate(self.payload)


class InventorySubmission(BaseModel):
    """A full or partial inventory report.

    Sections are independent, so an agent may report only what changed. The
    server stores each section separately and dedupes on content hash.
    """

    model_config = ConfigDict(extra="forbid")

    inventory_schema_version: Literal[1] = INVENTORY_SCHEMA_VERSION
    agent_version: Annotated[str, StringConstraints(max_length=64)] | None = None
    sections: list[InventorySectionIn] = Field(min_length=1, max_length=len(InventorySection))

    @field_validator("sections")
    @classmethod
    def sections_must_be_unique(
        cls, value: list[InventorySectionIn]
    ) -> list[InventorySectionIn]:
        names = [entry.section for entry in value]
        if len(names) != len(set(names)):
            raise ValueError("each inventory section may appear at most once")
        return value


class InventorySectionOut(BaseModel):
    """One stored section, newest first in operator views."""

    model_config = ConfigDict(from_attributes=True)
    id: str
    agent_id: str
    section: InventorySection
    status: InventorySectionStatus
    schema_version: int
    content_hash: str
    byte_size: int
    payload: dict
    collected_at: datetime
    received_at: datetime


class InventoryOut(BaseModel):
    """The current inventory for one agent: at most one row per section."""

    agent_id: str
    sections: list[InventorySectionOut] = Field(default_factory=list)
    #: Sections this build knows about that the endpoint has never reported.
    missing_sections: list[InventorySection] = Field(default_factory=list)
