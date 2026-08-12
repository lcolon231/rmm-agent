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

#: Bounds on the Windows Update section (issue #51). As with software, the byte
#: budget is the binding constraint at full field lengths; these counts stop a
#: pathological endpoint from enumerating an unbounded update backlog.
MAX_MISSING_UPDATES = 512
MAX_INSTALLED_UPDATES = 1024

ShortText = Annotated[str, StringConstraints(max_length=255)]
Identifier = Annotated[str, StringConstraints(max_length=128)]
#: Free prose supplied by the operating system rather than by NodeLink, where
#: 255 characters is simply the wrong bound: Windows Update's own stock history
#: description is 262 characters, so a ShortText field silently made every real
#: endpoint's update scan unstorable. Still bounded — the per-section byte
#: budget remains the binding constraint — just bounded at prose scale.
ProseText = Annotated[str, StringConstraints(max_length=2048)]


class InventorySection(str, Enum):
    """Section names. Later inventory issues add members here, not schemas."""

    system = "system"
    cpu = "cpu"
    memory = "memory"
    storage = "storage"
    network = "network"
    installed_software = "installed_software"
    security_defender = "security_defender"
    # Platform security is three sections rather than one so a single
    # permission failure cannot void the rest: BitLocker's cmdlets need
    # elevation, while Secure Boot and TPM generally do not.
    security_bitlocker = "security_bitlocker"
    security_secure_boot = "security_secure_boot"
    security_tpm = "security_tpm"
    #: Local Administrators group membership (issue #39). Who holds local
    #: administrative rights on the endpoint, resolved by the built-in group's
    #: well-known SID so the reading is identical on non-English Windows.
    local_administrators = "local_administrators"
    #: Windows Update scan result (issue #51): missing/applicable and installed
    #: updates. Populated on demand by the scan_updates typed command, not on the
    #: heartbeat inventory path, because a live scan takes far longer than the
    #: per-section heartbeat budget.
    windows_updates = "windows_updates"
    #: Package-manager discovery (issue #55): installed packages and available
    #: upgrades from winget (or the opt-in chocolatey provider). Populated on
    #: demand by the scan_packages typed command, not on the heartbeat path.
    installed_packages = "installed_packages"


class InventorySectionStatus(str, Enum):
    """Why a section looks the way it does.

    ``ok``                collected completely.
    ``partial``           collected, but bounded away — some rows are missing.
    ``unavailable``       the platform supports this but collection failed.
    ``unsupported``       the platform cannot report it at all.
    ``permission_denied`` the platform supports it and it exists, but the agent
                          lacks the rights to read it.

    ``permission_denied`` is separated from ``unavailable`` because the two
    call for different responses. An unavailable section is a transient fault
    to retry; a denied one is a fixable deployment problem — the agent is not
    running with the privileges its collectors need — and would otherwise hide
    inside generic failures forever. BitLocker is the first collector that can
    hit it, since its cmdlets require elevation.
    """

    ok = "ok"
    partial = "partial"
    unavailable = "unavailable"
    unsupported = "unsupported"
    permission_denied = "permission_denied"


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


#: Cap on named third-party antivirus products. Security Center registers few,
#: but the list is endpoint-controlled and so is bounded like everything else.
MAX_THIRD_PARTY_PRODUCTS = 16


class DefenderProviderState(str, Enum):
    """What role Defender is actually playing on the endpoint.

    This is deliberately a *field* rather than a section status, because the
    distinction a technician needs cannot be carried by ``ok``/``unavailable``.
    A machine running a third-party antivirus with Defender stood down is
    healthy and correctly configured; a machine where Defender is simply off is
    not. Collapsing both into "Defender disabled" would generate false alarms
    on every endpoint with a competing product installed — and, worse, would
    hide the genuinely unprotected ones in that noise.
    """

    #: Defender is the primary antivirus and running normally.
    active = "active"
    #: Defender is present but stood down (passive, SxS passive, or EDR block),
    #: normally because another product is primary.
    passive = "passive"
    #: A non-Defender product is the registered antivirus provider.
    third_party = "third_party"
    #: Defender is the provider but is switched off. This is the alarming one.
    disabled = "disabled"
    #: Defender responded but its role could not be determined.
    unknown = "unknown"


class DefenderInventory(BaseModel):
    model_config = ConfigDict(extra="forbid")

    provider_state: DefenderProviderState = DefenderProviderState.unknown
    antivirus_enabled: bool | None = None
    realtime_protection_enabled: bool | None = None
    tamper_protection_enabled: bool | None = None

    antivirus_signature_version: ShortText | None = None
    antivirus_signature_updated_at: datetime | None = None
    #: Signature age at the moment of collection, in hours.
    #:
    #: Stored alongside the timestamp rather than derived from it on read, for
    #: two reasons. It is the value a technician actually judges staleness on,
    #: and it is computed entirely on the endpoint — so an endpoint whose clock
    #: is wrong reports a misleading ``updated_at`` but a still-correct age,
    #: because the skew cancels in the subtraction.
    antivirus_signature_age_hours: int | None = Field(default=None, ge=0)

    engine_version: ShortText | None = None
    product_version: ShortText | None = None
    last_quick_scan_at: datetime | None = None
    last_full_scan_at: datetime | None = None

    #: Products registered with Security Center, when it is queryable. Server
    #: SKUs have no Security Center, which is reported as an empty list rather
    #: than as evidence that no antivirus exists.
    third_party_products: list[ShortText] = Field(
        default_factory=list, max_length=MAX_THIRD_PARTY_PRODUCTS
    )


class BitLockerProtectionStatus(str, Enum):
    """Whether protection is on for a volume, as BitLocker reports it."""

    on = "on"
    off = "off"
    unknown = "unknown"


class BitLockerVolume(BaseModel):
    """One volume's BitLocker state.

    There is deliberately **no field capable of holding a recovery key**, and
    ``extra="forbid"`` means an agent that tried to send one is rejected rather
    than having it quietly dropped. Recovery keys are the one piece of data
    whose disclosure defeats the control entirely; the safest schema is one
    with nowhere to put them. Key-protector *types* would be reportable, but
    are omitted here because they are not needed to answer "is this volume
    encrypted" and every additional field is another chance to leak.
    """

    model_config = ConfigDict(extra="forbid")

    mount_point: ShortText | None = None
    protection_status: BitLockerProtectionStatus = BitLockerProtectionStatus.unknown
    #: BitLocker's own volume state, e.g. FullyEncrypted, EncryptionInProgress.
    volume_status: ShortText | None = None
    encryption_method: ShortText | None = None
    encryption_percentage: int | None = Field(default=None, ge=0, le=100)
    is_system_volume: bool | None = None


class BitLockerInventory(BaseModel):
    model_config = ConfigDict(extra="forbid")
    volumes: list[BitLockerVolume] = Field(default_factory=list, max_length=MAX_VOLUMES)


class FirmwareType(str, Enum):
    uefi = "uefi"
    bios = "bios"
    unknown = "unknown"


class SecureBootInventory(BaseModel):
    """Secure Boot state.

    ``enabled`` is only meaningful under UEFI. A legacy-BIOS machine cannot
    have Secure Boot at all, and reporting it as "disabled" would describe a
    machine that is behaving correctly for its firmware as though it had been
    switched off — the same false-alarm shape as reading passive Defender as
    disabled. That case is reported as an unsupported section instead.
    """

    model_config = ConfigDict(extra="forbid")
    enabled: bool | None = None
    firmware_type: FirmwareType = FirmwareType.unknown


class TpmInventory(BaseModel):
    """TPM presence and readiness.

    ``present=False`` is a real, useful answer — it is the reason a machine
    cannot enable BitLocker with a TPM protector — and is distinct from a
    section that could not be read at all.
    """

    model_config = ConfigDict(extra="forbid")
    present: bool | None = None
    enabled: bool | None = None
    activated: bool | None = None
    #: True only when the TPM is present, enabled, activated, and owned.
    ready: bool | None = None
    spec_version: ShortText | None = None
    manufacturer: ShortText | None = None


#: Cap on reported Administrators members. A correctly managed group is small;
#: a machine reporting more than this is either misconfigured or hostile input,
#: and the excess is reported ``partial`` rather than stored unbounded.
MAX_LOCAL_ADMIN_MEMBERS = 256

#: Windows SID strings are at most SECURITY_MAX_SID_STRING_CHARACTERS long.
Sid = Annotated[str, StringConstraints(max_length=184)]


class LocalAdminIdentityType(str, Enum):
    """Where an Administrators member's identity originates.

    Reported by the endpoint from the principal's source. ``unknown`` is used
    when the platform returns a principal whose origin cannot be classified,
    rather than guessing a trust origin the operator would rely on.
    """

    #: A local account or the built-in Administrator.
    local = "local"
    #: An Active Directory domain principal.
    domain = "domain"
    #: An Entra ID (Azure AD) principal.
    azuread = "azuread"
    unknown = "unknown"


class LocalAdminPrincipalClass(str, Enum):
    """Whether an Administrators member is a single account or a nested group."""

    user = "user"
    group = "group"
    unknown = "unknown"


class LocalAdminMember(BaseModel):
    """One principal holding local administrative rights.

    ``name`` is the only field a member cannot be reported without. ``sid`` is
    present when the endpoint resolved it; a member is never expanded beyond
    this shape, so a nested group is reported as one ``group`` member rather
    than having its own membership pulled in.
    """

    model_config = ConfigDict(extra="forbid")
    name: ShortText
    sid: Sid | None = None
    identity_type: LocalAdminIdentityType = LocalAdminIdentityType.unknown
    principal_class: LocalAdminPrincipalClass = LocalAdminPrincipalClass.unknown


class LocalAdministratorsInventory(BaseModel):
    """Members of the built-in Administrators group.

    The group is resolved on the endpoint by its well-known SID (S-1-5-32-544),
    not the localized display name, so the section behaves identically on
    non-English Windows. An unreachable directory or unsupported OS is carried
    by the section *status*, not by an empty ``members`` list that would read as
    "no administrators".
    """

    model_config = ConfigDict(extra="forbid")
    members: list[LocalAdminMember] = Field(
        default_factory=list, max_length=MAX_LOCAL_ADMIN_MEMBERS
    )


class MissingUpdate(BaseModel):
    """One applicable-but-not-installed update the scan found (issue #51).

    ``title`` is the only field a row cannot be reported without; everything
    else is ``None`` when Windows Update did not supply it, never guessed.
    """

    model_config = ConfigDict(extra="forbid")
    title: ProseText
    #: e.g. "KB5034123"; some updates (drivers, definition updates) have none.
    kb_id: Identifier | None = None
    #: Windows Update's UpdateID GUID, for correlating across snapshots.
    update_id: Identifier | None = None
    #: Update category / classification, e.g. "Security Updates".
    classification: ShortText | None = None
    #: Category product/title, e.g. "Windows 11".
    product: ShortText | None = None
    #: MSRC severity, e.g. "Critical" / "Important"; unset when not rated.
    severity: ShortText | None = None
    reboot_required: bool | None = None
    is_downloaded: bool | None = None
    support_url: ShortText | None = None
    last_deployment_change: datetime | None = None
    #: Computed priority grade, e.g. "P1 - Critical", "P2 - High", "P3 - Medium", "P4 - Low".
    priority_grade: ShortText | None = None


class InstalledUpdate(BaseModel):
    """One update already installed on the endpoint (issue #51)."""

    model_config = ConfigDict(extra="forbid")
    #: KB identifier (Get-Hotfix HotFixID) or the update's KB, when known.
    kb_id: Identifier | None = None
    #: Windows Update identity; present even for drivers and firmware without KBs.
    update_id: Identifier | None = None
    revision_number: int | None = Field(default=None, ge=0)
    title: ProseText | None = None
    description: ProseText | None = None
    installed_on: datetime | None = None
    installed_by: ShortText | None = None
    #: Windows Update history client-application id, when sourced from history.
    client_application_id: ShortText | None = None
    support_url: ShortText | None = None
    #: Windows Update Agent operation result (2=success, 3=success with errors).
    result_code: int | None = Field(default=None, ge=0, le=5)
    hresult: Identifier | None = None


class WindowsUpdatesInventory(BaseModel):
    """Normalized Windows Update scan result (issue #51).

    Populated on demand by the ``scan_updates`` typed command, not on the
    heartbeat inventory path. ``missing`` and ``installed`` are bounded lists;
    an empty ``missing`` with ``status == ok`` means "fully patched", which a
    non-``ok`` section status must not be confused with.
    """

    model_config = ConfigDict(extra="forbid")
    #: When the endpoint completed the scan.
    scanned_at: datetime | None = None
    #: System-level pending-reboot state independent of any single update.
    reboot_required: bool | None = None
    #: Where the data came from, e.g. "windows_update_agent".
    source: ShortText | None = None
    #: Non-secret scan error string/HRESULT when the scan itself failed.
    error_code: ShortText | None = None
    #: Separate history failure so a valid missing-update scan remains usable.
    history_error_code: ShortText | None = None
    missing: list[MissingUpdate] = Field(
        default_factory=list, max_length=MAX_MISSING_UPDATES
    )
    installed: list[InstalledUpdate] = Field(
        default_factory=list, max_length=MAX_INSTALLED_UPDATES
    )


#: Bounds on discovered packages. Endpoints can install a lot of software, so
#: the installed list is generous; upgrades are usually far fewer.
MAX_INSTALLED_PACKAGES = 2048
MAX_UPGRADABLE_PACKAGES = 1024


class InstalledPackage(BaseModel):
    """One package reported as installed by a provider (issue #55)."""

    model_config = ConfigDict(extra="forbid")
    package_id: Identifier
    name: ShortText | None = None
    version: ShortText | None = None
    #: Provider/source, e.g. "winget", "msstore", or "chocolatey".
    source: ShortText | None = None


class UpgradablePackage(BaseModel):
    """One installed package with an available upgrade (issue #55)."""

    model_config = ConfigDict(extra="forbid")
    package_id: Identifier
    name: ShortText | None = None
    current_version: ShortText | None = None
    available_version: ShortText | None = None
    source: ShortText | None = None


class InstalledPackagesInventory(BaseModel):
    """Normalized package-manager discovery result (issue #55).

    Populated on demand by the ``scan_packages`` typed command. ``source``
    records which provider produced the snapshot; an empty ``upgradable`` with
    ``status == ok`` means "everything installed is current".
    """

    model_config = ConfigDict(extra="forbid")
    scanned_at: datetime | None = None
    #: Provider that produced this snapshot, e.g. "winget" or "chocolatey".
    source: ShortText | None = None
    #: Non-secret discovery error string when the scan itself failed.
    error_code: ShortText | None = None
    installed: list[InstalledPackage] = Field(
        default_factory=list, max_length=MAX_INSTALLED_PACKAGES
    )
    upgradable: list[UpgradablePackage] = Field(
        default_factory=list, max_length=MAX_UPGRADABLE_PACKAGES
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
    InventorySection.security_defender: DefenderInventory,
    InventorySection.security_bitlocker: BitLockerInventory,
    InventorySection.security_secure_boot: SecureBootInventory,
    InventorySection.security_tpm: TpmInventory,
    InventorySection.local_administrators: LocalAdministratorsInventory,
    InventorySection.windows_updates: WindowsUpdatesInventory,
    InventorySection.installed_packages: InstalledPackagesInventory,
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


class InventoryHistoryOut(BaseModel):
    """Snapshots for one section, newest first.

    Rows exist only where content changed, so this is a list of *changes*
    rather than a sample of every collection.
    """

    agent_id: str
    section: InventorySection
    items: list[InventorySectionOut] = Field(default_factory=list)
    page: int = Field(ge=1)
    page_size: int = Field(ge=1, le=100)
    total: int = Field(ge=0)


class InventoryDiffOut(BaseModel):
    """What changed between two snapshots of one section."""

    agent_id: str
    section: InventorySection
    #: False when the endpoint has fewer than two snapshots for this section —
    #: not an error, just nothing to compare yet.
    comparable: bool
    before: InventorySectionOut | None = None
    after: InventorySectionOut | None = None
    diff: dict = Field(default_factory=dict)
    summary: dict = Field(default_factory=dict)
