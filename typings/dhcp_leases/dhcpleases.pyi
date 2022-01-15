from __future__ import annotations

from datetime import datetime
from pathlib import Path
from re import Pattern
from typing import Any

_Filename = str | bytes | Path[str] | Path[bytes]

def check_datetime(dt: datetime | None) -> None: ...
def parse_time(s: str) -> datetime: ...
def _extract_prop_option(line: str) -> tuple[str, str]: ...
def _extract_prop_set(line: str) -> tuple[str, str]: ...
def _extract_prop_general(line: str) -> tuple[str, str]: ...
def _extract_properties(
    config: str,
) -> tuple[dict[str, str], dict[str, str], dict[str, str]]: ...

class DhcpLeases(object):
    """
    Class to parse isc-dhcp-server lease files into lease objects
    """

    regex_leaseblock: Pattern[str]
    regex_leaseblock6: Pattern[str]
    regex_iaaddr: Pattern[str]

    filename: _Filename
    gzip: bool
    now: datetime | None
    def __init__(
        self, filename: _Filename, gzip: bool = ..., now: datetime | None = ...
    ) -> None: ...
    def get(self, include_backups: bool = ...) -> list[Lease | Lease6]: ...
    def get_current(self) -> dict[str, Lease | Lease6]: ...

class BaseLease(object):
    """
    Base Implementation for all leases. This does most of the common work that is shared among v4 and v6 leases.

    Attributes:
        ip          The IP address assigned by this lease as string
        data        Dict of all the info in the dhcpd.leases file for this lease
        options     Options on this lease
        sets        Dict of key-value set statement values from this lease
    """

    ip: str
    data: dict[str, str]
    options: dict[str, str]
    sets: dict[str, str]
    binding_state: str  # Literal["active", ...]
    _now: datetime | None
    def __init__(
        self,
        ip: str,
        properties: dict[str, str],
        options: dict[str, str] | None = ...,
        sets: dict[str, str] | None = ...,
        now: datetime | None = ...,
    ) -> None: ...
    @property
    def active(self) -> bool: ...
    @property
    def now(self) -> datetime: ...

class Lease(BaseLease):
    """
    Representation of a IPv4 dhcp lease

    Attributes:
        ip              The IPv4 address assigned by this lease as string
        hardware        The OSI physical layer used to request the lease (usually ethernet)
        ethernet        The ethernet address of this lease (MAC address)
        start           The start time of this lease as DateTime object
        end             The time this lease expires as DateTime object or None if this is an infinite lease
        hostname        The hostname for this lease if given by the client
        binding_state   The binding state as string ('active', 'free', 'abandoned', 'backup')
        data            Dict of all the info in the dhcpd.leases file for this lease
    """

    start: datetime | None
    end: datetime | None
    _hardware: list[str]
    ethernet: str | None
    hardware: str | None
    hostname: str
    def __init__(self, ip: str, properties: dict[str, str], **kwargs: Any) -> None: ...
    @property
    def valid(self) -> bool: ...

class Lease6(BaseLease):
    """
    Representation of a IPv6 dhcp lease

    Attributes:
        ip                 The IPv6 address assigned by this lease as string
        type               If this is a temporary or permanent address
        host_identifier    The unique host identifier (replaces mac addresses in IPv6)
        duid               The DHCP Unique Identifier (DUID) of the host
        iaid               The Interface Association Identifier (IAID) of the host
        last_communication The last communication time with the host
        end                The time this lease expires as DateTime object or None if this is an infinite lease
        binding_state      The binding state as string ('active', 'free', 'abandoned', 'backup')
        preferred_life     The preferred lifetime in seconds
        max_life           The valid lifetime for this address in seconds
        data               Dict of all the info in the dhcpd.leases file for this lease
    """

    (TEMPORARY, NON_TEMPORARY, PREFIX_DELEGATION) = ("ta", "na", "pd")

    type: str
    last_communication: datetime
    host_identifier: bytes
    iaid: int
    duid: bytes
    end: datetime | None
    preferred_life: int
    max_life: int
    def __init__(
        self,
        ip: str,
        properties: dict[str, str],
        cltt: datetime,
        host_identifier: str,
        address_type: str,
        **kwargs: Any
    ) -> None: ...
    @property
    def host_identifier_string(self) -> str: ...
    @property
    def valid(self) -> bool: ...
    def _iaid_duid_to_bytes(self, input_string: str | bytes) -> bytes: ...
