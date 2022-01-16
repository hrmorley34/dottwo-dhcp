from __future__ import annotations

__all__ = [
    "IPv4Address",
    "IPv6Address",
    "MACAddress",
    "Device",
]

from ipaddress import IPv4Address, IPv6Address
from typing import Iterable, NamedTuple

from .utils import Fielded, arrint, optional_cast


class MACAddress:
    __slots__ = ["_mac", "__weakref__"]

    _mac: int

    def __init__(self, mac: str | MACAddress) -> None:
        parts = str(mac).replace("-", ":").split(":")
        assert len(parts) == 6
        self._mac = int.from_bytes(arrint(parts, 16), "big")

    def __repr__(self) -> str:
        return type(self).__name__ + f'("{self!s}")'

    def __str__(self) -> str:
        return ":".join(f"{c:02x}" for c in self.packed)

    def __hash__(self) -> int:
        return self._mac

    def __int__(self) -> int:
        return self._mac

    def __eq__(self, obj: object) -> bool:
        if isinstance(obj, MACAddress):
            return obj._mac == self._mac
        return NotImplemented

    @property
    def packed(self) -> bytes:
        # like in ipaddress
        return self._mac.to_bytes(6, "big")


class Device(Fielded):
    _fields = ["human_name", "name", "mac", "ip", "ipv6", "deny"]

    human_name: str
    name: str
    mac: MACAddress | None
    ip: IPv4Address | None
    ipv6: IPv6Address | None
    deny: bool

    def __init__(
        self,
        human_name: str,
        name: str,
        mac: MACAddress | str | None,
        ip: IPv4Address | str | None,
        ipv6: IPv6Address | str | None,
        deny: bool,
    ) -> None:
        self.human_name = human_name
        self.name = name
        self.mac = optional_cast(mac, MACAddress)
        self.ip = optional_cast(ip, IPv4Address)
        self.ipv6 = optional_cast(ipv6, IPv6Address)
        self.deny = deny


class StrRange(NamedTuple):
    min: str | None
    max: str | None


class Range(Fielded, fields=["range", "rangev6"]):
    range: StrRange
    rangev6: StrRange

    def __init__(
        self,
        range: tuple[int | str | None, int | str | None] | StrRange,
        rangev6: tuple[str | None, str | None] | StrRange,
    ) -> None:
        # self.range = IntRange(
        #     optional_cast(range[0], int), optional_cast(range[1], int)
        # )
        self.range = StrRange(
            optional_cast(range[0], str), optional_cast(range[1], str)
        )
        self.rangev6 = StrRange(*rangev6)


class Group(Range, fields=["devices"]):
    devices: list[Device]

    def __init__(
        self,
        range: tuple[int | str | None, int | str | None] | StrRange,
        rangev6: tuple[str | None, str | None] | StrRange,
        devices: Iterable[Device] | None = None,
    ) -> None:
        super().__init__(range, rangev6)
        if devices is None:
            self.devices = []
        else:
            self.devices = list(devices)
