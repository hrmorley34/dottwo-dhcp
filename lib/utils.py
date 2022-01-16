from __future__ import annotations

from typing import Any, Callable, ClassVar, Iterable, TypeVar


T = TypeVar("T")
InT = TypeVar("InT")
OutT = TypeVar("OutT")


def arrint(it: Iterable[str | bytes | bytearray], base: int = 10) -> Iterable[int]:
    return (int(element, base) for element in it)


def optional_cast(obj: InT | None, cast: Callable[[InT], OutT]) -> OutT | None:
    "Cast `Optional[InT]` to `Optional[OutT]`, by casting `None` directly to `None`"
    if obj is None:
        return None
    return cast(obj)


def deduplicate(it: Iterable[T]) -> Iterable[T]:
    seen: set[T] = set()
    for v in it:
        if v in seen:
            continue
        seen.add(v)
        yield v


class FieldedMeta(type):
    def __new__(
        cls: type[T],
        name: str,
        bases: tuple[type, ...],
        namespace: dict[str, Any],
        fields: Iterable[str] | None = None,
        **kwds: Any
    ) -> T:
        if "_fields" in namespace:
            full_fields: list[str] = namespace["_fields"]
        else:
            full_fields = []
            for base in bases:
                full_fields += list(getattr(base, "_fields", ()))
            if fields is not None:
                full_fields += list(fields)

            full_fields = list(deduplicate(full_fields))
            namespace["_fields"] = full_fields

        if "__slots__" not in namespace:
            parentslots: set[str] = set()
            for base in bases:
                parentslots |= set(getattr(base, "__slots__", ()))
            namespace["__slots__"] = [
                field for field in full_fields if field not in parentslots
            ]

        return type.__new__(cls, name, bases, namespace, **kwds)


class Fielded(metaclass=FieldedMeta):
    _fields: ClassVar[list[str]] = []
    __slots__ = ["__weakref__"]

    def __repr__(self) -> str:
        return (
            type(self).__name__
            + "("
            + ", ".join(
                str(field) + "=" + repr(getattr(self, field)) for field in self._fields
            )
            + ")"
        )

    def to_dict(self) -> dict[str, Any]:
        return {k: getattr(self, k) for k in self._fields}
