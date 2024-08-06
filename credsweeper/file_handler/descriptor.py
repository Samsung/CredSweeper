from dataclasses import dataclass


@dataclass(frozen=True)
class Descriptor:
    """Descriptor for file - optimize memory consumption"""
    path: str
    extension: str
    info: str
