from dataclasses import dataclass


@dataclass(frozen=True)
class Descriptor:
    """Descriptor for file - optimize memory consumption

    Args:
        path: file path
        extension: file extension
        info: info for deep scan
    """
    path: str
    extension: str
    info: str
