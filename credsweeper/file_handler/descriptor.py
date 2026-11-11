from dataclasses import dataclass


@dataclass(frozen=True)
class Descriptor:
    """Metadata describing a file and its content for scanning.

    This dataclass groups metadata into a single object for convenient
    passing between components. It does not implement processing logic.

    Attributes:
        path: Path to the file being scanned.
        extension: File extension used for ML processing. It may differ
            from the extension of the file being scanned when the content
            originates from a nested file, such as a file inside an archive.
        info: Information describing how the content was obtained during
            deep scanning. Its format is not fixed and depends on the data
            source and extraction process.
    """
    path: str
    extension: str
    info: str
