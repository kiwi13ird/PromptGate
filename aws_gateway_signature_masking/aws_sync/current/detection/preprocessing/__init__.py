from .errors import (
    CorruptedDocumentError,
    DocumentParsingError,
    EncryptedDocumentError,
    UnsupportedFormatError,
)
from .format_detect import detect_format
from .indexer import (
    CellSpan,
    DetectionLocation,
    IndexedBlock,
    IndexedDocument,
    WordSpan,
    build_index,
)
from .pipeline import Block, ParsedDocument, build_text_document, parse_document
from .router import process_input

__all__ = [
    "process_input",
    "parse_document",
    "build_text_document",
    "detect_format",
    "ParsedDocument",
    "Block",
    "build_index",
    "IndexedDocument",
    "IndexedBlock",
    "DetectionLocation",
    "WordSpan",
    "CellSpan",
    "UnsupportedFormatError",
    "DocumentParsingError",
    "EncryptedDocumentError",
    "CorruptedDocumentError",
]
