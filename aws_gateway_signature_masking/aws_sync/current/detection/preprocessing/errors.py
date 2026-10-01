"""FR-PRE-007/008 관련 예외 타입.

파서는 실패 시 이 예외들만 던진다. 상위 pipeline.parse_document()가 이를 잡아
success=False 결과로 변환하므로, 실제 차단 조치(FR-GW-014의 "정의된 기본 조치")는
게이트웨이 계층에서 error_type을 보고 결정한다 - 이 모듈은 조치를 내리지 않는다.
"""


class DocumentParsingError(Exception):
    """지원 대상 형식이지만 파싱에 실패한 경우의 공통 베이스 (FR-PRE-007)."""


class CorruptedDocumentError(DocumentParsingError):
    """파일이 손상되어 열 수 없는 경우."""


class EncryptedDocumentError(DocumentParsingError):
    """암호가 설정되어 열 수 없는 경우."""


class UnsupportedFormatError(Exception):
    """지원 대상이 아닌 형식(PDF/DOCX/XLSX 외)인 경우 (FR-PRE-008)."""

    def __init__(self, extension: str):
        self.extension = extension
        super().__init__(f"지원하지 않는 형식입니다: {extension}")
