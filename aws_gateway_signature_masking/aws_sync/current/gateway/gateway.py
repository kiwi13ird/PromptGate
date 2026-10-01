from mitmproxy import http

import json
import os
import re
import threading
import time
import uuid
import requests
import zipfile
from collections import Counter, deque
from urllib.parse import unquote_plus

from datetime import datetime, timezone
from io import BytesIO
from email.parser import BytesParser
from email.policy import default

from pypdf import PdfReader
from docx import Document
from openpyxl import load_workbook

from detection_client import check as check_detection
from event_adapter import checkable_parts, part_request_id
from client_identity import read_and_strip_identity
from dashboard_event_mapper import build_dashboard_event
from dashboard_event_sender import (
    dashboard_integration_enabled,
    report_allow_events_enabled,
    send_dashboard_event,
    send_dashboard_metrics,
)
from extension_event_sender import send_extension_event
from normalizer import normalize_text
from gateway_file_masking import load_review_artifact, replace_multipart_file, sanitize_for_upload
DETECTION_BASE_URL = os.environ.get("DETECTION_BASE_URL", "http://10.0.3.168:8000")


# ============================================================
# Gateway 설정
# ============================================================

OPENAI_HOST = "api.openai.com"

OPENAI_RESPONSES_ENDPOINT = "/v1/responses"
OPENAI_FILES_ENDPOINT = "/v1/files"

# ============================================================
# LLM Web Service 식별
# ============================================================

LLM_HOSTS = {
    "chatgpt.com": "ChatGPT",
    "openai.com": "ChatGPT/OpenAI",
    "oaistatic.com": "ChatGPT/OpenAI",
    "oaiusercontent.com": "ChatGPT/OpenAI",
    "gemini.google.com": "Gemini",
    "claude.ai": "Claude",
    "anthropic.com": "Claude/Anthropic",
}


def service_for(host: str | None) -> str | None:
    host = (host or "").lower()

    for domain, service in LLM_HOSTS.items():
        if host == domain or host.endswith("." + domain):
            return service

    return None


# 다음 모듈
NEXT_MODULE_URL = (
    "http://127.0.0.1:3000/internal/gateway/events"
)

CHATGPT_FILE_META = {}
GEMINI_FILE_META = {}


# ============================================================
# Client IP
# ============================================================

def get_client_ip(flow: http.HTTPFlow) -> str | None:

    if flow.client_conn.peername:
        return flow.client_conn.peername[0]

    return None


# ============================================================
# 파일 텍스트 추출
# TXT / PDF / DOCX / XLSX
# ============================================================

def _json_body(flow: http.HTTPFlow) -> dict | None:
    try:
        data = json.loads(flow.request.get_text() or "")
        return data if isinstance(data, dict) else None
    except (json.JSONDecodeError, TypeError):
        return None


def _remember_chatgpt_file_metadata(flow: http.HTTPFlow):
    data = _json_body(flow)
    if not data:
        return

    found_ids = []
    found_names = []

    def walk(obj):
        if isinstance(obj, dict):
            for key, value in obj.items():
                key_l = str(key).lower()
                if key_l in {"file_id", "fileid"} and isinstance(value, str):
                    found_ids.append(value)
                elif key_l == "id" and isinstance(value, str) and len(value) >= 16:
                    found_ids.append(value)
                elif key_l in {"filename", "file_name", "name"} and isinstance(value, str) and "." in value:
                    found_names.append(value)
                walk(value)
        elif isinstance(obj, list):
            for item in obj:
                walk(item)

    walk(data)

    if not found_ids or not found_names:
        return

    filename = found_names[0]
    for file_id in found_ids:
        CHATGPT_FILE_META[file_id] = filename
        print("→ Remembered ChatGPT file metadata:", file_id, "=>", filename)


def _extract_chatgpt_raw_file_id(path: str) -> str | None:
    clean_path = path.split("?", 1)[0]
    parts = clean_path.strip("/").split("/")
    if len(parts) >= 3 and parts[0] == "files" and parts[2] == "raw":
        return parts[1]
    return None


def _guess_extension_from_content_type(content_type: str) -> str | None:
    content_type = (content_type or "").lower().split(";", 1)[0].strip()
    return {
        "text/plain": "txt",
        "application/pdf": "pdf",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "docx",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": "xlsx",
    }.get(content_type)



def _infer_chatgpt_file_extension(
    file_bytes: bytes,
    content_type: str = "",
    filename: str | None = None,
) -> str | None:
    """
    ChatGPT Web의 실제 PUT에는 원본 파일명이 없을 수 있으므로
    파일명 → MIME → 파일 시그니처 순서로 TXT/PDF/DOCX/XLSX를 판별한다.
    """

    # 1. 원본 filename이 확보된 경우
    if filename and "." in filename:
        ext = filename.lower().rsplit(".", 1)[-1]
        if ext in {"txt", "pdf", "docx", "xlsx"}:
            return ext

    # 2. Content-Type
    ext = _guess_extension_from_content_type(content_type)
    if ext:
        return ext

    # 3. PDF magic bytes
    if file_bytes.startswith(b"%PDF-"):
        return "pdf"

    # 4. DOCX/XLSX는 ZIP 컨테이너이므로 내부 구조로 구분
    if file_bytes.startswith(b"PK"):
        try:
            with zipfile.ZipFile(BytesIO(file_bytes)) as zf:
                names = zf.namelist()

                if any(name.startswith("word/") for name in names):
                    return "docx"

                if any(name.startswith("xl/") for name in names):
                    return "xlsx"

        except (zipfile.BadZipFile, OSError):
            pass

    # 5. TXT fallback
    try:
        decoded = file_bytes.decode("utf-8")
        if decoded:
            # 바이너리 파일을 TXT로 오인하지 않도록 NUL 문자는 제외
            if "\x00" not in decoded:
                return "txt"
    except UnicodeDecodeError:
        pass

    return None



def create_chatgpt_raw_file_event(
    flow: http.HTTPFlow,
    file_id: str,
    filename: str | None,
) -> dict:
    file_bytes = flow.request.raw_content or b""

    content_type = flow.request.headers.get("content-type", "")

    extension = _infer_chatgpt_file_extension(
        file_bytes=file_bytes,
        content_type=content_type,
        filename=filename,
    )

    if not extension:
        filename = filename or f"{file_id}.unknown"
    else:
        # 실제 filename이 없거나 확장자가 지원되지 않는 경우
        # 추출 가능한 확장자를 붙인다.
        if not filename or filename.lower().rsplit(".", 1)[-1] not in {
            "txt", "pdf", "docx", "xlsx"
        }:
            filename = f"{file_id}.{extension}"

    extracted_text = extract_file_text(filename, file_bytes)

    file_content = {
        "type": "file",
        "filename": filename,
        "content": extracted_text if extracted_text is not None else "",
        "file_id": file_id,
        "body_size": len(file_bytes),
    }

    return {
        "request_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "client": {"ip": get_client_ip(flow)},
        "service": "ChatGPT",
        "request": {
            "method": flow.request.method,
            "endpoint": flow.request.path.split("?", 1)[0],
        },
        "contents": [file_content],
        "metadata": {
            "content_count": 1,
            "body_size": len(file_bytes),
            "file_id": file_id,
        },
    }


def extract_file_text(
    filename: str | None,
    file_bytes: bytes,
) -> str | None:

    if not filename:
        return None

    extension = filename.lower().rsplit(".", 1)[-1]

    # --------------------------------------------------------
    # TXT
    # --------------------------------------------------------

    if extension == "txt":

        try:
            return file_bytes.decode(
                "utf-8",
                errors="ignore",
            )

        except Exception as e:

            print(
                "❌ TXT text extraction failed:",
                e,
            )

            return None

    # --------------------------------------------------------
    # PDF
    # --------------------------------------------------------

    if extension == "pdf":

        try:

            reader = PdfReader(
                BytesIO(file_bytes)
            )

            texts = []

            for page in reader.pages:

                text = page.extract_text()

                if text:
                    texts.append(text)

            return "\n".join(texts)

        except Exception as e:

            print(
                "❌ PDF text extraction failed:",
                e,
            )

            return None

    # --------------------------------------------------------
    # DOCX
    # --------------------------------------------------------

    if extension == "docx":

        try:

            document = Document(
                BytesIO(file_bytes)
            )

            texts = []

            # 일반 문단
            for paragraph in document.paragraphs:

                if paragraph.text:
                    texts.append(
                        paragraph.text
                    )

            # 표 내부 텍스트
            for table in document.tables:

                for row in table.rows:

                    values = []

                    for cell in row.cells:

                        if cell.text:
                            values.append(
                                cell.text
                            )

                    if values:
                        texts.append(
                            " | ".join(values)
                        )

            return "\n".join(texts)

        except Exception as e:

            print(
                "❌ DOCX text extraction failed:",
                e,
            )

            return None

    # --------------------------------------------------------
    # XLSX
    # --------------------------------------------------------

    if extension == "xlsx":

        try:

            workbook = load_workbook(
                BytesIO(file_bytes),
                read_only=True,
                data_only=True,
            )

            texts = []

            for sheet in workbook.worksheets:

                # Sheet 이름도 정보로 포함
                texts.append(
                    f"[Sheet: {sheet.title}]"
                )

                for row in sheet.iter_rows(
                    values_only=True
                ):

                    values = [
                        str(value)
                        for value in row
                        if value is not None
                    ]

                    if values:

                        texts.append(
                            " | ".join(values)
                        )

            return "\n".join(texts)

        except Exception as e:

            print(
                "❌ XLSX text extraction failed:",
                e,
            )

            return None

    # --------------------------------------------------------
    # CSV / JSON / HTML / HTM / RTF / ODT(plain XML fallback)
    # --------------------------------------------------------

    if extension in {"csv", "json", "html", "htm", "rtf"}:

        try:
            return file_bytes.decode(
                "utf-8",
                errors="ignore",
            )
        except Exception as e:
            print(
                f"❌ {extension.upper()} text extraction failed:",
                e,
            )
            return None

    # ODT는 ZIP 기반 XML 문서이므로 기존 zipfile import를 이용해
    # content.xml의 텍스트를 간단히 추출한다.
    if extension == "odt":

        try:
            import re as _re
            with zipfile.ZipFile(BytesIO(file_bytes)) as archive:
                xml = archive.read("content.xml").decode(
                    "utf-8",
                    errors="ignore",
                )
            xml = _re.sub(r"<[^>]+>", " ", xml)
            return " ".join(xml.split())
        except Exception as e:
            print(
                "❌ ODT text extraction failed:",
                e,
            )
            return None

    # --------------------------------------------------------
    # 지원하지 않는 형식
    # --------------------------------------------------------

    print(
        f"⚠️ Unsupported file type: {filename}"
    )

    return None


# ============================================================
# Responses API 콘텐츠 추출
# ============================================================

def extract_content(
    body: dict,
) -> list[dict]:

    results = []

    input_data = body.get("input")

    # --------------------------------------------------------
    # input = 문자열
    # --------------------------------------------------------

    if isinstance(input_data, str):

        results.append({
            "type": "prompt",
            "content": input_data,
        })

    # --------------------------------------------------------
    # input = 배열
    # --------------------------------------------------------

    elif isinstance(input_data, list):

        for item in input_data:

            # 문자열
            if isinstance(item, str):

                results.append({
                    "type": "prompt",
                    "content": item,
                })

                continue

            # 객체가 아니면 무시
            if not isinstance(item, dict):
                continue

            content = item.get("content")

            # ------------------------------------------------
            # content = 문자열
            # ------------------------------------------------

            if isinstance(content, str):

                results.append({
                    "type": "prompt",
                    "content": content,
                })

            # ------------------------------------------------
            # content = 배열
            # ------------------------------------------------

            elif isinstance(content, list):

                for content_item in content:

                    if not isinstance(
                        content_item,
                        dict,
                    ):
                        continue

                    content_type = content_item.get(
                        "type"
                    )

                    # ----------------------------------------
                    # Prompt
                    # ----------------------------------------

                    if content_type == "input_text":

                        results.append({
                            "type": "prompt",
                            "content": content_item.get(
                                "text",
                                "",
                            ),
                        })

                    # ----------------------------------------
                    # File
                    # ----------------------------------------

                    elif content_type == "input_file":

                        results.append({
                            "type": "file",
                            "file_id": content_item.get(
                                "file_id"
                            ),
                            "filename": content_item.get(
                                "filename"
                            ),
                        })

                    # ----------------------------------------
                    # Image
                    # ----------------------------------------

                    elif content_type in (
                        "input_image",
                        "image_url",
                    ):

                        results.append({
                            "type": "image",
                            "content": content_item,
                        })

    return results


# ============================================================
# Responses API Gateway Event
# ============================================================

def create_responses_event(
    flow: http.HTTPFlow,
    body: dict,
) -> dict:

    contents = extract_content(body)

    event = {

        "request_id": str(
            uuid.uuid4()
        ),

        "timestamp": (
            datetime.now(
                timezone.utc
            ).isoformat()
        ),

        "client": {
            "ip": get_client_ip(flow),
        },

        "service": "OpenAI",

        "request": {
            "method": flow.request.method,
            "endpoint": flow.request.path,
            "model": body.get("model"),
        },

        "contents": contents,

        "metadata": {
            "content_count": len(contents),
            "body_size": len(
                flow.request.raw_content or b""
            ),
        },
    }

    return event


# ============================================================
# Gemini Web Resumable File Upload
# ============================================================

def _remember_gemini_upload_filename(flow: http.HTTPFlow) -> str | None:
    """
    Gemini의 resumable upload 시작 요청에서 파일명을 기억한다.
    실제 파일 내용은 로그에 출력하지 않는다.
    """
    body = flow.request.raw_content or b""
    if not body:
        return None

    try:
        decoded = unquote_plus(body.decode("utf-8", errors="ignore")).strip()
    except Exception:
        return None

    prefix = "File name:"
    if not decoded.startswith(prefix):
        return None

    filename = decoded[len(prefix):].strip()
    if not filename:
        return None

    GEMINI_FILE_META[get_client_ip(flow) or "unknown"] = filename
    print("→ Remembered Gemini file metadata:", filename)
    return filename


def _get_gemini_upload_filename(flow: http.HTTPFlow) -> str | None:
    return GEMINI_FILE_META.get(get_client_ip(flow) or "unknown")


def _create_gemini_resumable_file_event(
    flow: http.HTTPFlow,
    filename: str | None,
) -> dict:
    file_bytes = flow.request.raw_content or b""

    # 파일명으로 확장자를 우선 판별하고,
    # 없으면 기존 시그니처 판별 로직을 재사용한다.
    extension = _infer_chatgpt_file_extension(
        file_bytes=file_bytes,
        content_type=flow.request.headers.get("content-type", ""),
        filename=filename,
    )

    if not extension:
        filename = filename or "gemini_upload.unknown"
    elif not filename or "." not in filename:
        filename = f"gemini_upload.{extension}"

    extracted_text = extract_file_text(filename, file_bytes)

    file_content = {
        "type": "file",
        "filename": filename,
        "content": extracted_text if extracted_text is not None else "",
        "body_size": len(file_bytes),
    }

    return {
        "request_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "client": {"ip": get_client_ip(flow)},
        "service": "Gemini",
        "request": {
            "method": flow.request.method,
            "endpoint": flow.request.path.split("?", 1)[0],
        },
        "contents": [file_content],
        "metadata": {
            "content_count": 1,
            "body_size": len(file_bytes),
        },
    }


def handle_gemini_resumable_upload(
    flow: http.HTTPFlow,
    identity: dict,
) -> bool:
    """
    Gemini Web의 push.clients6.google.com resumable upload를 처리한다.

    반환값:
      True  = Detection에 의해 요청을 종료함(BLOCK 등)
      False = 정상적으로 다음 단계로 진행
    """
    req = flow.request

    if req.host != "push.clients6.google.com" or req.method != "POST":
        return False

    raw_path = req.path.split("?", 1)[0]
    query = req.query

    # 업로드 시작 요청: 파일명만 전달
    if raw_path == "/upload/" and "upload_protocol" not in query:
        remembered = _remember_gemini_upload_filename(flow)
        if remembered:
            print("\n===== GEMINI FILE UPLOAD INIT =====")
            print("Filename:", remembered)
            print("→ Waiting for resumable file bytes")
        return False

    # 실제 resumable file bytes
    if (
        raw_path != "/upload/"
        or query.get("upload_protocol") != "resumable"
        or not query.get("upload_id")
    ):
        return False

    file_bytes = req.raw_content or b""
    if not file_bytes:
        return False

    filename = _get_gemini_upload_filename(flow)

    # DOCX/XLSX/기타 지원 파일을 시그니처로 보완
    if not filename:
        extension = _infer_chatgpt_file_extension(
            file_bytes=file_bytes,
            content_type=req.headers.get("content-type", ""),
        )
        filename = f"gemini_upload.{extension}" if extension else None

    print("\n===== GEMINI FILE UPLOAD DETECTED =====")
    print("Host:", req.host)
    print("Path:", raw_path)
    print("Filename:", filename or "(unknown)")
    print("Body size:", len(file_bytes))
    print("Upload protocol: resumable")

    if not filename:
        print("→ Filename could not be resolved; PASS THROUGH")
        return False

    event = _create_gemini_resumable_file_event(flow, filename)
    print_gateway_event(event)
    send_to_next_module(event)

    normalized_text = extract_file_checkable_text(event)

    if not normalized_text:
        print("→ No checkable text extracted; PASS THROUGH")
        return False

    print("→ Extracted file text length:", len(normalized_text))
    print("→ Sending extracted Gemini file text to Detection Module")

    result = check_detection(
        DETECTION_BASE_URL,
        request_id=event["request_id"],
        normalized_text=normalized_text,
        source={
            "service": "Gemini",
            "endpoint": raw_path,
            "content_type": "file",
            "filename": filename,
        },
    )

    print("\n===== GEMINI FILE DETECTION RESULT =====")
    print_detection_summary(result)

    if enforce_detection_result(
        flow,
        result,
        dashboard_context={
            "identity": identity,
            "targetLlm": "Gemini",
            "contentType": "file",
        },
    ):
        return True

    print("→ Gemini file upload: PASS")
    return False



# ============================================================
# Multipart File Upload 파싱
# ============================================================

def extract_file_upload_info(
    flow: http.HTTPFlow,
) -> dict:

    req = flow.request

    content_type = req.headers.get(
        "content-type",
        "",
    )

    # ========================================================
    # Multipart File Upload 파싱
    # ========================================================

    # OpenAI API는 아래의 기존 상세 파싱 로직으로 처리
    # (나머지 LLM 웹서비스는 현재 여기서 통과)
    body = req.raw_content or b""

    filename = None
    purpose = None
    file_bytes = None

    # --------------------------------------------------------
    # Content-Type 확인
    # --------------------------------------------------------

    if not content_type.startswith(
        "multipart/form-data"
    ):

        return {
            "filename": None,
            "purpose": None,
            "body_size": len(body),
            "file_bytes": None,
        }

    # --------------------------------------------------------
    # Multipart parser용 가상 MIME Header 생성
    # --------------------------------------------------------

    try:

        raw_message = (
            b"Content-Type: "
            + content_type.encode()
            + b"\r\n"
            + b"\r\n"
            + body
        )

        message = BytesParser(
            policy=default
        ).parsebytes(
            raw_message
        )

        # ----------------------------------------------------
        # Multipart 각 Part 처리
        # ----------------------------------------------------

        for part in message.iter_parts():

            disposition = part.get(
                "Content-Disposition",
                "",
            )

            part_name = part.get_param(
                "name",
                header="Content-Disposition",
            )

            # -----------------------------------------------
            # purpose
            # -----------------------------------------------

            if part_name == "purpose":

                payload = part.get_payload(
                    decode=True
                )

                if payload:

                    purpose = payload.decode(
                        "utf-8",
                        errors="ignore",
                    ).strip()

            # -----------------------------------------------
            # file
            # -----------------------------------------------

            elif part_name == "file":

                filename = part.get_filename()

                file_bytes = part.get_payload(
                    decode=True
                )

    except Exception as e:

        print(
            "❌ Multipart parsing failed:",
            e,
        )

    return {
        "filename": filename,
        "purpose": purpose,
        "body_size": len(body),
        "file_bytes": file_bytes,
    }


# ============================================================
# File Upload Gateway Event
# ============================================================

def create_file_event(
    flow: http.HTTPFlow,
) -> dict:

    file_info = extract_file_upload_info(
        flow
    )

    filename = file_info["filename"]
    file_bytes = file_info["file_bytes"]

    # --------------------------------------------------------
    # 실제 파일 텍스트 추출
    # --------------------------------------------------------

    extracted_text = None

    if file_bytes:

        extracted_text = extract_file_text(
            filename,
            file_bytes,
        )

    # --------------------------------------------------------
    # Content 생성
    # --------------------------------------------------------

    file_content = {
        "type": "file",
        "filename": filename,
        "purpose": file_info["purpose"],
    }

    # 텍스트 추출 성공 시 content 추가
    if extracted_text is not None:

        file_content["content"] = extracted_text

    # --------------------------------------------------------
    # Event 생성
    # --------------------------------------------------------

    event = {

        "request_id": str(
            uuid.uuid4()
        ),

        "timestamp": (
            datetime.now(
                timezone.utc
            ).isoformat()
        ),

        "client": {
            "ip": get_client_ip(flow),
        },

        "service": "OpenAI",

        "request": {
            "method": flow.request.method,
            "endpoint": flow.request.path,
        },

        "contents": [
            file_content
        ],

        "metadata": {
            "content_count": 1,
            "body_size": file_info["body_size"],
        },
    }

    return event


# ============================================================
# Detection Module 전달용 파일 텍스트 추출
# ============================================================

def extract_file_checkable_text(event: dict) -> str | None:
    """
    Gateway Event의 file content 중 실제 파일에서 추출한 텍스트만
    Detection Module 전달용 문자열로 합친다.
    """
    texts = []

    for item in event.get("contents", []):
        if not isinstance(item, dict):
            continue

        if item.get("type") != "file":
            continue

        content = item.get("content")

        if isinstance(content, str) and content.strip():
            texts.append(content.strip())

    if not texts:
        return None

    return "\n".join(texts)


# ============================================================
# 다음 모듈로 Event 전달
# ============================================================

def send_to_next_module(
    event: dict,
):

    try:

        session = requests.Session()

        # 시스템 Proxy 환경변수 무시
        # Gateway → localhost 통신이
        # 다시 Gateway를 거치지 않도록 함
        session.trust_env = False

        response = session.post(
            NEXT_MODULE_URL,
            json=event,
            timeout=3,
        )

        print(
            "\n===== NEXT MODULE RESPONSE ====="
        )

        print(
            "Status:",
            response.status_code,
        )

        print(
            "Response bytes:",
            len(response.content or b""),
        )

    except requests.RequestException as e:

        print(
            "\n❌ Failed to send Gateway Event"
        )

        print(
            "Error:",
            e,
        )


# ============================================================
# Event 출력
# ============================================================

def print_gateway_event(
    event: dict,
):
    """Log metadata only; never print prompt or extracted file content."""
    request = event.get("request") or {}
    metadata = event.get("metadata") or {}
    content_types = [
        item.get("type")
        for item in event.get("contents", [])
        if isinstance(item, dict) and item.get("type")
    ]
    print("\n===== GATEWAY EVENT METADATA =====")
    print(
        json.dumps(
            {
                "request_id": event.get("request_id"),
                "timestamp": event.get("timestamp"),
                "service": event.get("service"),
                "method": request.get("method"),
                "endpoint": request.get("endpoint"),
                "content_types": content_types,
                "content_count": metadata.get("content_count"),
                "body_size": metadata.get("body_size"),
            },
            ensure_ascii=False,
        )
    )


def print_detection_summary(result):
    """Log only non-sensitive decision metadata."""
    print("\n===== DETECTION RESULT METADATA =====")
    print("Request ID:", getattr(result, "request_id", None))
    print("Decided by:", getattr(result, "decided_by", None))
    print("Action:", getattr(result, "action", None))
    print("Blocked:", getattr(result, "blocked", None))
    print("Degraded:", getattr(result, "degraded", None))
    print("HTTP status:", getattr(result, "http_status", None))
    print("Total ms:", getattr(result, "total_ms", None))


def _masked_text(text: str, spans: list[dict]) -> str | None:
    """Apply metadata-only Detection spans without ever logging matched values."""
    validated = []
    for span in spans or []:
        if not isinstance(span, dict):
            return None
        start, end = span.get("start"), span.get("end")
        entity_type = str(span.get("entity_type") or "SENSITIVE")
        if not isinstance(start, int) or not isinstance(end, int) or start < 0 or end <= start or end > len(text):
            return None
        validated.append((start, end, entity_type))
    validated.sort()
    if not validated or any(left[1] > right[0] for left, right in zip(validated, validated[1:])):
        return None
    result = text
    for start, end, entity_type in reversed(validated):
        result = result[:start] + f"[MASKED:{entity_type}]" + result[end:]
    return result


def _replace_matching_json_strings(value, normalized_target: str, replacement: str) -> int:
    count = 0
    if isinstance(value, list):
        for index, item in enumerate(value):
            if isinstance(item, str) and normalize_text(item) == normalized_target:
                value[index] = replacement
                count += 1
            else:
                count += _replace_matching_json_strings(item, normalized_target, replacement)
    elif isinstance(value, dict):
        for key, item in list(value.items()):
            if isinstance(item, str) and normalize_text(item) == normalized_target:
                value[key] = replacement
                count += 1
            else:
                count += _replace_matching_json_strings(item, normalized_target, replacement)
    return count


def _apply_json_mask(flow: http.HTTPFlow, normalized_text: str, result, body: dict | None = None) -> bool:
    replacement = getattr(result, "masked_text", None)
    if replacement is None:
        replacement = _masked_text(normalized_text, getattr(result, "mask_spans", None) or [])
    if replacement is None:
        return False
    if body is None:
        body = _json_body(flow)
    if not isinstance(body, dict):
        return False
    if _replace_matching_json_strings(body, normalized_text, replacement) < 1:
        return False
    flow.request.set_text(json.dumps(body, ensure_ascii=False, separators=(",", ":")))
    return True


def _apply_gemini_mask(flow: http.HTTPFlow, normalized_text: str, result) -> bool:
    replacement = getattr(result, "masked_text", None)
    if replacement is None:
        replacement = _masked_text(normalized_text, getattr(result, "mask_spans", None) or [])
    if replacement is None:
        return False
    try:
        form = flow.request.urlencoded_form
        outer = json.loads(form.get("f.req") or "")
        if not isinstance(outer, list) or len(outer) < 2 or not isinstance(outer[1], str):
            return False
        nested = json.loads(outer[1])
        if _replace_matching_json_strings(nested, normalized_text, replacement) < 1:
            return False
        outer[1] = json.dumps(nested, ensure_ascii=False, separators=(",", ":"))
        form["f.req"] = json.dumps(outer, ensure_ascii=False, separators=(",", ":"))
        return True
    except (ValueError, TypeError):
        return False


# ============================================================
# ChatGPT Web Request 사용자 프롬프트 추출
# ============================================================

def extract_chatgpt_prompt(flow: http.HTTPFlow) -> str | None:
    """
    실제 ChatGPT 메시지 전송 요청인
    /backend-api/f/conversation 의 Request Body에서
    사용자(role=user)의 텍스트 프롬프트만 추출한다.

    대상 구조:
    messages[].author.role == "user"
    messages[].content.content_type == "text"
    messages[].content.parts[]
    """
    req = flow.request

    if req.method.upper() != "POST":
        return None

    if req.path.split("?", 1)[0] != "/backend-api/f/conversation":
        return None

    content_type = req.headers.get("content-type", "").lower()
    if "application/json" not in content_type:
        return None

    try:
        body_text = req.get_text(strict=False)
        if not body_text:
            return None

        body = json.loads(body_text)

    except (json.JSONDecodeError, TypeError, UnicodeDecodeError) as e:
        print("❌ ChatGPT conversation JSON parsing failed:", e)
        return None

    messages = body.get("messages")
    if not isinstance(messages, list):
        return None

    prompts = []

    for message in messages:
        if not isinstance(message, dict):
            continue

        author = message.get("author")
        if not isinstance(author, dict):
            continue

        if author.get("role") != "user":
            continue

        content = message.get("content")
        if not isinstance(content, dict):
            continue

        if content.get("content_type") != "text":
            continue

        parts = content.get("parts")
        if not isinstance(parts, list):
            continue

        for part in parts:
            if isinstance(part, str) and part.strip():
                prompts.append(part)

    if not prompts:
        return None

    # 실제 전송에서 마지막 user part가 이번 요청의 새 프롬프트다. 하나씩 검사해야
    # MASK 좌표를 요청 JSON의 정확한 문자열에 다시 적용할 수 있다.
    return prompts[-1]


# ============================================================
# Gemini Web Request 구조 확인용 DEBUG
# ============================================================

def debug_gemini_request_structure(flow: http.HTTPFlow):
    """
    Gemini 웹 요청의 구조만 확인하기 위한 DEBUG 함수.
    프롬프트/쿠키/Authorization/세션값/전체 body는 출력하지 않는다.
    """
    req = flow.request

    if req.method.upper() != "POST":
        return

    path = req.path.split("?", 1)[0]

    if not (
        req.host == "gemini.google.com"
        and (
            "StreamGenerate" in path
            or "batchexecute" in path
        )
    ):
        return

    raw_body = req.raw_content or b""
    content_type = req.headers.get("content-type", "")

    print("\n===== GEMINI REQUEST STRUCTURE DEBUG =====")
    print("Endpoint:", path)
    print("Content-Type:", content_type.split(";", 1)[0])
    print("Body size:", len(raw_body))

    if "application/json" in content_type.lower():
        try:
            body = json.loads(req.get_text(strict=False) or "")
            if isinstance(body, dict):
                print("Body format: JSON object")
                print("Top-level keys:", list(body.keys())[:30])
            elif isinstance(body, list):
                print("Body format: JSON array")
                print("Array length:", len(body))
            else:
                print("Body format: JSON", type(body).__name__)
        except Exception as e:
            print("JSON parse:", type(e).__name__)

    elif "application/x-www-form-urlencoded" in content_type.lower():
        try:
            from urllib.parse import parse_qs

            decoded = raw_body.decode("utf-8", errors="ignore")
            fields = parse_qs(decoded, keep_blank_values=True)

            print("Body format: x-www-form-urlencoded")
            print("Field names:", list(fields.keys())[:50])

            field_lengths = {
                key: [len(v) for v in values[:5]]
                for key, values in fields.items()
            }
            print("Field value lengths:", field_lengths)

        except Exception as e:
            print("Form parse:", type(e).__name__)

    else:
        print("Body format: other/unknown")

        printable = sum(
            1 for b in raw_body
            if b in (9, 10, 13) or 32 <= b <= 126
        )

        print(
            "Printable byte ratio:",
            round(printable / len(raw_body), 3) if raw_body else 0,
        )

    print("===== END GEMINI REQUEST STRUCTURE DEBUG =====")



# ============================================================
# Gemini StreamGenerate f.req 구조 확인용 DEBUG
# ============================================================

def debug_gemini_request_response(flow: http.HTTPFlow, phase: str):
    """
    Gemini request/response를 같은 flow.id 기준으로 추적한다.
    실제 body/query 값은 출력하지 않고 구조와 길이만 출력한다.
    """
    req = flow.request
    if req.host != "gemini.google.com" or req.method.upper() != "POST":
        return

    path = req.path.split("?", 1)[0]
    if "BardChatUi" not in path:
        return

    try:
        client_conn = getattr(flow, "client_conn", None)
        server_conn = getattr(flow, "server_conn", None)

        print("\n===== GEMINI REQUEST/RESPONSE FLOW DEBUG =====")
        print("Phase:", phase)
        print("Flow ID:", getattr(flow, "id", None))
        print("Client connection ID:", getattr(client_conn, "id", None))
        print("Server connection ID:", getattr(server_conn, "id", None))
        print("Method:", req.method)
        print("Host:", req.host)
        print("Path:", path)

        if path.endswith("/batchexecute"):
            print("Endpoint type: BATCHEXECUTE")
        elif "assistant" in path.lower():
            print("Endpoint type: ASSISTANT")
        else:
            print("Endpoint type: OTHER_BARDCHATUI")

        if phase == "REQUEST":
            body = req.raw_content or b""
            ctype = req.headers.get("content-type", "")
            print("Content-Type:", ctype.split(";", 1)[0].strip())
            print("Request body size:", len(body))

            if "application/x-www-form-urlencoded" in ctype.lower():
                from urllib.parse import parse_qs
                try:
                    fields = parse_qs(
                        body.decode("utf-8", errors="ignore"),
                        keep_blank_values=True,
                    )
                    print("Request form fields:", list(fields.keys())[:30])
                    for name, values in fields.items():
                        print(
                            f"Request field {name}: "
                            f"{len(values[0]) if values else 0} chars"
                        )
                except Exception as e:
                    print("Request form inspection failed:", type(e).__name__)

        elif phase == "RESPONSE":
            response = flow.response
            if response is None:
                print("Response: NONE")
            else:
                ctype = response.headers.get("content-type", "")
                body = response.raw_content or b""
                print("Response status:", response.status_code)
                print("Response Content-Type:", ctype.split(";", 1)[0].strip())
                print("Response body size:", len(body))

        print("===== END GEMINI REQUEST/RESPONSE FLOW DEBUG =====\n")
    except Exception as e:
        print("\n===== GEMINI REQUEST/RESPONSE FLOW DEBUG ERROR =====")
        print("Phase:", phase)
        print("Error type:", type(e).__name__)
        print("===== END GEMINI REQUEST/RESPONSE FLOW DEBUG ERROR =====\n")


def debug_gemini_flow_identity(flow: http.HTTPFlow):
    """
    Gemini request flow를 정확히 식별하기 위한 DEBUG.

    목적:
    - mitmproxy 한 줄 로그의 assistant... 요청과
      addon 내부에서 처리되는 flow를 매칭
    - batchexecute와 assistant 요청이 실제로 별도 flow인지 확인
    - request body 내용이나 query string은 출력하지 않음
    """

    req = flow.request

    if req.host != "gemini.google.com":
        return

    if req.method.upper() != "POST":
        return

    path = req.path.split("?", 1)[0]

    if "BardChatUi" not in path:
        return

    try:
        raw_body = req.raw_content or b""
        content_type = req.headers.get("content-type", "")
        content_type_base = content_type.split(";", 1)[0].strip()

        # flow 객체에서 안전하게 확인 가능한 식별 정보만 사용
        flow_id = getattr(flow, "id", None)

        client_conn = getattr(flow, "client_conn", None)
        server_conn = getattr(flow, "server_conn", None)

        client_id = getattr(client_conn, "id", None)
        server_id = getattr(server_conn, "id", None)

        client_addr = getattr(client_conn, "address", None)
        server_addr = getattr(server_conn, "address", None)

        print("\n===== GEMINI FLOW IDENTITY DEBUG =====")
        print("Flow ID:", flow_id)
        print("Client connection ID:", client_id)
        print("Server connection ID:", server_id)
        print("Client address:", client_addr)
        print("Server address:", server_addr)
        print("Method:", req.method)
        print("Host:", req.host)
        print("Path:", path)
        print("Path type:", type(path).__name__)
        print("Content-Type:", content_type_base)
        print("Body size:", len(raw_body))

        if path.endswith("/batchexecute"):
            print("Endpoint type: BATCHEXECUTE")
        elif "assistant" in path.lower():
            print("Endpoint type: ASSISTANT")
        else:
            print("Endpoint type: OTHER_BARDCHATUI")

        # body의 구조적 정보만 출력
        if "application/x-www-form-urlencoded" in content_type.lower():
            try:
                from urllib.parse import parse_qs

                decoded_body = raw_body.decode(
                    "utf-8",
                    errors="ignore",
                )

                fields = parse_qs(
                    decoded_body,
                    keep_blank_values=True,
                )

                print(
                    "Form field names:",
                    list(fields.keys())[:30],
                )

                for field_name, values in fields.items():
                    value_length = (
                        len(values[0])
                        if values
                        else 0
                    )

                    print(
                        f"Field {field_name}: "
                        f"{value_length} chars"
                    )

            except Exception as e:
                print(
                    "Form inspection failed:",
                    type(e).__name__,
                )

        print("===== END GEMINI FLOW IDENTITY DEBUG =====\n")

    except Exception as e:
        print("\n===== GEMINI FLOW IDENTITY DEBUG ERROR =====")
        print("Error type:", type(e).__name__)
        print("===== END GEMINI FLOW IDENTITY DEBUG ERROR =====\n")


def debug_gemini_assistant_path(flow: http.HTTPFlow):
    """
    Gemini 요청 중 assistant 관련 endpoint가 실제로 어떤 path로
    들어오는지 확인하기 위한 최우선 DEBUG.

    보안상 query string과 body 내용은 출력하지 않는다.
    """

    req = flow.request

    if req.host != "gemini.google.com":
        return

    if req.method.upper() != "POST":
        return

    path = req.path.split("?", 1)[0]

    # Gemini BardChatUi/data 계열 POST를 넓게 확인하고,
    # 특히 assistant 문자열이 포함된 요청을 별도로 표시한다.
    if "BardChatUi" not in path and "assistant" not in path.lower():
        return

    try:
        content_type = req.headers.get("content-type", "")
        content_type_base = content_type.split(";", 1)[0].strip()
        raw_body = req.raw_content or b""

        is_assistant = "assistant" in path.lower()

        print("\n===== GEMINI PATH DEBUG =====")

        if is_assistant:
            print("!!! ASSISTANT ENDPOINT DETECTED !!!")

        print("Method:", req.method)
        print("Host:", req.host)
        print("Path:", path)
        print("Path repr:", repr(path))
        print("Content-Type:", content_type_base)
        print("Body size:", len(raw_body))

        if "application/x-www-form-urlencoded" in content_type.lower():
            try:
                from urllib.parse import parse_qs

                decoded_body = raw_body.decode(
                    "utf-8",
                    errors="ignore",
                )

                fields = parse_qs(
                    decoded_body,
                    keep_blank_values=True,
                )

                print("Form field names:", list(fields.keys())[:30])

                for field_name, values in fields.items():
                    if field_name == "f.req":
                        print(
                            "Field f.req:",
                            f"{len(values[0]) if values else 0} chars"
                        )
                    elif field_name == "at":
                        print(
                            "Field at:",
                            f"{len(values[0]) if values else 0} chars"
                        )
                    else:
                        print(
                            f"Field {field_name}:",
                            f"{len(values[0]) if values else 0} chars"
                        )

            except Exception as e:
                print(
                    "Form inspection failed:",
                    type(e).__name__,
                )

        print("===== END GEMINI PATH DEBUG =====\n")

    except Exception as e:
        print("\n===== GEMINI PATH DEBUG ERROR =====")
        print("Error type:", type(e).__name__)
        print("===== END GEMINI PATH DEBUG ERROR =====\n")


def debug_gemini_f_req_structure(flow: http.HTTPFlow):
    """
    Gemini f.req 구조를 분석한다.

    핵심:
    - f.req 전체 값을 출력하지 않는다.
    - 문자열의 실제 내용도 출력하지 않는다.
    - 대신 문자열이 JSON으로 다시 파싱되는지 재귀적으로 확인한다.
    - Gemini 요청에서 흔히 보이는 "JSON 안에 JSON 문자열" 구조를 찾는다.
    """

    req = flow.request
    path = req.path.split("?", 1)[0]

    if not (
        req.host == "gemini.google.com"
        and req.method.upper() == "POST"
        and "BardChatUi" in path
    ):
        return

    try:
        from urllib.parse import parse_qs

        raw_body = req.raw_content or b""
        content_type = req.headers.get("content-type", "")

        if "application/x-www-form-urlencoded" not in content_type.lower():
            return

        decoded_body = raw_body.decode(
            "utf-8",
            errors="ignore",
        )

        fields = parse_qs(
            decoded_body,
            keep_blank_values=True,
        )

        f_req_values = fields.get("f.req")

        if not f_req_values:
            return

        f_req = f_req_values[0]

        print("\n===== GEMINI NESTED f.req DEBUG =====")
        print("Endpoint:", path)
        print("f.req length:", len(f_req))

        try:
            data = json.loads(f_req)
        except Exception as e:
            print("Outer JSON parse: FAILED")
            print("Error type:", type(e).__name__)
            print("===== END GEMINI NESTED f.req DEBUG =====\n")
            return

        print("Outer JSON parse: SUCCESS")
        print("Outer root type:", type(data).__name__)

        def inspect_value(
            value,
            path="$",
            depth=0,
            max_depth=12,
            max_items=30,
        ):
            indent = "  " * depth

            if depth > max_depth:
                print(
                    f"{indent}{path}: "
                    "<MAX_DEPTH_REACHED>"
                )
                return

            if isinstance(value, dict):
                print(
                    f"{indent}{path}: "
                    f"object ({len(value)} keys)"
                )

                for index, (key, child) in enumerate(
                    value.items()
                ):
                    if index >= max_items:
                        print(
                            f"{indent}  ... "
                            f"<remaining {len(value) - max_items} keys omitted>"
                        )
                        break

                    safe_key = str(key)
                    if len(safe_key) > 80:
                        safe_key = safe_key[:80] + "..."

                    inspect_value(
                        child,
                        f"{path}.{safe_key}",
                        depth + 1,
                        max_depth,
                        max_items,
                    )

            elif isinstance(value, list):
                print(
                    f"{indent}{path}: "
                    f"array ({len(value)} items)"
                )

                for index, child in enumerate(
                    value[:max_items]
                ):
                    inspect_value(
                        child,
                        f"{path}[{index}]",
                        depth + 1,
                        max_depth,
                        max_items,
                    )

                if len(value) > max_items:
                    print(
                        f"{indent}  ... "
                        f"<remaining {len(value) - max_items} items omitted>"
                    )

            elif isinstance(value, str):
                print(
                    f"{indent}{path}: "
                    f"string (length={len(value)})"
                )

                # 핵심: 문자열 자체가 JSON이면 재귀적으로 구조만 확인.
                stripped = value.strip()

                if (
                    len(stripped) >= 2
                    and stripped[0] in "[{"
                    and stripped[-1] in "]}"
                ):
                    try:
                        nested = json.loads(stripped)

                        print(
                            f"{indent}  "
                            "Nested JSON parse: SUCCESS"
                        )
                        print(
                            f"{indent}  "
                            "Nested JSON root type:",
                            type(nested).__name__,
                        )

                        inspect_value(
                            nested,
                            f"{path}::<parsed>",
                            depth + 2,
                            max_depth,
                            max_items,
                        )

                    except Exception:
                        print(
                            f"{indent}  "
                            "Nested JSON parse: FAILED"
                        )

            elif isinstance(value, bool):
                print(
                    f"{indent}{path}: boolean"
                )

            elif value is None:
                print(
                    f"{indent}{path}: null"
                )

            elif isinstance(value, (int, float)):
                print(
                    f"{indent}{path}: number"
                )

            else:
                print(
                    f"{indent}{path}: "
                    f"{type(value).__name__}"
                )

        inspect_value(data)

        print("===== END GEMINI NESTED f.req DEBUG =====\n")

    except Exception as e:
        print("\n===== GEMINI NESTED f.req DEBUG ERROR =====")
        print("Error type:", type(e).__name__)
        print("===== END GEMINI NESTED f.req DEBUG ERROR =====\n")


# ============================================================
# Detection 호출
# ============================================================

def detect_web_prompt(
    flow: http.HTTPFlow,
    service: str,
    prompt: str,
):
    """
    웹 LLM에서 추출한 사용자 프롬프트만 Detection Module로 전달.
    """

    request_id = str(uuid.uuid4())

    result = check_detection(
        DETECTION_BASE_URL,
        request_id=request_id,
        normalized_text=prompt,
        source={
            "service": service,
            "endpoint": flow.request.path,
            "content_type": "prompt",
        },
    )

    print("\n===== WEB LLM PROMPT METADATA =====")
    print("Request ID:", request_id)
    print("Prompt length:", len(prompt))
    print_detection_summary(result)

    return result



# ============================================================
# Detection 결과에 따른 BLOCK / PASS 집행
# ============================================================

def enforce_detection_result(
    flow: http.HTTPFlow,
    result,
    dashboard_context: dict | None = None,
    mask_callback=None,
) -> bool:
    """
    Detection Module의 응답에 따라 요청을 차단하거나 통과시킨다.

    Detection 응답의 decision 값을 그대로 집행한다(2026-09-15).
      action        "block" -> 차단 / "allow" -> 통과 / "allow_degraded" -> Detection 무응답, 통과(잠정 정책)
      user_message  사용자에게 보여줄 문구. 문서명·구간은 들어 있지 않다
      http_status   차단 응답 상태 코드(403)
    문서명·구간·일치율(doc_id, doc_span, input_span, score)과 reason은 사용자 응답에 넣지 않고
    Gateway 로그에만 남긴다 - 사용자가 어떤 문서의 어느 부분이 걸렸는지 알 수 없게.

    Returns:
        True  -> 요청을 BLOCK함
        False -> 요청을 PASS함
    """
    action = getattr(result, "action", None)
    if not action:  # 옛 클라이언트 결과(action 없음) 호환
        action = "block" if getattr(result, "blocked", False) else "allow"

    request_id = getattr(result, "request_id", None)
    detector = _result_detector(result)
    degraded = bool(getattr(result, "degraded", False))
    flow.metadata["gw_request_id"] = request_id
    flow.metadata["gw_detection_result"] = result
    flow.metadata["gw_action"] = action
    flow.metadata["gw_detector"] = detector
    flow.metadata["gw_degraded"] = degraded

    if action in {"block", "block_notify"}:
        print("\n===== GATEWAY ACTION =====")
        print("→ BLOCK")
        print("Request ID:", request_id)
        print("Decided by:", getattr(result, "decided_by", None))
        status = getattr(result, "http_status", None) or 403

        flow.response = http.Response.make(
            status,
            json.dumps(
                {
                    "error": {
                        "type": "policy_violation",
                        "message": getattr(result, "user_message", None)
                        or "Request blocked by AI Security Gateway.",
                        "reason_code": getattr(result, "reason_code", None),
                        "request_id": request_id,
                    }
                },
                ensure_ascii=False,
            ).encode("utf-8"),
            {
                "Content-Type": "application/json; charset=utf-8",
            },
        )

        report_dashboard_event(
            flow,
            result,
            dashboard_context,
            enforcement_applied=True,
            http_status=status,
        )

        return True

    if action in {"mask", "mask_partial", "mask_full"}:
        applied = False
        try:
            applied = bool(mask_callback and mask_callback(result))
        except Exception as exc:
            print("MASK application failed:", type(exc).__name__)
        if not applied:
            # A requested mask that cannot be proven applied must never leak the
            # original value. Convert only this request to a fail-closed block.
            result.action = "block"
            result.blocked = True
            result.reason_code = "mask_application_failed"
            result.user_message = "민감정보 마스킹에 실패하여 전송이 차단되었습니다. 문의 시 요청 번호를 알려주세요."
            result.http_status = 403
            return enforce_detection_result(flow, result, dashboard_context)

        flow.metadata["gw_action"] = "mask"
        print("\n===== GATEWAY ACTION =====")
        print("→ MASK")
        print("Request ID:", request_id)
        report_dashboard_event(
            flow,
            result,
            dashboard_context,
            enforcement_applied=True,
            http_status=None,
        )
        return False

    print("\n===== GATEWAY ACTION =====")
    if action == "allow_degraded":
        print("→ PASS (Detection 무응답 - 잠정 통과)")
        print("Request ID:", request_id)
    elif action == "allow_notify":
        print("→ PASS WITH NOTIFICATION")
    else:
        print("→ PASS")

    report_dashboard_event(
        flow,
        result,
        dashboard_context,
        enforcement_applied=False,
        http_status=None,
    )

    return False


def report_dashboard_event(
    flow: http.HTTPFlow,
    result,
    dashboard_context: dict | None,
    *,
    enforcement_applied: bool,
    http_status: int | None,
):
    """Best-effort Dashboard delivery that cannot change BLOCK/PASS."""
    if not dashboard_context or not dashboard_integration_enabled():
        return

    request_id = getattr(result, "request_id", None)
    try:
        event, skip_reason = build_dashboard_event(
            result=result,
            request_id=request_id or "unknown-request",
            identity=dashboard_context.get("identity") or {},
            target_llm=dashboard_context["targetLlm"],
            host=flow.request.host,
            endpoint=flow.request.path,
            content_type=dashboard_context["contentType"],
            enforcement_applied=enforcement_applied,
            http_status=http_status,
            report_allow_events=report_allow_events_enabled(),
        )
    except Exception as exc:
        print(
            "[DASHBOARD] event mapping failed "
            f"requestId={request_id or 'unknown'} error_type={type(exc).__name__}"
        )
        return

    if event is None:
        print(
            "[DASHBOARD] event skipped "
            f"requestId={request_id or 'unknown'} reason={skip_reason}"
        )
        return

    # 한 요청에 prompt/file 등 여러 검사 항목이 있을 수 있으므로 모두 보존한다.
    # 응답까지 받은 후 실제 Gateway latency/HTTP status를 확정해서 전송한다.
    flow.metadata.setdefault("gw_dashboard_events", []).append(event)


def _send_deferred_dashboard_event(flow: http.HTTPFlow):
    events = flow.metadata.pop("gw_dashboard_events", [])
    legacy_event = flow.metadata.pop("gw_dashboard_event", None)
    if legacy_event:
        events.append(legacy_event)
    if not events:
        return
    for event in events:
        latency_ms = flow.metadata.get("gw_latency_ms")
        if latency_ms is not None:
            # Dashboard Security Event v1의 허용 필드. Traffic 화면은 이 값을
            # 집계해 평균/P95 지연시간을 계산한다.
            event["processingMs"] = latency_ms
        send_dashboard_event(event)
        send_extension_event(event)



# ============================================================
# Claude Web 파일 업로드 Detection
# ============================================================

def _is_claude_multipart_file_upload(flow: http.HTTPFlow) -> bool:
    req = flow.request

    if req.host != "claude.ai" or req.method.upper() != "POST":
        return False

    content_type = req.headers.get("content-type", "").lower()
    if not content_type.startswith("multipart/form-data"):
        return False

    # Claude Web의 업로드 API 경로는 변경될 수 있으므로
    # 특정 endpoint 하나에 고정하지 않고 실제 multipart part에
    # filename이 있는지를 기준으로 파일 업로드를 식별한다.
    return True


def extract_claude_file_upload_info(flow: http.HTTPFlow) -> list[dict]:
    """
    Claude Web multipart 요청에서 파일 part를 모두 추출한다.

    로그에는 파일 원문을 출력하지 않는다. filename/body size만 기록하고
    실제 파일 bytes는 Detection 직전 메모리에서만 처리한다.
    """
    req = flow.request
    body = req.raw_content or b""
    content_type = req.headers.get("content-type", "")

    if not body or not content_type.lower().startswith("multipart/form-data"):
        return []

    files = []

    try:
        raw_message = (
            b"Content-Type: "
            + content_type.encode("utf-8", errors="ignore")
            + b"\r\n\r\n"
            + body
        )
        message = BytesParser(policy=default).parsebytes(raw_message)

        for part in message.iter_parts():
            filename = part.get_filename()
            if not filename:
                continue

            file_bytes = part.get_payload(decode=True) or b""
            files.append({
                "filename": filename,
                "file_bytes": file_bytes,
                "body_size": len(file_bytes),
                "part_name": part.get_param(
                    "name",
                    header="Content-Disposition",
                ),
                "content_type": part.get_content_type(),
            })

    except Exception as e:
        print("❌ Claude multipart parsing failed:", type(e).__name__)

    return files


def create_claude_file_event(flow: http.HTTPFlow, files: list[dict]) -> dict:
    contents = []

    for item in files:
        filename = item.get("filename")
        file_bytes = item.get("file_bytes") or b""
        extracted_text = extract_file_text(filename, file_bytes) if file_bytes else None

        content = {
            "type": "file",
            "filename": filename,
            "body_size": len(file_bytes),
        }

        if extracted_text is not None:
            content["content"] = extracted_text

        contents.append(content)

    return {
        "request_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "client": {"ip": get_client_ip(flow)},
        "service": "Claude",
        "request": {
            "method": flow.request.method,
            "endpoint": flow.request.path.split("?", 1)[0],
        },
        "contents": contents,
        "metadata": {
            "content_count": len(contents),
            "body_size": len(flow.request.raw_content or b""),
        },
    }


def detect_claude_file_upload(flow: http.HTTPFlow, identity: dict) -> bool:
    """
    Claude Web 파일 업로드를 추출 → Detection Module 검사 → BLOCK/PASS 집행.

    현재 공통 파일 추출기가 지원하는 TXT/PDF/DOCX/XLSX/CSV/JSON/HTML/RTF/ODT를
    검사한다. 지원하지 않는 형식은 원문을 추출할 수 없으므로 기존 정책대로 통과시킨다.
    """
    if not _is_claude_multipart_file_upload(flow):
        return False

    files = extract_claude_file_upload_info(flow)

    print("\n===== CLAUDE FILE UPLOAD DETECTED =====")
    print("Host:", flow.request.host)
    print("Method:", flow.request.method)
    print("Path:", flow.request.path.split("?", 1)[0])
    print("File count:", len(files))

    if not files:
        print("→ No file part found; PASS THROUGH")
        return False

    event = create_claude_file_event(flow, files)
    print_gateway_event(event)
    send_to_next_module(event)

    normalized_text = extract_file_checkable_text(event)

    if not normalized_text:
        print("→ No checkable file text extracted; PASS THROUGH")
        return False

    print("Extracted file text length:", len(normalized_text))
    print("→ Sending Claude file text to Detection Module")

    result = check_detection(
        DETECTION_BASE_URL,
        request_id=event["request_id"],
        normalized_text=normalized_text,
        source={
            "service": "Claude",
            "endpoint": flow.request.path.split("?", 1)[0],
            "content_type": "file",
            "filename": ", ".join(
                str(item.get("filename"))
                for item in event.get("contents", [])
                if item.get("filename")
            ),
        },
    )

    print("\n===== CLAUDE FILE DETECTION RESULT =====")
    print_detection_summary(result)

    return enforce_detection_result(
        flow,
        result,
        dashboard_context={
            "identity": identity,
            "targetLlm": "Claude",
            "contentType": "file",
        },
    )


# ============================================================
# Claude Web Request 사용자 프롬프트 추출
# ============================================================
def extract_claude_prompt(flow: http.HTTPFlow) -> str | None:
    """
    Claude Web의 실제 대화 전송 요청에서 사용자 prompt를 추출한다.

    현재 확인된 Claude Web completion 형태:
      POST /api/organizations/{orgId}/chat_conversations/{convId}/completion
      Content-Type: application/json

    일반적인 body의 prompt 필드를 우선 사용하고,
    구조가 달라진 경우 messages 계열의 user text를 보조적으로 찾는다.
    인증정보/쿠키/전체 body는 로그에 출력하지 않는다.
    """
    req = flow.request

    if req.host != "claude.ai" or req.method.upper() != "POST":
        return None

    path = req.path.split("?", 1)[0]

    # Claude Web 실제 completion endpoint
    if not re.match(
        r"^/api/organizations/[^/]+/chat_conversations/[^/]+/completion$",
        path,
    ):
        return None

    content_type = req.headers.get("content-type", "").lower()
    if "application/json" not in content_type:
        return None

    try:
        body = json.loads(req.get_text(strict=False) or "")
    except (json.JSONDecodeError, TypeError, UnicodeDecodeError):
        print("❌ Claude completion JSON parsing failed")
        return None

    if not isinstance(body, dict):
        return None

    # 1순위: Claude Web completion의 prompt
    prompt = body.get("prompt")
    if isinstance(prompt, str) and prompt.strip():
        return prompt.strip()

    # 2순위: messages 구조가 사용되는 경우
    messages = body.get("messages")
    candidates = []

    def walk_messages(value):
        if isinstance(value, dict):
            role = value.get("role")
            content = value.get("content")

            if role in {"user", "human"}:
                if isinstance(content, str) and content.strip():
                    candidates.append(content.strip())
                elif isinstance(content, list):
                    for item in content:
                        if isinstance(item, dict):
                            item_type = item.get("type")
                            if item_type in {"text", "input_text"}:
                                item_text = item.get("text")
                                if isinstance(item_text, str) and item_text.strip():
                                    candidates.append(item_text.strip())

            for child in value.values():
                walk_messages(child)

        elif isinstance(value, list):
            for child in value:
                walk_messages(child)

    if isinstance(messages, (dict, list)):
        walk_messages(messages)

    if candidates:
        return candidates[-1]

    return None


def detect_claude_web(flow: http.HTTPFlow, identity: dict) -> bool:
    """
    Claude Web 사용자 prompt를 Detection Module에 전달하고
    기존 Gateway BLOCK / MASK / PASS 정책을 적용한다.
    """
    prompt = extract_claude_prompt(flow)

    if not prompt:
        print("→ Claude user prompt not found")
        return False

    print("\n===== CLAUDE PROMPT DETECTED =====")
    print("Prompt length:", len(prompt))
    print("Endpoint:", flow.request.path.split("?", 1)[0])

    result = detect_web_prompt(
        flow,
        "Claude",
        prompt,
    )

    return enforce_detection_result(
        flow,
        result,
        dashboard_context={
            "identity": identity,
            "targetLlm": "Claude",
            "contentType": "prompt",
        },
        mask_callback=lambda detection_result: _apply_json_mask(
            flow,
            prompt,
            detection_result,
        ),
    )



def extract_gemini_prompt(flow: http.HTTPFlow) -> str | None:
    """
    Gemini Web StreamGenerate 요청의 f.req 내부에서
    사용자 입력 텍스트를 추출한다.

    실제 구조:
    form-data:
        f.req = [
            null,
            "[[... , \"USER_PROMPT\", ...]]"
        ]
    """

    req = flow.request

    if req.method.upper() != "POST":
        return None

    path = req.path.split("?", 1)[0]

    if "StreamGenerate" not in path:
        return None

    try:
        form = req.urlencoded_form

        raw = form.get("f.req")

        if not raw:
            return None

        outer = json.loads(raw)

        if not isinstance(outer, list):
            return None

        # Gemini는 두 번째 element가 JSON 문자열
        if len(outer) < 2 or not isinstance(outer[1], str):
            return None

        nested = json.loads(outer[1])

        if not isinstance(nested, list):
            return None

        candidates = []

        def walk(obj):
            if isinstance(obj, str):
                value = obj.strip()

                # prompt 후보 필터
                if (
                    len(value) >= 2
                    and not value.startswith("!")
                    and not value.startswith("http")
                    and value not in ("ko", "en")
                ):
                    candidates.append(value)

            elif isinstance(obj, list):
                for item in obj:
                    walk(item)

            elif isinstance(obj, dict):
                for value in obj.values():
                    walk(value)

        walk(nested)

        if not candidates:
            return None

        # 가장 긴 문자열을 사용자 prompt 후보로 사용
        return max(candidates, key=len)

    except Exception as e:
        print("Gemini prompt extraction failed:", e)
        return None


def detect_gemini_web(flow: http.HTTPFlow, identity: dict):
    prompt = extract_gemini_prompt(flow)

    if not prompt:
        print("→ Gemini user prompt not found")
        return False

    print("\n===== GEMINI PROMPT DETECTED =====")
    print("Prompt length:", len(prompt))

    result = detect_web_prompt(
        flow,
        "Gemini",
        prompt,
    )

    return enforce_detection_result(
        flow,
        result,
        dashboard_context={
            "identity": identity,
            "targetLlm": "Gemini",
            "contentType": "prompt",
        },
        mask_callback=lambda detection_result: _apply_gemini_mask(flow, prompt, detection_result),
    )


# ============================================================
# Gateway Traffic / Performance Metrics
# ============================================================
# 프롬프트/파일 원문은 저장하지 않으며 프로세스 메모리에서만 집계한다.

METRICS_WINDOW_SECONDS = 60
METRICS_LATENCY_MAX = 5000
_gateway_metrics_lock = threading.RLock()
_gateway_client_inflight = Counter()
_gateway_started_requests = deque()
_gateway_completed_requests = deque()
_gateway_latencies_ms = deque(maxlen=METRICS_LATENCY_MAX)
_gateway_metrics = {
    "total_requests": 0,
    "completed_requests": 0,
    "error_requests": 0,
    "timeout_requests": 0,
    "degraded_requests": 0,
    "action_counts": Counter(),
    "llm_counts": Counter(),
    "detector_counts": Counter(),
}


def _gateway_tracked(flow: http.HTTPFlow) -> bool:
    host = (flow.request.host or "").lower()
    return bool(service_for(host)) or host == OPENAI_HOST


def _prune_metric_window(queue, cutoff):
    while queue and queue[0] < cutoff:
        queue.popleft()


def _start_gateway_metric(flow: http.HTTPFlow):
    if not _gateway_tracked(flow):
        return
    now = time.time()
    client_ip = get_client_ip(flow)
    with _gateway_metrics_lock:
        _prune_metric_window(_gateway_started_requests, now - METRICS_WINDOW_SECONDS)
        _prune_metric_window(_gateway_completed_requests, now - METRICS_WINDOW_SECONDS)
        _gateway_metrics["total_requests"] += 1
        _gateway_started_requests.append(now)
        if client_ip:
            _gateway_client_inflight[client_ip] += 1
    flow.metadata["gw_metrics_started_at"] = time.perf_counter()
    flow.metadata["gw_metrics_client_ip"] = client_ip
    flow.metadata["gw_metrics_finalized"] = False
    _emit_gateway_metrics()


def _gateway_p95(values):
    if not values:
        return 0.0
    ordered = sorted(values)
    index = int((len(ordered) - 1) * 0.95)
    return round(float(ordered[index]), 2)


def _gateway_metrics_snapshot():
    now = time.time()
    with _gateway_metrics_lock:
        _prune_metric_window(_gateway_started_requests, now - METRICS_WINDOW_SECONDS)
        _prune_metric_window(_gateway_completed_requests, now - METRICS_WINDOW_SECONDS)
        latencies = list(_gateway_latencies_ms)
        total = max(1, _gateway_metrics["total_requests"])
        return {
            "active_clients": sum(
                1 for count in _gateway_client_inflight.values() if count > 0
            ),
            "concurrent_requests": sum(_gateway_client_inflight.values()),
            "requests_per_sec": round(
                len(_gateway_started_requests) / METRICS_WINDOW_SECONDS, 3
            ),
            "avg_latency_ms": (
                round(sum(latencies) / len(latencies), 2) if latencies else 0.0
            ),
            "p95_latency_ms": _gateway_p95(latencies),
            "timeout_rate": round(_gateway_metrics["timeout_requests"] / total, 4),
            "degraded_rate": round(_gateway_metrics["degraded_requests"] / total, 4),
            "total_requests": _gateway_metrics["total_requests"],
            "completed_requests": _gateway_metrics["completed_requests"],
            "error_requests": _gateway_metrics["error_requests"],
            "action_distribution": dict(_gateway_metrics["action_counts"]),
            "llm_distribution": dict(_gateway_metrics["llm_counts"]),
            "detector_distribution": dict(_gateway_metrics["detector_counts"]),
            "window_seconds": METRICS_WINDOW_SECONDS,
        }


def _emit_gateway_metrics():
    """Best-effort async delivery; metrics must never delay LLM traffic."""
    threading.Thread(
        target=send_dashboard_metrics,
        args=(_gateway_metrics_snapshot(),),
        daemon=True,
        name="dashboard-metrics",
    ).start()


def _finalize_gateway_metric(
    flow: http.HTTPFlow,
    *,
    action=None,
    detector=None,
    degraded=False,
    error=False,
    timeout=False,
):
    if (
        not flow.metadata.get("gw_metrics_started_at")
        or flow.metadata.get("gw_metrics_finalized")
    ):
        return
    flow.metadata["gw_metrics_finalized"] = True
    latency_ms = round(
        (time.perf_counter() - flow.metadata["gw_metrics_started_at"]) * 1000,
        2,
    )
    service = service_for(flow.request.host) or (
        "OpenAI" if flow.request.host == OPENAI_HOST else "Unknown"
    )
    client_ip = flow.metadata.get("gw_metrics_client_ip")
    with _gateway_metrics_lock:
        _gateway_metrics["completed_requests"] += 1
        _gateway_completed_requests.append(time.time())
        _gateway_latencies_ms.append(latency_ms)
        if error:
            _gateway_metrics["error_requests"] += 1
        if timeout:
            _gateway_metrics["timeout_requests"] += 1
        if degraded:
            _gateway_metrics["degraded_requests"] += 1
        if action:
            _gateway_metrics["action_counts"][str(action).upper()] += 1
        _gateway_metrics["llm_counts"][service] += 1
        if detector:
            _gateway_metrics["detector_counts"][str(detector)] += 1
        if client_ip:
            current = _gateway_client_inflight.get(client_ip, 0) - 1
            if current > 0:
                _gateway_client_inflight[client_ip] = current
            else:
                _gateway_client_inflight.pop(client_ip, None)
    flow.metadata["gw_latency_ms"] = latency_ms
    flow.metadata["gw_metrics_snapshot"] = _gateway_metrics_snapshot()
    _emit_gateway_metrics()
    print("\n===== GATEWAY TRAFFIC METRICS =====")
    print(json.dumps(flow.metadata["gw_metrics_snapshot"], ensure_ascii=False))


def _result_detector(result):
    for name in ("detector", "detector_name", "decided_by"):
        value = getattr(result, name, None)
        if value:
            return value
    return None


def _result_dashboard_metadata(result):
    names = (
        "severity", "match_status", "coverage", "similarity", "confidence",
        "doc_id", "doc_span", "input_span", "reason_code", "policy_version",
    )
    return {
        name: getattr(result, name)
        for name in names
        if getattr(result, name, None) is not None
    }


def _gateway_error_is_timeout(flow: http.HTTPFlow) -> bool:
    message = str(getattr(flow, "error", "") or "").lower()
    return "timeout" in message or "timed out" in message


# ============================================================
# mitmproxy Request Hook
# ============================================================

def request(
    flow: http.HTTPFlow,
):

    req = flow.request
     # Chrome Extension Gateway health check
    host = (req.pretty_host or "").lower()

    if host == "llm-gateway.local":
        if req.path.startswith("/__llmsgw/health"):
            flow.response = http.Response.make(
                200,
                json.dumps({
                    "status": "ok",
                    "service": "llm-security-gateway",
                    "version": "dev",
                }).encode("utf-8"),
                {
                    "Content-Type": "application/json; charset=utf-8",
                    "Cache-Control": "no-store",
                },
            )
            return
        review_prefix = "/__llmsgw/review/"
        if req.method == "GET" and req.path.split("?", 1)[0].startswith(review_prefix):
            review_id = req.path.split("?", 1)[0][len(review_prefix):]
            artifact = load_review_artifact(review_id)
            if artifact is None:
                flow.response = http.Response.make(404, b'{"error":"review_not_found"}',
                                                   {"Content-Type": "application/json", "Cache-Control": "no-store"})
                return
            name, payload = artifact
            extension = name.rsplit(".", 1)[-1]
            mime = {"docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                    "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"}.get(
                        extension, "application/octet-stream")
            flow.response = http.Response.make(
                200, payload, {"Content-Type": mime,
                "Content-Disposition": f'attachment; filename="review-{review_id}.{extension}"',
                "Cache-Control": "no-store"})
            return

    _start_gateway_metric(flow)

    content_type = req.headers.get(
        "content-type",
        "",
    )

    # ========================================================
    # ChatGPT 파일 업로드 경로 확인용 DEBUG
    #
    # 현재 웹 파일 업로드가 /backend-api/files/로 잡히지 않아
    # 실제 파일 바이트가 어느 POST 요청으로 들어오는지 확인한다.
    # 파일 내용 자체는 출력하지 않고 URL / Content-Type / 크기만 기록한다.
    # ========================================================
    if req.host == "chatgpt.com" and req.method == "POST":
        raw_body = req.raw_content or b""
        print("\n===== CHATGPT POST DEBUG =====")
        print("Path:", req.path)
        print("Content-Type:", content_type)
        print("Body size:", len(raw_body))

    # ========================================================
    # LLM Web Service 식별
    #
    # ChatGPT 웹서비스는 사용자 프롬프트가 포함된
    # /backend-api/f/conversation/prepare 요청을 별도로 파싱.
    # 그 외 LLM 웹서비스 요청은 현재 식별 후 통과.
    # ========================================================

    llm_service = service_for(req.host)
    identity = {}

    # Gemini 파일 업로드는 gemini.google.com이 아니라
    # push.clients6.google.com의 resumable upload로 들어오므로
    # LLM service 식별보다 먼저 처리한다.
    if req.host == "push.clients6.google.com":
        if handle_gemini_resumable_upload(flow, {}):
            return

    if llm_service:
        identity = read_and_strip_identity(flow)
        flow.metadata["llmsgw_identity"] = identity

        # Gemini 웹 요청 구조만 확인한다.
        # 현재 Detection / BLOCK / PASS 로직은 변경하지 않는다.
        if llm_service == "Gemini":
            debug_gemini_request_response(flow, "REQUEST")
            debug_gemini_flow_identity(flow)
            debug_gemini_assistant_path(flow)
            debug_gemini_request_structure(flow)
            debug_gemini_f_req_structure(flow)

            # Gemini 사용자 프롬프트 추출 및 Detection Module 전달
            blocked = detect_gemini_web(flow, identity)
            if blocked:
                return

        # ====================================================
        # Claude Web 사용자 프롬프트 Detection
        #
        # Claude Web의 completion 요청은
        # /api/organizations/{orgId}/chat_conversations/{convId}/completion
        # 형태의 JSON POST로 처리한다.
        # ====================================================
        if llm_service == "Claude":
            # ------------------------------------------------
            # Claude Web 파일 업로드 Detection
            # ------------------------------------------------
            # 실제 Claude Web의 파일 업로드 endpoint는 변경될 수 있으므로
            # 특정 path에 고정하지 않고 multipart/form-data + filename part를
            # 기준으로 파일 업로드를 식별한다.
            if _is_claude_multipart_file_upload(flow):
                blocked = detect_claude_file_upload(flow, identity)
                if blocked:
                    return

                # 파일 업로드 요청은 여기서 처리 종료.
                # 파일 원문을 추출하지 못한 경우에도 upstream으로 정상 전달한다.
                print("→ Claude Web file upload: PASS THROUGH")
                return

            # ------------------------------------------------
            # Claude Web 사용자 프롬프트 Detection
            # ------------------------------------------------
            blocked = detect_claude_web(flow, identity)
            if blocked:
                return

            # Claude completion 요청이면 여기서 처리를 끝낸다.
            # 다른 Claude 부수 요청까지 프롬프트 검사 대상으로 삼지 않는다.
            claude_path = req.path.split("?", 1)[0]
            if re.match(
                r"^/api/organizations/[^/]+/chat_conversations/[^/]+/completion$",
                claude_path,
            ):
                print("→ Claude Web prompt: PASS THROUGH")
                return

        print(
            "\n===== LLM WEB TRAFFIC DETECTED ====="
        )

        print(
            "Service:",
            llm_service,
        )

        print(
            "Host:",
            req.host,
        )

        print(
            "Method:",
            req.method,
        )

        print(
            "Path:",
            req.path,
        )

        # =================================================
        # ChatGPT Web 실제 파일 바이트 업로드
        # oaiusercontent.com /files/{file_id}/raw
        # =================================================
        raw_path = req.path.split("?", 1)[0]
        is_chatgpt_raw_upload = (
            req.method == "PUT"
            and req.host.endswith("oaiusercontent.com")
            and raw_path.startswith("/files/")
            and raw_path.endswith("/raw")
        )

        if is_chatgpt_raw_upload:
            file_id = _extract_chatgpt_raw_file_id(req.path)
            filename = CHATGPT_FILE_META.get(file_id) if file_id else None

            print("\n===== CHATGPT RAW FILE UPLOAD DETECTED =====")
            print("Host:", req.host)
            print("Method:", req.method)
            print("Path:", raw_path)
            print("File ID:", file_id)
            print("Content-Type:", req.headers.get("content-type", ""))
            print("Filename:", filename or "(metadata not resolved)")
            print("Body size:", len(req.raw_content or b""))

            if file_id and filename:
                event = create_chatgpt_raw_file_event(flow, file_id, filename)
                print_gateway_event(event)
                send_to_next_module(event)

                normalized_text = extract_file_checkable_text(event)

                if normalized_text:
                    print("\n===== FILE TEXT EXTRACTION SUCCESS =====")
                    print("Filename:", event["contents"][0].get("filename"))
                    print("Extracted text length:", len(normalized_text))
                    print("→ Sending extracted file text to Detection Module")

                    def detect_file_segment(segment, child_request_id):
                        return check_detection(
                            DETECTION_BASE_URL, request_id=child_request_id,
                            normalized_text=segment.text,
                            source={"service": "ChatGPT", "endpoint": raw_path,
                                    "content_type": "file", "filename": filename},
                        )
                    try:
                        outcome = sanitize_for_upload(
                            filename, req.raw_content or b"", event["request_id"], detect_file_segment
                        )
                        req.raw_content = outcome.sanitized_bytes
                        req.headers["content-length"] = str(len(req.raw_content))
                        flow.metadata["llmsgw_review_id"] = outcome.review_id
                        print(f"[SIGNATURE] sanitized raw upload review_id={outcome.review_id} elapsed_ms={outcome.elapsed_ms:.1f}")
                    except Exception as exc:
                        print("[SIGNATURE] raw file masking failed error_type=", type(exc).__name__)
                        flow.response = http.Response.make(503, b'{"error":{"type":"file_masking_failed"}}',
                                                           {"Content-Type": "application/json"})
                        return
                else:
                    print("\n===== FILE TEXT EXTRACTION FAILED =====")
                    print("→ Supported types: TXT / PDF / DOCX / XLSX")
                    print("→ No checkable text extracted")
                    print("→ File upload blocked because safe masking cannot be guaranteed")
                    flow.response = http.Response.make(503, b'{"error":{"type":"file_masking_failed"}}',
                                                       {"Content-Type": "application/json"})
            else:
                print("→ File metadata was not resolved; upload blocked")
                flow.response = http.Response.make(503, b'{"error":{"type":"file_masking_failed"}}',
                                                   {"Content-Type": "application/json"})

            return

        is_openai_api = (
            req.host == OPENAI_HOST
            and req.path in (
                OPENAI_RESPONSES_ENDPOINT,
                OPENAI_FILES_ENDPOINT,
            )
        )

        if not is_openai_api:
            # =================================================
            # ChatGPT Web 파일 업로드
            #
            # 실제 ChatGPT 웹에서는 OpenAI API의 /v1/files가 아니라
            # /backend-api/files/... 경로로 파일 업로드가 발생할 수 있다.
            # multipart/form-data인 경우 기존 파일 파서를 재사용하여
            # TXT / PDF / DOCX / XLSX의 텍스트를 추출하고 Detection에 전달한다.
            # =================================================

            web_path = req.path.split("?", 1)[0]
            is_chatgpt_file_upload = (
                llm_service == "ChatGPT"
                and web_path.startswith("/backend-api/files/")
            )

            if is_chatgpt_file_upload:
                if req.method == "POST" and content_type.startswith("application/json"):
                    _remember_chatgpt_file_metadata(flow)

                print("\n===== CHATGPT WEB FILE UPLOAD DETECTED =====")
                print("Host:", req.host)
                print("Method:", req.method)
                print("Path:", req.path)
                print("Content-Type:", content_type)

                if (
                    req.method == "POST"
                    and content_type.startswith("multipart/form-data")
                ):
                    event = create_file_event(flow)
                    event["service"] = "ChatGPT"

                    print_gateway_event(event)
                    send_to_next_module(event)

                    normalized_text = extract_file_checkable_text(event)

                    if normalized_text:
                        filename = (
                            (event.get("contents") or [{}])[0].get("filename")
                        )

                        print("\n===== FILE TEXT EXTRACTION SUCCESS =====")
                        print("Filename:", filename)
                        print("Extracted text length:", len(normalized_text))
                        print("→ Sending extracted file text to Detection Module")

                        file_info = extract_file_upload_info(flow)
                        def detect_file_segment(segment, child_request_id):
                            return check_detection(
                                DETECTION_BASE_URL, request_id=child_request_id,
                                normalized_text=segment.text,
                                source={"service": "ChatGPT", "endpoint": req.path,
                                        "content_type": "file", "filename": filename},
                            )
                        try:
                            outcome = sanitize_for_upload(
                                filename, file_info["file_bytes"], event["request_id"], detect_file_segment
                            )
                            req.raw_content = replace_multipart_file(req.raw_content or b"", content_type, outcome.sanitized_bytes)
                            req.headers["content-length"] = str(len(req.raw_content))
                            flow.metadata["llmsgw_review_id"] = outcome.review_id
                            print(f"[SIGNATURE] sanitized ChatGPT multipart review_id={outcome.review_id} elapsed_ms={outcome.elapsed_ms:.1f}")
                        except Exception as exc:
                            print("[SIGNATURE] ChatGPT multipart masking failed error_type=", type(exc).__name__)
                            flow.response = http.Response.make(503, b'{"error":{"type":"file_masking_failed"}}',
                                                               {"Content-Type": "application/json"})
                            return
                    else:
                        print("\n===== FILE TEXT EXTRACTION FAILED =====")
                        print("→ No checkable text extracted from uploaded file")
                        print("→ File upload blocked because safe masking cannot be guaranteed")
                        flow.response = http.Response.make(503, b'{"error":{"type":"file_masking_failed"}}',
                                                           {"Content-Type": "application/json"})

                    return

                # claim_and_finish 같은 웹 파일 API가 multipart가 아닐 경우
                # 해당 요청 자체에는 파일 원문이 없을 수 있으므로,
                # 일단 통과시키되 로그로 실제 Content-Type을 확인한다.
                print("→ ChatGPT file endpoint is not multipart/form-data")
                print("→ File bytes are not available in this request")
                print("→ PASS THROUGH")

                return

            # =================================================
            # 실제 ChatGPT 메시지 전송 요청만 사용자 프롬프트 추출
            # =================================================
            prompt = None

            if (
                llm_service == "ChatGPT"
                and web_path == "/backend-api/f/conversation"
            ):
                prompt = extract_chatgpt_prompt(flow)

            if prompt:
                result = detect_web_prompt(
                    flow,
                    llm_service,
                    prompt,
                )

                # Detection 결과에 따라 실제 BLOCK / PASS 집행
                if enforce_detection_result(
                    flow,
                    result,
                    dashboard_context={
                        "identity": identity,
                        "targetLlm": "ChatGPT",
                        "contentType": "prompt",
                    },
                    mask_callback=lambda detection_result: _apply_json_mask(
                        flow,
                        normalize_text(prompt),
                        detection_result,
                    ),
                ):
                    return
            else:
                print("→ User prompt not found in this request")
                print("→ LLM Web Traffic: PASS THROUGH")

            return

    # OpenAI API는 아래의 기존 상세 파싱 로직으로 처리
    # (나머지 LLM 웹서비스는 현재 여기서 통과)
    # ========================================================
    # 1. OpenAI File Upload
    # ========================================================

    if (
        req.host == OPENAI_HOST
        and req.method == "POST"
        and req.path == OPENAI_FILES_ENDPOINT
        and content_type.startswith(
            "multipart/form-data"
        )
    ):

        print(
            "\n===== OPENAI FILE UPLOAD DETECTED ====="
        )

        print(
            "Host:",
            req.host,
        )

        print(
            "Method:",
            req.method,
        )

        print(
            "Path:",
            req.path,
        )

        print(
            "Content-Type:",
            content_type,
        )

        # ----------------------------------------------------
        # File Event 생성
        # ----------------------------------------------------

        event = create_file_event(
            flow
        )

        print_gateway_event(
            event
        )

        # ----------------------------------------------------
        # 다음 모듈 전달
        # ----------------------------------------------------

        send_to_next_module(
            event
        )

        # ----------------------------------------------------
        # 파일에서 추출한 텍스트를 Detection Module에 직접 전달
        # ----------------------------------------------------

        normalized_text = extract_file_checkable_text(event)

        if normalized_text:
            filename = (
                (event.get("contents") or [{}])[0].get("filename")
            )

            print("\n===== FILE TEXT EXTRACTION SUCCESS =====")
            print("Filename:", filename)
            print("Extracted text length:", len(normalized_text))
            print("→ Sending extracted file text to Detection Module")

            file_info = extract_file_upload_info(flow)
            def detect_file_segment(segment, child_request_id):
                return check_detection(
                    DETECTION_BASE_URL, request_id=child_request_id,
                    normalized_text=segment.text,
                    source={"service": "OpenAI", "endpoint": req.path,
                            "content_type": "file", "filename": filename},
                )
            try:
                outcome = sanitize_for_upload(filename, file_info["file_bytes"], event["request_id"], detect_file_segment)
                req.raw_content = replace_multipart_file(req.raw_content or b"", content_type, outcome.sanitized_bytes)
                req.headers["content-length"] = str(len(req.raw_content))
                flow.metadata["llmsgw_review_id"] = outcome.review_id
                print(f"[SIGNATURE] sanitized multipart upload review_id={outcome.review_id} elapsed_ms={outcome.elapsed_ms:.1f}")
            except Exception as exc:
                print("[SIGNATURE] multipart file masking failed error_type=", type(exc).__name__)
                flow.response = http.Response.make(503, b'{"error":{"type":"file_masking_failed"}}',
                                                   {"Content-Type": "application/json"})
                return
        else:
            print("\n===== FILE TEXT EXTRACTION FAILED =====")
            print("→ No checkable text extracted from uploaded file")
            print("→ File upload blocked because safe masking cannot be guaranteed")
            flow.response = http.Response.make(503, b'{"error":{"type":"file_masking_failed"}}',
                                               {"Content-Type": "application/json"})

        return

    # ========================================================
    # 2. OpenAI Responses API
    # ========================================================

    if not (
        req.host == OPENAI_HOST
        and req.method == "POST"
        and req.path == OPENAI_RESPONSES_ENDPOINT
        and content_type.startswith(
            "application/json"
        )
    ):

        return

    print(
        "\n===== OPENAI REQUEST DETECTED ====="
    )

    print(
        "Host:",
        req.host,
    )

    print(
        "Method:",
        req.method,
    )

    print(
        "Path:",
        req.path,
    )

    print(
        "Content-Type:",
        content_type,
    )

    # --------------------------------------------------------
    # JSON Body 파싱
    # --------------------------------------------------------

    try:

        body = json.loads(
            req.get_text()
        )

    except (
        json.JSONDecodeError,
        TypeError,
    ):

        print(
            "❌ JSON parsing failed"
        )

        return

    # --------------------------------------------------------
    # Gateway Event 생성
    # --------------------------------------------------------

    event = create_responses_event(
        flow,
        body,
    )

    print_gateway_event(
        event
    )

    # --------------------------------------------------------
    # 다음 모듈 전달
    # --------------------------------------------------------

    send_to_next_module(
        event
    )

    # --------------------------------------------------------
    # 항목별로 따로 Detection에 보낸다 (2026-09-23)
    #
    # 프롬프트와 파일을 이어붙여 한 번에 보내면 창 해시가 어느 쪽에도 없는 창을 만들고,
    # 시그니처는 경계를 넘는 문맥 검사 때문에 없던 적중을 만들거나 있던 적중을 잃는다
    # (event_adapter 모듈 docstring에 실측 근거). 항목마다 한 번씩 부른다.
    #
    # 출처별 처리(파일은 차단, 프롬프트는 마스킹 등)는 아직 정하지 않았다. 지금은 옛 동작을
    # 그대로 유지한다 - 한 항목이라도 차단이면 요청 전체를 차단한다. 검사 순서도 항목 순서
    # 그대로다. 정책이 정해지면 이 루프 안에서 분기한다.
    # --------------------------------------------------------

    for part in checkable_parts(event):

        result = check_detection(
            DETECTION_BASE_URL,
            request_id=part_request_id(event["request_id"], part["index"]),
            normalized_text=part["text"],
            source={
                "service": event.get("service"),
                "content_type": part["kind"],
                "filename": part["filename"],
            },
        )

        print()
        print(
            f"===== DETECTION RESULT "
            f"[{part['kind']} #{part['index']}"
            f"{' ' + part['filename'] if part['filename'] else ''}] ====="
        )
        print_detection_summary(result)

        # Detection 결과에 따라 실제 BLOCK / PASS 집행
        if enforce_detection_result(
            flow,
            result,
            dashboard_context={
                "identity": identity,
                "targetLlm": "ChatGPT",
                "contentType": part["kind"],
            },
            mask_callback=lambda detection_result, part=part: _apply_json_mask(
                flow,
                part["text"],
                detection_result,
                body,
            ),
        ):
            return

def debug_gemini_streamgenerate_response(flow: http.HTTPFlow):
    """
    Gemini StreamGenerate 응답의 상태/헤더/크기만 안전하게 기록한다.
    응답 body 내용, 쿠키, 인증값, query string은 출력하지 않는다.
    """
    try:
        req = flow.request
        if req.host != "gemini.google.com" or req.method.upper() != "POST":
            return

        path = req.path.split("?", 1)[0]
        if "StreamGenerate" not in path:
            return

        resp = flow.response
        print("\n===== GEMINI STREAMGENERATE RESPONSE TRACE =====")
        print("Flow ID:", getattr(flow, "id", None))
        print("Status:", resp.status_code if resp is not None else "NONE")

        if resp is None:
            print("Response: NONE")
            print("===== END GEMINI STREAMGENERATE RESPONSE TRACE =====\n")
            return

        ctype = resp.headers.get("content-type", "")
        content_length = resp.headers.get("content-length", "")
        transfer_encoding = resp.headers.get("transfer-encoding", "")

        print("Content-Type:", ctype.split(";", 1)[0].strip())
        print("Content-Length header:", content_length or "<none>")
        print("Transfer-Encoding:", transfer_encoding or "<none>")
        print("Response body size:", len(resp.raw_content or b""))
        print("===== END GEMINI STREAMGENERATE RESPONSE TRACE =====\n")
    except Exception as exc:
        print("\n===== GEMINI STREAMGENERATE RESPONSE TRACE ERROR =====")
        print("Error type:", type(exc).__name__)
        print("===== END GEMINI STREAMGENERATE RESPONSE TRACE ERROR =====\n")


def response(flow: http.HTTPFlow):
    review_id = flow.metadata.get("llmsgw_review_id")
    if review_id and flow.response is not None:
        flow.response.headers["X-LLMSGW-Review-ID"] = review_id
        flow.response.headers["X-LLMSGW-Review-URL"] = f"http://llm-gateway.local/__llmsgw/review/{review_id}"
    debug_gemini_request_response(flow, "RESPONSE")
    debug_gemini_streamgenerate_response(flow)
    _finalize_gateway_metric(
        flow,
        action=flow.metadata.get("gw_action"),
        detector=flow.metadata.get("gw_detector"),
        degraded=flow.metadata.get("gw_degraded", False),
        error=False,
        timeout=False,
    )
    _send_deferred_dashboard_event(flow)


def error(flow: http.HTTPFlow):
    """Gemini flow의 실제 mitmproxy-level connection error만 안전하게 기록한다."""
    _finalize_gateway_metric(
        flow,
        action=flow.metadata.get("gw_action"),
        detector=flow.metadata.get("gw_detector"),
        degraded=flow.metadata.get("gw_degraded", False),
        error=True,
        timeout=_gateway_error_is_timeout(flow),
    )
    _send_deferred_dashboard_event(flow)
    try:
        req = flow.request
        if req.host != "gemini.google.com" or req.method.upper() != "POST":
            return

        path = req.path.split("?", 1)[0]
        if "StreamGenerate" not in path:
            return

        err = getattr(flow, "error", None)
        print("\n===== GEMINI STREAMGENERATE ERROR =====")
        print("Flow ID:", getattr(flow, "id", None))
        if err is None:
            print("Error: <none>")
        else:
            print("Error type:", type(err).__name__)
            print("Error message:", str(err)[:500])
        print("===== END GEMINI STREAMGENERATE ERROR =====\n")
    except Exception as exc:
        print("\n===== GEMINI STREAMGENERATE ERROR TRACE FAILED =====")
        print("Error type:", type(exc).__name__)
        print("===== END GEMINI STREAMGENERATE ERROR TRACE FAILED =====\n")
