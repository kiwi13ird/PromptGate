from mitmproxy import http

import json
import uuid
import requests

from datetime import datetime, timezone
from io import BytesIO
from email.parser import BytesParser
from email.policy import default

from pypdf import PdfReader
from docx import Document
from openpyxl import load_workbook

from detection_client import check as check_detection
from event_adapter import extract_checkable_text

DETECTION_BASE_URL = "http://10.0.3.168:8000"


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
            "Body:",
            response.text,
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

    print(
        "\n===== GATEWAY EVENT ====="
    )

    print(
        json.dumps(
            event,
            ensure_ascii=False,
            indent=2,
        )
    )


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

    return "\n".join(prompts)


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
        },
    )

    print("\n===== WEB LLM PROMPT =====")
    print(prompt)

    print("\n===== DETECTION RESULT =====")
    print(result)

    return result



# ============================================================
# Detection 결과에 따른 BLOCK / PASS 집행
# ============================================================

def enforce_detection_result(
    flow: http.HTTPFlow,
    result,
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

    if action == "block":
        print("\n===== GATEWAY ACTION =====")
        print("→ BLOCK")
        print("Request ID:", request_id)
        print("Decided by:", getattr(result, "decided_by", None))
        print("Document:", getattr(result, "doc_id", None), getattr(result, "doc_span", None))
        print("Input span:", getattr(result, "input_span", None), "Score:", getattr(result, "score", None))
        print("PII hits:", getattr(result, "pii_hits", None))
        print("Reason:", getattr(result, "reason", None))

        flow.response = http.Response.make(
            getattr(result, "http_status", None) or 403,
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

        return True

    print("\n===== GATEWAY ACTION =====")
    if action == "allow_degraded":
        print("→ PASS (Detection 무응답 - 잠정 통과)")
        print("Request ID:", request_id)
    else:
        print("→ PASS")

    return False

# ============================================================
# mitmproxy Request Hook
# ============================================================

def request(
    flow: http.HTTPFlow,
):

    req = flow.request

    content_type = req.headers.get(
        "content-type",
        "",
    )

    # ========================================================
    # LLM Web Service 식별
    #
    # ChatGPT 웹서비스는 사용자 프롬프트가 포함된
    # /backend-api/f/conversation/prepare 요청을 별도로 파싱.
    # 그 외 LLM 웹서비스 요청은 현재 식별 후 통과.
    # ========================================================

    llm_service = service_for(req.host)

    if llm_service:
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

        is_openai_api = (
            req.host == OPENAI_HOST
            and req.path in (
                OPENAI_RESPONSES_ENDPOINT,
                OPENAI_FILES_ENDPOINT,
            )
        )

        if not is_openai_api:
            # =================================================
            # 실제 ChatGPT 메시지 전송 요청만 사용자 프롬프트 추출
            # =================================================
            prompt = None

            if (
                llm_service == "ChatGPT"
                and req.path.split("?", 1)[0]
                == "/backend-api/f/conversation"
            ):
                prompt = extract_chatgpt_prompt(flow)

            if prompt:
                result = detect_web_prompt(
                    flow,
                    llm_service,
                    prompt,
                )

                # Detection 결과에 따라 실제 BLOCK / PASS 집행
                if enforce_detection_result(flow, result):
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

    normalized_text = extract_checkable_text(event)
    if normalized_text:
        result = check_detection(
            DETECTION_BASE_URL,
            request_id=event["request_id"],
            normalized_text=normalized_text,
            source={"service": event.get("service")},
        )
        print("\n===== DETECTION RESULT =====")
        print(result)

        # Detection 결과에 따라 실제 BLOCK / PASS 집행
        if enforce_detection_result(flow, result):
            return
