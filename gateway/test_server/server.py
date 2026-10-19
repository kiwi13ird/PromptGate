from collections import Counter
import json

from fastapi import FastAPI, Request

from signature_detector.analyzer import (
    TARGET_ENTITIES,
    create_analyzer,
)

app = FastAPI()

# 서버 시작 시 한 번만 생성
analyzer = create_analyzer()

REPLACEMENTS = {
    "EMAIL_ADDRESS": "[EMAIL_ADDRESS]",
    "KR_PHONE_NUMBER": "[PHONE_NUMBER]",
    "KR_DATE_OF_BIRTH": "[DATE_OF_BIRTH]",
    "KR_RRN": "[RRN]",
    "KR_FOREIGN_REGISTRATION_NUMBER": "[FOREIGN_RRN]",
}


def analyze_content(
    content_index: int,
    item: dict,
) -> list[dict]:
    """Gateway contents 항목 하나를 Signature Detector로 분석한다."""

    content_type = item.get("type")
    text = item.get("content")

    # 현재 Signature Detector는 prompt/file 텍스트만 처리
    if content_type not in {"prompt", "file"}:
        return []

    if not isinstance(text, str) or not text.strip():
        return []

    results = analyzer.analyze(
        text=text,
        language="en",
        entities=TARGET_ENTITIES,
    )

    detections = []

    for result in results:
        detections.append(
            {
                "content_index": content_index,
                "content_type": content_type,
                "filename": item.get("filename"),
                "entity_type": result.entity_type,
                "replacement": REPLACEMENTS.get(
                    result.entity_type,
                    f"[{result.entity_type}]",
                ),
                "start": result.start,
                "end": result.end,
                "score": round(float(result.score), 4),
            }
        )

    return detections


def decide_action(
    event: dict,
    detections: list[dict],
) -> tuple[str, str | None]:
    """현재 E2E 테스트용 단순 정책."""

    if not detections:
        return "ALLOW", None

    has_file_detection = any(
        detection["content_type"] == "file"
        for detection in detections
    )

    if has_file_detection:
        return "BLOCK", "FILE_SENSITIVE_DATA_BLOCK"

    return "MASK", "PROMPT_SENSITIVE_DATA_MASK"


def print_detection_result(
    event: dict,
    detections: list[dict],
    action: str,
    policy_id: str | None,
) -> None:
    """터미널에서 탐지 결과를 확인하기 위한 디버그 출력."""

    print("\n===== SIGNATURE DETECTION RESULT =====")
    print("Request ID:", event.get("request_id"))

    if not detections:
        print("Detected entities: NONE")
        print("\n===== POLICY DECISION =====")
        print("Policy: NONE")
        print("Action: ALLOW")
        return

    print("\nDetected entities:")

    for index, detection in enumerate(detections, start=1):
        print(f"\n[{index}]")
        print("Content Type:", detection["content_type"])

        if detection["filename"]:
            print("Filename:", detection["filename"])

        print("Entity:", detection["entity_type"])
        print("Replacement:", detection["replacement"])
        print("Start:", detection["start"])
        print("End:", detection["end"])
        print("Score:", detection["score"])

    counts = Counter(
        detection["entity_type"]
        for detection in detections
    )

    print("\n===== DETECTION SUMMARY =====")

    for entity_type, count in sorted(counts.items()):
        replacement = REPLACEMENTS.get(
            entity_type,
            f"[{entity_type}]",
        )
        print(
            f"{entity_type}: {count} "
            f"(replacement={replacement})"
        )

    print("Total:", len(detections))

    print("\n===== POLICY DECISION =====")
    print("Policy:", policy_id)
    print("Action:", action)


@app.post("/internal/gateway/events")
async def receive_gateway_event(request: Request):
    try:
        event = await request.json()
    except Exception:
        return {
            "status": "error",
            "error": "invalid_json",
        }

    print("\n===== GATEWAY EVENT RECEIVED =====")
    print(
        json.dumps(
            event,
            ensure_ascii=False,
            indent=2,
        )
    )

    detections = []

    for content_index, item in enumerate(
        event.get("contents", [])
    ):
        if not isinstance(item, dict):
            continue

        detections.extend(
            analyze_content(
                content_index=content_index,
                item=item,
            )
        )

    action, policy_id = decide_action(
        event=event,
        detections=detections,
    )

    print_detection_result(
        event=event,
        detections=detections,
        action=action,
        policy_id=policy_id,
    )

    return {
        "status": "analyzed",
        "request_id": event.get("request_id"),
        "action": action,
        "policy_id": policy_id,
        "detection_count": len(detections),
        "detections": detections,
    }


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "service": "signature-detector-test-server",
    }
