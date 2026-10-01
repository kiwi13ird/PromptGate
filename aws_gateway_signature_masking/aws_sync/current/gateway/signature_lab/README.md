# Signature Detector

외부 LLM으로 보내기 전 텍스트와 DOCX에서 한국형 PII를 탐지하고 마스킹하는 실험 프로젝트입니다.

## 지원 PII

- `EMAIL_ADDRESS`
- `KR_PHONE_NUMBER`
- `KR_DATE_OF_BIRTH`
- `KR_RRN`
- `KR_FOREIGN_REGISTRATION_NUMBER`

## 구조

```text
signature_detector/       탐지·마스킹·문서 처리 라이브러리
tests/                    부작용 없는 단위 테스트
evaluation/
├── datasets/             Ground Truth JSON
├── fixtures/docx/        평가 입력 DOCX
├── generators/           fixture 생성기
├── evaluate_pii.py       텍스트 탐지 평가
├── run_docx_masking.py   복합 DOCX 마스킹 실행
└── evaluate_docx_masking.py
artifacts/sanitized/      생성된 sanitized DOCX
```

## 실행

모든 명령은 프로젝트 루트에서 실행합니다.

```bash
python -m unittest discover -s tests -v
python -m evaluation.evaluate_pii
python -m evaluation.run_docx_masking
python -m evaluation.evaluate_docx_masking
```

editable install 후에는 `pyproject.toml`에 정의된 CLI 명령도 사용할 수 있습니다.

```bash
python -m pip install -e .
evaluate-pii
mask-evaluation-docx
evaluate-docx-masking
```

## DOCX 범위

본문, 표, 중첩 표, 헤더, 푸터를 처리합니다. Text Box/Shape, OCR, 각주·미주·주석과 완전한 run formatting 보존은 아직 지원하지 않습니다.
