# preprocessing

사내망 상용 LLM 기밀정보 유출 방지 시스템의 전처리 모듈. 입력(자연어/PDF/DOCX/XLSX)을 받아
**파싱 → 정규화 → 위치 인덱싱**까지 수행하고, 탐지 모듈(FR-SIG/FR-HSH/FR-EMB, 아직 미구현)이
바로 스캔할 수 있는 단일 문자열(`normalized_text`)과, 탐지된 위치를 원문으로 되짚을 수 있는
인덱스(`IndexedDocument`)를 만들어 넘긴다.

## 상태

FR-PRE-001~005, 007, 008 구현 완료. FR-PRE-006(탐지 모듈로의 병렬 분배)은 하류에 실제 탐지
모듈이 아직 없어 미착수 — 이 모듈이 만드는 `ParsedDocument.normalized_text` /
`ParsedDocument.index`가 그 다음 단계의 입력 계약이다.

테스트 80개(`preprocessing/tests/`) 전부 통과. 개발 과정에서 실제 기밀문서 형태의 사내
테스트베드 문서 20종(이 저장소에는 미포함)을 대상으로 문자 단위 정확성(10,703개 조각 대조,
누락 0건)과 오프셋 왕복 정확성(371개 매치, 불일치 0건)을 검증했다.

## 라이선스 안내 — PDF 백엔드

`pdf_parser.py`는 현재 [PyMuPDF](https://pypi.org/project/PyMuPDF/)(fitz)를 쓴다. PyMuPDF는
**AGPL-3.0 또는 Artifex 상용 라이선스** 둘 중 하나로만 쓸 수 있어, 비공개 상용 제품에
그대로 넣으면 안 된다(자세한 이유는 `pdf_parser.py` 상단 주석 참고). 이 상태는 성능 비교를
위한 실험/데모 버전이고, 상용 배포용으로는 MIT 라이선스인 `pdfplumber`나 `pypdfium2`로
바꿔야 한다.

## 설치

```bash
pip install -r requirements.txt
```

## 빠른 시작

```python
from preprocessing import process_input

result = process_input("어떤 파일 경로 또는 그냥 문장")

result.success          # bool
result.format            # "text" | "pdf" | "docx" | "xlsx"
result.normalized_text   # 탐지 모듈에 넘길 최종 문자열
result.blocks             # list[Block] - 문단/표/제목 단위 원문+정규화 결과
result.index              # IndexedDocument | None - 탐지 매치를 원문 위치로 되짚는 인덱스
```

`process_input()`은 인자가 실제 존재하는 파일이면 **내용(매직바이트)** 으로 pdf/docx/xlsx를
가려 해당 파서를 태우고, 아니면 자연어 입력으로 보고 정규화만 수행한다 - 확장자를 보지 않는다
(파일 확장자는 위조 가능하므로 신뢰하지 않는다, FR-GW 경계 하드닝).

파일 형식을 이미 알고 있고 확장자를 신뢰할 수 있는 상황(직접 지정한 경로)이면
`parse_document()`를 대신 써도 된다. 문서가 아니라 순수 텍스트를 문서와 동일한
인터페이스로 감싸고 싶으면 `build_text_document(text)`를 쓴다.

## CLI 도구

`src/` 디렉터리에서 실행한다(`preprocessing`을 임포트 가능한 패키지로 인식시키기 위함).

```bash
cd src

# 자유 입력(자연어/PDF/DOCX/XLSX) 파싱+정규화 결과를 눈으로 확인
python -m preprocessing.cli "경로 또는 문장"
python -m preprocessing.cli "문서.pdf" --raw          # 정규화 전 원문도 같이 출력
python -m preprocessing.cli "문서.pdf" --json          # 결과를 JSON으로 출력
python -m preprocessing.cli "문서.pdf" --find "찾을 텍스트"  # FR-PRE-005 위치 인덱싱 결과 확인

# 자연어 정규화만 따로 확인/저장 (문서 파서를 거치지 않는 경로)
python -m preprocessing.normalize_cli --text "확인하고 싶은 문장"
python -m preprocessing.normalize_cli --file 텍스트파일.txt
python -m preprocessing.normalize_cli --demo   # 환경별(macOS/Windows/Notion 등) 정규화 동등성 검증
```

`normalize_cli.py`의 결과는 항상 `outputs/`에 저장된다 (`--out`으로 경로 지정 가능).

## 모듈 구조

| 파일 | 역할 |
|---|---|
| `router.py` | `process_input()` - 콘텐츠 기반 형식 감지 후 자연어/PDF/DOCX/XLSX로 라우팅 |
| `format_detect.py` | `detect_format()` - 매직바이트로 pdf/docx/xlsx/zip-unknown/binary-unknown 판별 |
| `pipeline.py` | `parse_document()`/`build_text_document()` - 파싱+정규화+인덱싱을 하나로 묶음. `Block`/`ParsedDocument` 자료구조 정의 |
| `pdf_parser.py` | FR-PRE-002. PyMuPDF(fitz) 기반(라이선스 안내 위 참고). 문단 재조립, 하이픈 개행 복원, 표 추출(`find_tables`) |
| `docx_parser.py` | FR-PRE-003. python-docx 기반. 문서 XML 순서를 그대로 따라가므로 PDF류의 좌표 기반 순서 문제가 구조적으로 없음 |
| `xlsx_parser.py` | FR-PRE-004. openpyxl 기반. 병합 셀로 "문단형 행"과 "표형 행"을 구분(하드코딩된 행 번호 아님). 큰 시트에서 `iter_rows()` 순차 순회 사용 (셀 단위 랜덤 접근은 수만 행에서 심각하게 느림 - 실측) |
| `normalizer.py` | FR-PRE-001. NFC 정규화, 공백/따옴표/대시/불릿 표준화, 제로폭·제어문자 제거. 서로 다른 환경(macOS/Windows/Notion)에서 만든 동일 내용이 동일하게 정규화됨을 보장 |
| `indexer.py` | FR-PRE-005. 블록별 원문↔정규화 오프셋 매핑(`build_offset_map`), 단어 인덱스, `IndexedDocument.locate(start, end)`로 탐지 매치를 원문 위치(페이지/섹션/셀/원문 오프셋/스니펫)로 역변환 |
| `errors.py` | `UnsupportedFormatError`/`DocumentParsingError`/`EncryptedDocumentError`/`CorruptedDocumentError` - 전부 예외를 던지지 않고 `ParsedDocument(success=False)`로 흡수됨(FR-PRE-007) |

## 출력 형식

```
ParsedDocument
├─ success: bool
├─ format: str
├─ blocks: list[Block]              # type(heading|paragraph|table|header|footer), raw_text, normalized_text, page, section 등
├─ normalized_text: str             # 탐지 모듈 입력 - 전체 블록을 이어붙인 최종 문자열
├─ index: IndexedDocument | None
│   └─ locate(start, end) -> DetectionLocation
│        (block_index, block_type, page, section, raw_start/end, raw_snippet, word_indices, cell)
└─ error_type / error_message       # success=False일 때만
```

탐지기는 `normalized_text` 하나만 보고 매치를 `(start, end)` 오프셋으로 돌려준다. 그 오프셋을
`index.locate()`에 넣으면 원문상 위치(페이지, 표 셀, 원문 오프셋)를 감사로그/알림용으로
되짚을 수 있다 - `blocks[].raw_text`나 `offset_map`은 탐지 단계에서는 전혀 쓰이지 않고, 매치가
나온 뒤 위치 역추적에만 쓰인다.

## 알려진 제한사항

- **스캔 이미지 PDF(텍스트 레이어 없음)는 이 모듈 범위 밖이다.** `parse_document()`/
  `process_input()`은 이런 파일에서 정상적으로 0블록을 반환한다(버그 아님). OCR은 별도
  파이프라인이 필요하며 아직 이 모듈에 통합돼 있지 않다.
- **벡터그래픽이 극단적으로 많은 PDF**(디자인 산출물 성격의 보고서 등)는 pdfplumber 기준
  페이지당 수 초씩 걸리는 문제가 있었다(실측: 137페이지 15분). PyMuPDF로 바꾼 뒤 같은 파일이
  34초로 줄었지만(약 27배), 이건 위 라이선스 안내와 맞바꾼 결과라는 점을 감안해야 한다.
- PDF 폰트 인코딩이 깨진 문서에서 일부 글리프가 복구 불가능하게 유실될 수 있다(정규화 단계에서
  제어문자로 걸러지긴 하지만 원래 글자를 되살릴 방법은 없음).

## 테스트

```bash
cd src && python -m pytest preprocessing/tests/ -q
```
