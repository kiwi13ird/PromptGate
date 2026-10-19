"""PDF 가림 시험용 합성 PDF(가짜 값만). 함수마다 (PDF 바이트, 넣은 가짜 값 목록, 남아야 할 일반 낱말 목록)을 돌려준다.

한글은 PyMuPDF 내장 CJK 글꼴(Droid Sans Fallback)을 Type0/Identity-H(CID 글꼴)로 넣는다 - 서버에도 같은 글꼴이 있다.
"""

from __future__ import annotations

import fitz

RRN = "900101-1234567"
RRN2 = "850315-2345678"
PHONE = "010-1234-5678"
PHONE2 = "010-9876-5432"
EMAIL = "hong.gildong@example.com"
EMAIL2 = "kim.cs@example.org"
PASSWORD = "Hunter2024!x"
KEEP = ["품질관리팀", "정기점검", "회의록", "Quarterly", "Review"]

_CJK = None


def _font_buffer() -> bytes:
    global _CJK
    if _CJK is None:
        _CJK = fitz.Font("cjk").buffer
    return _CJK


def new_page(doc, width=595, height=842):
    page = doc.new_page(width=width, height=height)
    page.insert_font(fontname="kr", fontbuffer=_font_buffer())
    return page


def put(page, xy, text, size=11, **kw):
    page.insert_text(xy, text, fontname=kw.pop("fontname", "kr"), fontsize=size, **kw)


def finish(doc, *, subset=True) -> bytes:
    if subset:
        doc.subset_fonts()
    return doc.tobytes(garbage=3, deflate=True)


def plain():
    doc = fitz.open()
    page = new_page(doc)
    lines = ["인사기록 요약 (가상 데이터) 품질관리팀",
             f"성명 홍길동 주민등록번호 {RRN} 연락처 {PHONE}",
             f"이메일 {EMAIL} 로 회신 바랍니다.",
             "정기점검 회의록 Quarterly Review 일정 공유",
             "비고: 연봉 협상 결과는 별도 문서로 통보합니다."]
    for i, line in enumerate(lines):
        put(page, (60, 80 + 22 * i), line)
    return finish(doc), [RRN, PHONE, EMAIL], KEEP


def clean_doc():
    doc = fitz.open()
    page = new_page(doc)
    for i, line in enumerate(["주간 회의 메모 품질관리팀", "정기점검 회의록 Quarterly Review", "개인정보 없음"]):
        put(page, (60, 80 + 22 * i), line)
    return finish(doc), [], KEEP


def table():
    doc = fitz.open()
    page = new_page(doc)
    put(page, (60, 60), "고객 명단 (가상 데이터) 품질관리팀 정기점검", 13)
    rows = [["이름", "주민등록번호", "연락처", "이메일"],
            ["홍길동", RRN, PHONE, EMAIL],
            ["김철수", RRN2, PHONE2, EMAIL2]]
    widths = [70, 120, 110, 190]
    for r, row in enumerate(rows):
        x = 50
        for c, cell in enumerate(row):
            rect = fitz.Rect(x, 90 + r * 24, x + widths[c], 90 + (r + 1) * 24)
            page.draw_rect(rect, color=(0, 0, 0), width=0.6)
            put(page, (x + 4, rect.y1 - 7), cell, 10)
            x += widths[c]
    put(page, (60, 200), "회의록 Quarterly Review 외부 반출 금지", 10)
    return finish(doc), [RRN, RRN2, PHONE, PHONE2, EMAIL, EMAIL2], KEEP


def multipage(n=30, lines_per_page=25):
    doc = fitz.open()
    values = set()
    for i in range(n):
        page = new_page(doc)
        put(page, (60, 60), f"{i + 1}쪽 상담 기록 (가상) 품질관리팀", 13)
        for k in range(lines_per_page):
            if k == 5:
                line = f"상담자 연락처 {PHONE if i % 2 else PHONE2} 주민등록번호 {RRN if i % 2 else RRN2}"
                values.update({PHONE if i % 2 else PHONE2, RRN if i % 2 else RRN2})
            elif k == 12:
                line = f"회신 메일: {EMAIL}"
                values.add(EMAIL)
            else:
                line = f"상담 내용 {k}: 정기점검 회의록 Quarterly Review 사항을 담당 부서에 전달함."
            put(page, (60, 90 + 26 * k), line, 10)
    return finish(doc), sorted(values), KEEP


def tight_lines(pitch=9.0):
    """줄 간격(9pt)이 글자 상자 높이(약 14pt)보다 좁다 - 지우는 상자가 이웃 줄을 건드리면 안 된다."""
    doc = fitz.open()
    page = new_page(doc)
    texts = ["위 줄 정기점검 회의록 ABCDEFGHIJKLMNOP", f"값 줄 주민 {RRN} 끝", "아래 줄 품질관리팀 Quarterly Review QRSTUVWX"]
    for i, t in enumerate(texts):
        put(page, (60, 100 + pitch * i), t)
    return finish(doc), [RRN], KEEP + ["ABCDEFGHIJKLMNOP", "QRSTUVWX"]


def rotated_page(rotation=90):
    doc = fitz.open()
    page = new_page(doc)
    put(page, (60, 100), f"회전 쪽 주민등록번호 {RRN} 품질관리팀")
    put(page, (60, 130), f"메일 {EMAIL} 정기점검 회의록")
    page.set_rotation(rotation)
    return finish(doc), [RRN, EMAIL], ["품질관리팀", "정기점검", "회의록"]


def rotated_text():
    doc = fitz.open()
    page = new_page(doc)
    put(page, (300, 500), f"세로 글자 {PHONE} 품질관리팀", rotate=90)
    put(page, (60, 80), "가로 글자 정기점검 회의록")
    return finish(doc), [PHONE], ["품질관리팀", "정기점검", "회의록"]


def hidden_text():
    """보이지 않는 글자 층(OCR 글자처럼 render_mode 3) - 추출·검사·지우기 대상이다."""
    doc = fitz.open()
    page = new_page(doc)
    put(page, (60, 80), "보이는 글자 정기점검 회의록")
    put(page, (60, 110), f"숨은 글자 {EMAIL} {RRN}", render_mode=3)
    return finish(doc), [EMAIL, RRN], ["정기점검", "회의록"]


def line_split():
    """값이 줄바꿈으로 나뉨 - 쪽 판정은 못 잡고 공백 뺀 재검사가 잡는다(→ residual)."""
    doc = fitz.open()
    page = new_page(doc)
    put(page, (60, 80), "줄바꿈 분리: 주민등록번호 900101-")
    put(page, (60, 98), "1234567 를 확인하세요. 정기점검")
    return finish(doc), [RRN], ["정기점검"]


def letter_spaced():
    """글자마다 따로 찍은 값(자간) - 추출 글자에 공백이 끼면 쪽 판정이 못 잡는다(→ residual)."""
    doc = fitz.open()
    page = new_page(doc)
    put(page, (60, 80), "자간 확대 정기점검")
    x = 60
    for ch in PHONE:
        put(page, (x, 110), ch)
        x += 14
    return finish(doc), [PHONE], ["정기점검"]


def en_dash():
    doc = fitz.open()
    page = new_page(doc)
    put(page, (60, 80), f"대시 문자 주민 {RRN.replace('-', chr(0x2013))} 정기점검 회의록")
    return finish(doc), [RRN.replace("-", chr(0x2013))], ["정기점검", "회의록"]


def annotations_and_form():
    """주석 Contents·FreeText·양식 칸 값에 가짜 값, 쪽 본문에도 값 하나."""
    doc = fitz.open()
    page = new_page(doc)
    put(page, (60, 80), f"본문 연락처 {PHONE} 정기점검 회의록")
    note = page.add_text_annot((300, 300), f"메모 주민번호 {RRN}")
    note.update()
    free = page.add_freetext_annot(fitz.Rect(60, 400, 400, 430), f"자유 글 {EMAIL}", fontsize=10)
    free.update()
    widget = fitz.Widget()
    widget.field_type = fitz.PDF_WIDGET_TYPE_TEXT
    widget.field_name = "contact"
    widget.rect = fitz.Rect(60, 500, 300, 520)
    widget.field_value = PHONE2
    page.add_widget(widget)
    page.insert_link({"kind": fitz.LINK_URI, "from": fitz.Rect(60, 600, 200, 620), "uri": f"mailto:{EMAIL2}"})
    return finish(doc, subset=False), [PHONE, RRN, EMAIL, PHONE2, EMAIL2], ["정기점검", "회의록"]


def document_level():
    """책갈피·정보 사전·태그 구조(/ActualText·/Alt)·계층 양식 상위 칸 /V·쪽 이름·이름 목록에 가짜 값(명세 §1.3 실험과 같은 자리)."""
    doc = fitz.open()
    page = new_page(doc)
    put(page, (60, 100), f"본문 주민번호 {RRN} 정기점검 회의록")
    page2 = new_page(doc)
    put(page2, (60, 100), "둘째 쪽 품질관리팀")
    page = doc[0]  # 쪽을 더하면 앞서 받은 쪽 객체는 버려진다
    widget = fitz.Widget()
    widget.field_type = fitz.PDF_WIDGET_TYPE_TEXT
    widget.field_name = "kid"
    widget.rect = fitz.Rect(72, 200, 300, 220)
    widget.field_value = RRN
    page.add_widget(widget)
    wx = [w.xref for w in page.widgets()][0]
    parent = doc.get_new_xref()
    doc.update_object(parent, f"<< /T (holder) /FT /Tx /V <FEFF{RRN.encode('utf-16-be').hex().upper()}> /Kids [{wx} 0 R] >>")
    doc.xref_set_key(wx, "Parent", f"{parent} 0 R")
    acro = doc.xref_get_key(doc.pdf_catalog(), "AcroForm")
    if acro[0] == "xref":
        doc.xref_set_key(int(acro[1].split()[0]), "Fields", f"[{parent} 0 R]")
    else:
        doc.xref_set_key(doc.pdf_catalog(), "AcroForm/Fields", f"[{parent} 0 R]")
    elem, root = doc.get_new_xref(), doc.get_new_xref()
    doc.update_object(elem, f"<< /Type /StructElem /S /P /P {root} 0 R /ActualText ({RRN}) /Alt <{EMAIL.encode().hex()}> >>")
    doc.update_object(root, f"<< /Type /StructTreeRoot /K [{elem} 0 R] >>")
    cat = doc.pdf_catalog()
    doc.xref_set_key(cat, "StructTreeRoot", f"{root} 0 R")
    doc.xref_set_key(cat, "MarkInfo", "<< /Marked true >>")
    doc.xref_set_key(cat, "PageLabels", f"<< /Nums [0 << /S /D /P ({RRN} ) >>] >>")
    doc.xref_set_key(cat, "Names", f"<< /Dests << /Names [({EMAIL}) [{page.xref} 0 R /Fit]] >> >>")
    doc.set_toc([[1, f"담당 {RRN}", 1], [1, f"메일 {EMAIL}", 2]])
    doc.set_metadata({"author": f"작성 {PHONE}", "title": f"제목 {EMAIL}", "subject": RRN, "keywords": PHONE})
    doc.set_xml_metadata(f"<x:xmpmeta xmlns:x='adobe:ns:meta/'><dc>{RRN}</dc></x:xmpmeta>")
    return doc.tobytes(garbage=1, deflate=True), [RRN, EMAIL, PHONE], ["정기점검", "회의록", "품질관리팀"]


def shared_header(pages=3):
    """여러 쪽이 공유하는 Form XObject 머리글에 값. 모든 쪽에서 지워져야 한다."""
    src = fitz.open()
    header = new_page(src, 595, 60)
    put(header, (40, 40), f"머리글 담당 연락처 {PHONE} 품질관리팀")
    src_bytes = src.tobytes()
    src = fitz.open(stream=src_bytes, filetype="pdf")
    doc = fitz.open()
    for i in range(pages):
        page = new_page(doc)
        page.show_pdf_page(fitz.Rect(0, 0, 595, 60), src, 0)
        put(page, (60, 200), f"{i + 1}쪽 본문 정기점검 회의록")
    return finish(doc), [PHONE], ["품질관리팀", "정기점검", "회의록"]


def off_page():
    """CropBox 밖(MediaBox 안) 글자와 쪽 밖 글자 - 보이지 않지만 추출된다."""
    doc = fitz.open()
    page = new_page(doc)
    put(page, (60, 100), f"잘린 쪽 위 주민 {RRN}")
    put(page, (700, 300), f"쪽 밖 {EMAIL}")
    put(page, (60, 400), "보이는 글자 정기점검 회의록")
    page.set_cropbox(fitz.Rect(0, 200, 595, 842))
    return finish(doc), [RRN, EMAIL], ["정기점검", "회의록"]


def password_label():
    """이름표에 기대는 값(비밀번호:) - 값만 지우면 이름표가 다음 줄 낱말을 값으로 잡는다(명세 §6-7)."""
    doc = fitz.open()
    page = new_page(doc)
    put(page, (60, 80), "서버 접속 정보 정기점검")
    put(page, (60, 100), f"비밀번호: {PASSWORD}")
    put(page, (60, 120), "Database 서버 이름은 별도 문서 회의록")
    return finish(doc), [PASSWORD], ["정기점검", "Database", "회의록"]


def actual_text(where: str):
    """ActualText 표시 글자. where='hidden' 값이 ActualText에만 / 'shown' 값이 글리프에만(ActualText는 다른 글)."""
    doc = fitz.open()
    page = doc.new_page()
    page.insert_text((72, 100), "seed", fontname="helv", fontsize=11)
    name = page.get_fonts()[0][4]
    if where == "hidden":
        body = f"BT /{name} 11 Tf 72 700 Td /Span <</ActualText ({RRN})>> BDC (plain words) Tj EMC ET"
    else:
        body = f"BT /{name} 11 Tf 72 700 Td /Span <</ActualText (nothing here)>> BDC (shown {RRN}) Tj EMC ET"
    body += f"\nBT /{name} 11 Tf 72 650 Td (Quarterly Review) Tj ET\n"
    doc.update_stream(page.get_contents()[0], body.encode("latin-1"))
    return doc.tobytes(garbage=1, deflate=True), [RRN], ["Quarterly", "Review"]


def scanned():
    data, _, _ = plain()
    src = fitz.open(stream=data, filetype="pdf")
    pix = src[0].get_pixmap(dpi=60)
    doc = fitz.open()
    page = doc.new_page()
    page.insert_image(page.rect, pixmap=pix)
    return doc.tobytes(garbage=3, deflate=True), [], []


def encrypted(user_password: bool):
    data, values, keep = plain()
    src = fitz.open(stream=data, filetype="pdf")
    kw = dict(encryption=fitz.PDF_ENCRYPT_AES_256, owner_pw="owner-fake-pw", permissions=fitz.PDF_PERM_PRINT)
    kw["user_pw"] = "user-fake-pw" if user_password else ""
    return src.tobytes(**kw), values, keep


def helvetica_simple():
    """단순 글꼴(WinAnsi, 내용 스트림에 글자가 그대로) - 지운 뒤 내용 스트림에 값이 남지 않아야 한다."""
    doc = fitz.open()
    page = doc.new_page()
    page.insert_text((72, 100), f"Contact {EMAIL} phone {PHONE} Quarterly Review", fontname="helv", fontsize=11)
    return doc.tobytes(garbage=1), [EMAIL, PHONE], ["Quarterly", "Review"]


def big(pages: int, lines_per_page=40):
    """성능 표용 - 쪽마다 값 2개."""
    return multipage(pages, lines_per_page)
