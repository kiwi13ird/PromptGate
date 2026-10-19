"""Conservative label-bound PII detection; offsets always belong to value text."""
import re
from dataclasses import dataclass

LABELS = {
    'KR_BANK_ACCOUNT': ('계좌번호', '급여계좌', '급여계좌번호', '변경 전 계좌번호', '변경 후 계좌번호', '입금계좌', '계좌', 'account number', 'bank account'),
    'KR_ADDRESS': ('주소', '주소(요약)', '거주지', '거주지 주소', '연락 주소', '자택주소', '배송주소', '도로명주소', 'address'),
    'KR_POSTAL_CODE': ('우편번호', 'postal code', 'zip code', 'zipcode'),
    'KR_DATE_OF_BIRTH': ('생년월일', '생일', '출생일', 'date of birth', 'dob'),
    'PASSWORD': ('비밀번호', '임시 비밀번호', 'password', 'passwd', 'pwd', 'db_password', 'database_password'),
    'GENERIC_API_KEY': ('API 키', 'api_key', 'apikey', 'api key', 'x-api-key', 'access_key', 'access key', 'client_secret', 'client secret'),
}

# Only these entities have supplemental value recognizers here. Other labels
# are transported to Detection, which reuses its existing recognizers.
VALUE_ENTITIES = {'KR_BANK_ACCOUNT', 'KR_ADDRESS', 'KR_POSTAL_CODE'}


def canonical_label(value):
    value = re.sub(r'\s+', '', value or '').strip(':：= ').casefold()
    for entity, labels in LABELS.items():
        if value == entity.casefold():
            return entity
        if any(value == re.sub(r'\s+', '', label).casefold() for label in labels):
            return entity
    return None


@dataclass(frozen=True)
class ContextHit:
    entity_type: str
    start: int
    end: int
    score: float = 0.9


def query_contextual(text, context=None):
    """Inline explicit labels or a verified neighboring table label; no global number matching."""
    hits = []
    windows = []
    entity = canonical_label(context or '')
    if entity in VALUE_ENTITIES:
        windows.append((entity, 0, len(text)))
    for entity, labels in LABELS.items():
        if entity not in VALUE_ENTITIES:
            continue
        label_pattern = '|'.join(re.escape(label) for label in sorted(labels, key=len, reverse=True))
        delimiter = r'\s*[:：=]\s*'
        if entity == 'KR_BANK_ACCOUNT':
            # Explicit account label followed directly by a value or bank name.
            # Do not treat unrelated prose after a bare label as account context.
            delimiter += r'|\s+(?=(?:[가-힣]{1,12}(?:은행|뱅크)\s+)?[0-9]{2,8}(?:-|[0-9]))'
        pattern = re.compile(rf'(?<![\w])(?:{label_pattern})(?:{delimiter})', re.I)
        for match in pattern.finditer(text):
            end_match = re.search(r'[\n\t;；|]', text[match.end():])
            end = match.end() + end_match.start() if end_match else len(text)
            # Stop before another labeled field on the same line.
            boundary_labels = [label for group in LABELS.values() for label in group]
            boundary_labels += ['전화번호', '휴대전화', '이메일', '성명', '사번']
            boundaries = '|'.join(re.escape(label) for label in sorted(boundary_labels, key=len, reverse=True))
            next_field = re.search(rf'\s+(?:{boundaries})\s*[:：=]', text[match.end():end], re.I)
            if next_field:
                end = match.end() + next_field.start()
            windows.append((entity, match.end(), end))
    for entity, start, end in windows:
        value = text[start:end]
        if entity == 'KR_BANK_ACCOUNT':
            for match in re.finditer(r'(?<![\w-])(?:[0-9]{2,8}(?:-[0-9]{2,8}){1,3}|[0-9]{10,16})(?![0-9A-Za-z_-])', value):
                if 10 <= sum(c.isdigit() for c in match.group()) <= 16:
                    hits.append(ContextHit(entity, start + match.start(), start + match.end()))
        elif entity == 'KR_POSTAL_CODE':
            for match in re.finditer(r'(?<!\w)[0-9]{5}(?!\w)', value):
                hits.append(ContextHit(entity, start + match.start(), start + match.end()))
        else:
            left = len(value) - len(value.lstrip())
            candidate = value.strip()
            # Require Korean address structure, not arbitrary prose following 'address'.
            region = re.match(r'(?:서울|부산|대구|인천|광주|대전|울산|세종|경기|강원|충청|전라|경상|제주|충북|충남|전북|전남|경북|경남)[가-힣]*\s', candidate)
            location = re.search(r'[가-힣0-9·]+(?:로|길|동|읍|면|리)\s*[0-9]+(?:-[0-9]+)?', candidate)
            # Administrative summary addresses have no building/lot number.
            # Require region + district + neighborhood and the entire value,
            # rather than accepting arbitrary text ending in 동.
            summary = re.fullmatch(
                r'(?:서울|부산|대구|인천|광주|대전|울산|세종|경기|강원|충청|전라|경상|제주|충북|충남|전북|전남|경북|경남)[가-힣]*\s+'
                r'(?:[가-힣]+시\s+)?[가-힣]+(?:구|군)(?:\s+[가-힣0-9·]+(?:동|읍|면|리))?', candidate)
            if region and (location or summary) and len(candidate) <= 250:
                hits.append(ContextHit(entity, start + left, start + left + len(candidate)))
    unique = {(h.start, h.end, h.entity_type): h for h in hits}
    return sorted(unique.values(), key=lambda h: (h.start, h.end))


def merge_contextual_hits(text, hits, context=None):
    existing = list(hits)
    for new in query_contextual(text, context):
        if not any(new.start < old.end and new.end > old.start for old in existing):
            existing.append(new)
    return sorted(existing, key=lambda h: (h.start, h.end))
