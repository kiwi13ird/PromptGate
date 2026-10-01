"""Apply Signature policy results without returning or logging matched values."""
from __future__ import annotations
from .engine import Hit

REPLACEMENTS = {
    "KR_RRN": "[KR_RRN]", "KR_FOREIGN_REGISTRATION_NUMBER": "[KR_FOREIGN_REGISTRATION_NUMBER]",
    "KR_PHONE_NUMBER": "[KR_PHONE_NUMBER]", "EMAIL_ADDRESS": "[EMAIL_ADDRESS]",
    "KR_DATE_OF_BIRTH": "[KR_DATE_OF_BIRTH]", "KR_BANK_ACCOUNT": "[KR_BANK_ACCOUNT]",
    "GITHUB_TOKEN": "[GITHUB_TOKEN]", "GENERIC_API_KEY": "[GENERIC_API_KEY]", "PASSWORD": "[PASSWORD]",
}

def _mask_digits(value: str, visible_prefix: int = 0, visible_suffix: int = 0) -> str:
    positions = [i for i, char in enumerate(value) if char.isdigit()]
    protected = set(positions[:visible_prefix] + (positions[-visible_suffix:] if visible_suffix else []))
    return "".join(char if i in protected or not char.isdigit() else "*" for i, char in enumerate(value))

def partial_replacement(entity_type: str, value: str) -> str:
    digits = sum(char.isdigit() for char in value)
    if entity_type == "KR_PHONE_NUMBER":
        return _mask_digits(value, visible_prefix=max(0, digits - 4))
    if entity_type in {"KR_RRN", "KR_FOREIGN_REGISTRATION_NUMBER"}:
        return _mask_digits(value, visible_prefix=6)
    if entity_type == "KR_BANK_ACCOUNT":
        return _mask_digits(value, visible_suffix=4)
    if entity_type == "KR_DATE_OF_BIRTH":
        return _mask_digits(value, visible_prefix=4)
    if entity_type == "EMAIL_ADDRESS" and "@" in value:
        local, domain = value.rsplit("@", 1)
        return local[:1] + "*" * max(1, len(local) - 1) + "@" + domain
    return REPLACEMENTS.get(entity_type, f"[{entity_type}]")

def apply(text: str, hits: list[Hit], actions: list[str]) -> tuple[str | None, list[dict]]:
    if len(hits) != len(actions):
        raise ValueError("Signature hit/action count mismatch")
    items = sorted(zip(hits, actions), key=lambda item: (item[0].start, item[0].end))
    previous_end = -1
    for hit, _ in items:
        if hit.start < previous_end or hit.start < 0 or hit.end <= hit.start or hit.end > len(text):
            raise ValueError("invalid or overlapping Signature span")
        previous_end = hit.end
    masked = text
    findings = []
    for hit, action in reversed(items):
        replacement = None
        if action == "MASK_FULL":
            replacement = REPLACEMENTS.get(hit.entity_type, f"[{hit.entity_type}]")
        elif action == "MASK_PARTIAL":
            replacement = partial_replacement(hit.entity_type, text[hit.start:hit.end])
        if replacement is not None:
            masked = masked[:hit.start] + replacement + masked[hit.end:]
        findings.append({"entity_type": hit.entity_type, "start": hit.start, "end": hit.end,
                         "score": hit.score, "policy_action": action.lower(), "replacement": replacement})
    findings.reverse()
    return (masked if masked != text else None), findings
