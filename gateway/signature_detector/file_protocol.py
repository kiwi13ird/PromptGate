"""Bounded JSON/SSE completion diagnostics; no response values or dynamic keys logged."""
import json


def matching_file_keys(candidates, registry):
    """Only exact IDs or explicit file_ / file- prefix aliases; no size guessing."""
    def canonical(value):
        for prefix in ('file_', 'file-'):
            if value.startswith(prefix):
                return value[len(prefix):]
        return value
    wanted = {canonical(i) for i in candidates if isinstance(i, str)}
    return [key for key in registry if canonical(key) in wanted]


def request_size_summary(data, registry, path_file_id=None):
    """Fixed-key diagnostics only; never return IDs, arbitrary keys or values."""
    sizes, ids = [], []
    upload_id_present = False

    def walk(value, depth=0):
        nonlocal upload_id_present
        if depth > 8:
            return
        if isinstance(value, dict):
            for key, child in list(value.items())[:64]:
                key = str(key).lower()
                if key == 'file_size' and type(child) is int and 0 <= child <= 2**53:
                    sizes.append(child)
                if key in {'file_id', 'fileid', 'id'} and isinstance(child, str):
                    ids.append(child.removeprefix('file_'))
                if key == 'upload_id':
                    upload_id_present = True
                walk(child, depth + 1)
        elif isinstance(value, list):
            for child in value[:64]:
                walk(child, depth + 1)
    walk(data)
    candidates = ([path_file_id] if path_file_id else []) + ids
    matches = matching_file_keys(candidates, registry)
    expected = sorted({registry[i] for i in matches})
    return {'file_sizes': sizes[:64], 'file_id_present': bool(candidates),
            'upload_id_present': upload_id_present, 'registry_match': bool(expected),
            'expected_sizes': expected[:64], 'matched_file_count': len(matches),
            'size_matches': (all(s == expected[0] for s in sizes)
                             if sizes and len(expected) == 1 else None)}


def completion_summary(text):
    if len(text) > 262144:
        return {'format': 'oversized', 'events': 0}
    values = []
    try:
        values.append(json.loads(text))
        kind = 'json'
    except (ValueError, TypeError):
        kind = 'sse'
        for block in text.replace('\r\n', '\n').split('\n\n')[:64]:
            payload = '\n'.join(line[5:].lstrip() for line in block.splitlines() if line.startswith('data:'))
            if not payload or payload == '[DONE]':
                continue
            try:
                values.append(json.loads(payload))
            except ValueError:
                pass
    statuses = []
    failures = 0
    allowed = {'failed', 'error', 'success', 'ready', 'complete', 'completed', 'processing', 'uploaded'}

    def walk(value, depth=0):
        nonlocal failures
        if depth > 8:
            return
        if isinstance(value, dict):
            for key, child in list(value.items())[:64]:
                if key in {'status', 'state', 'type'} and isinstance(child, str) and child in allowed:
                    statuses.append(child)
                if (key == 'success' and child is False) or (key == 'error' and bool(child)):
                    failures += 1
                walk(child, depth + 1)
        elif isinstance(value, list):
            for child in value[:64]:
                walk(child, depth + 1)
    for value in values:
        walk(value)
    return {'format': kind if values else 'unparsed', 'events': len(values),
            'states': sorted(set(statuses)), 'error_signals': failures}
