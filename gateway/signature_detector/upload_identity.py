"""Bounded, transient ID relationship diagnostics. Never enforce or expose raw IDs/URLs."""
import json
import time
from urllib.parse import urlsplit
from signature_detector.file_protocol import matching_file_keys

FIELDS = frozenset({'id', 'file_id', 'fileid', 'upload_id', 'reservation_id',
                    'upload_reservation_id'})
URL_FIELDS = frozenset({'upload_url', 'url', 'signed_url'})


def identifiers(data):
    ids, raw_ids = {}, set()
    def walk(value, depth=0):
        if depth > 8:
            return
        if isinstance(value, dict):
            for key, child in list(value.items())[:64]:
                key = str(key).lower()
                if key in FIELDS and isinstance(child, str):
                    ids.setdefault(key, set()).add(child)
                if key in URL_FIELDS and isinstance(child, str):
                    try:
                        parts = urlsplit(child).path.strip('/').split('/')
                        if len(parts) == 3 and parts[0] == 'files' and parts[2] == 'raw':
                            raw_ids.add(parts[1])
                    except ValueError:
                        pass
                walk(child, depth + 1)
        elif isinstance(value, list):
            for child in value[:64]:
                walk(child, depth + 1)
    walk(data)
    return ids, raw_ids


class IdentityDiagnostic:
    def __init__(self, clock=time.monotonic):
        self.records = {}
        self.clock = clock

    def _expire(self):
        now = self.clock()
        self.records = {k: v for k, v in self.records.items() if now - v[0] < 600}

    def remember(self, scope, text):
        self._expire()
        if len(text) > 262144:
            return {'parsed': False, 'reason': 'oversized'}
        try:
            data = json.loads(text)
        except (ValueError, TypeError):
            return {'parsed': False, 'reason': 'not_json'}
        ids, raw_ids = identifiers(data)
        stored = len(raw_ids) == 1 and bool(ids)
        if stored:
            key = (scope, next(iter(raw_ids)))
            self.records[key] = (self.clock(), ids)
            while len(self.records) > 256:
                del self.records[next(iter(self.records))]
        return {'parsed': True, 'id_fields': sorted(ids),
                'raw_url_count': len(raw_ids), 'relationship_recorded': stored}

    def compare(self, scope, body, registry, path_id=None):
        self._expire()
        ids, _ = identifiers(body)
        candidates = {v for values in ids.values() for v in values}
        if path_id:
            candidates.add(path_id)
        fields, raw_matches = set(), 0
        for (record_scope, raw_id), (_, response_ids) in self.records.items():
            if record_scope != scope or raw_id not in registry:
                continue
            matching = {field for field, values in response_ids.items()
                        if matching_file_keys(candidates, dict.fromkeys(values))}
            if matching:
                fields.update(matching)
                raw_matches += 1
        return {'creation_records': sum(k[0] == scope for k in self.records),
                'completion_id_fields': sorted(ids),
                'creation_matching_fields': sorted(fields),
                'linked_raw_upload_count': raw_matches}

    def resolve_reservation(self, scope, path_id, registry):
        """Resolve only a unique server-issued reservation -> raw upload relation."""
        self._expire()
        if not scope or not path_id:
            return None
        matches = []
        for (record_scope, raw_id), (_, response_ids) in self.records.items():
            reservations = response_ids.get('reservation_id', set()) | response_ids.get('upload_reservation_id', set())
            if (record_scope == scope and raw_id in registry
                    and matching_file_keys([path_id], dict.fromkeys(reservations))):
                matches.append(raw_id)
        return matches[0] if len(matches) == 1 else None
