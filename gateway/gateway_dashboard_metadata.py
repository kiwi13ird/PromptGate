"""Opt-in extended event metadata; never copy request/response bodies.

The legacy ingest schema rejects unknown fields. Enable only after the receiver
has explicitly accepted the extended schema, independently of enforcement.
"""
import math
import os
import re


def _number(value):
    return type(value) in (int, float) and math.isfinite(value)


def attach_metadata(event, result, context, metrics):
    if os.getenv('DASHBOARD_EXTENDED_METADATA', '0') != '1':
        return
    detection = {}
    # Only well-defined identifiers/coordinates and numeric metadata, not free text.
    for name in ('coverage', 'similarity', 'confidence'):
        value = getattr(result, name, None)
        if _number(value):
            detection[name] = value
    for name in ('doc_span', 'input_span'):
        value = getattr(result, name, None)
        if isinstance(value, str) and re.fullmatch(r'\d+-\d+', value):
            detection[name] = value
    for name in ('doc_id', 'policy_version'):
        value = getattr(result, name, None)
        if type(value) is int or (isinstance(value, str) and re.fullmatch(r'[\w.-]{1,200}', value)):
            detection[name] = value
    if getattr(result, 'reason_code', None) in ('none', 'pii', 'doc_excerpt'):
        detection['reason_code'] = result.reason_code
    safe_metrics = {key: value for key, value in metrics.items() if key in {
        'active_clients', 'concurrent_requests', 'requests_per_sec', 'avg_latency_ms',
        'p95_latency_ms', 'timeout_rate', 'degraded_rate', 'total_requests',
        'completed_requests', 'error_requests', 'window_seconds'} and _number(value)}
    event['gateway'] = {
        'request_id': event.get('requestId'),
        'action': getattr(result, 'action', None),
        'detector': getattr(result, 'decided_by', None),
        'degraded': bool(getattr(result, 'degraded', False)),
        'enforcement_applied': bool(event.get('enforcement', {}).get('applied', False)),
        'content_type': context.get('contentType'),
        'metrics': safe_metrics, 'detection': detection,
    }
    if event.get('policyVersion') is not None:
        event['gateway']['policy_version'] = event['policyVersion']


def finalize_metadata(event, latency_ms, http_status):
    metadata = event.get('gateway')
    if not isinstance(metadata, dict):
        return
    if _number(latency_ms):
        metadata['latency_ms'] = latency_ms
    if type(http_status) is int and 100 <= http_status <= 599:
        metadata['http_status'] = http_status
