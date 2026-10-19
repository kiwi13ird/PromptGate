"""Administrator-authenticated review links; never include document or prompt data."""
import os
from urllib.parse import quote, urlsplit


def request_review_url(request_id):
    if not isinstance(request_id, str) or not request_id or len(request_id) > 200:
        return None
    base = os.getenv('DASHBOARD_REVIEW_BASE_URL', 'http://52.79.153.42').rstrip('/')
    try:
        parsed = urlsplit(base)
        if (parsed.scheme not in {'http', 'https'} or not parsed.hostname
                or parsed.username or parsed.password or parsed.query or parsed.fragment
                or any(char.isspace() or ord(char) < 32 for char in base)):
            return None
        parsed.port  # Reject invalid ports, without exposing configuration values.
    except ValueError:
        return None
    return base + '/requests/' + quote(request_id, safe='')
