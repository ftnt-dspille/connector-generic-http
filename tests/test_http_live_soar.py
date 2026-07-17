"""Live tests against a real FortiSOAR appliance.

These exercise the HTTP connector against real /api/3/* endpoints to validate
that the connector handles actual FSR JSON-LD responses, pagination, file
downloads, attachment IRIs, and the Authorization: API-KEY scheme.

Enable with:
    RUN_SOAR_LIVE_TESTS=1 pytest tests/test_http_live_soar.py -v

Credentials are read from a .env file at the repo root (BASE_URL + API_KEY),
or the BASE_URL / API_KEY environment variables.

These tests are READ-ONLY — they do not POST, PUT, PATCH, or DELETE anything.
"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
ENV_FILE = REPO_ROOT / '.env'

SOAR_LIVE = bool(os.environ.get('RUN_SOAR_LIVE_TESTS'))


def _read_env_file(path: Path) -> dict:
    """Tiny .env parser — picks up uncommented KEY=VALUE lines, strips quotes."""
    out = {}
    if not path.is_file():
        return out
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith('#') or '=' not in line:
            continue
        key, _, val = line.partition('=')
        key = key.strip()
        val = val.strip().strip('"').strip("'")
        if key and key not in out:
            out[key] = val
    return out


_env = _read_env_file(ENV_FILE)
BASE_URL = os.environ.get('BASE_URL') or _env.get('BASE_URL', '').rstrip('/')
API_KEY = os.environ.get('API_KEY') or _env.get('API_KEY', '')

pytestmark = pytest.mark.skipif(
    not (SOAR_LIVE and BASE_URL and API_KEY),
    reason='set RUN_SOAR_LIVE_TESTS=1 and provide BASE_URL + API_KEY (.env or env vars)',
)


@pytest.fixture
def ops(load_connector):
    mod = load_connector('generic-http')
    mod._OAUTH_TOKEN_CACHE.clear()
    return mod


@pytest.fixture
def soar_tmp_dir(monkeypatch):
    """Point TMP_FILE_ROOT at a real tmpdir so download_file can write here."""
    django_conf = sys.modules['django.conf']
    tmp_root = tempfile.mkdtemp(prefix='soar_live_tests_')

    class _Settings:
        TMP_FILE_ROOT = tmp_root
        def __getattr__(self, item):
            return None

    monkeypatch.setattr(django_conf, 'settings', _Settings(), raising=False)
    return tmp_root


def _soar_config(**overrides):
    """FortiSOAR uses 'Authorization: API-KEY <key>' — modeled as API Key Header
    auth with header name 'Authorization' and value 'API-KEY <key>'."""
    cfg = {
        'server_url': BASE_URL,
        'auth_type': 'API Key Header',
        'api_key_header_name': 'Authorization',
        'api_key': f'API-KEY {API_KEY}',
        'verify_ssl': True,
        'timeout': 60,
        'return_on_error': True,
        'default_headers': {'Accept': 'application/json'},
    }
    cfg.update(overrides)
    return cfg


# ---------------------------------------------------------------------------
# Sanity: connection / auth
# ---------------------------------------------------------------------------

def test_soar_health_check(ops):
    """check_health() pings the base URL; FSR returns its UI HTML at /."""
    assert ops.check_health(_soar_config()) is True


def test_soar_get_picklist_names(ops):
    """/api/3/picklist_names is a small read-only endpoint that proves auth works
    and that the connector parses JSON-LD wrapped responses cleanly."""
    result = ops.http_get(_soar_config(), {'rest_api': '/api/3/picklist_names'})
    assert result['status_code'] == 200
    body = result['body']
    # JSON-LD shape: hydra:member is the list of records.
    members = body.get('hydra:member') or body.get('member') or []
    assert isinstance(members, list)
    assert len(members) > 0
    # Each picklist name has @type Picklist (or similar).
    first = members[0]
    assert '@id' in first or 'name' in first


# ---------------------------------------------------------------------------
# Attachments
# ---------------------------------------------------------------------------

def test_soar_list_attachments(ops):
    result = ops.http_get(
        _soar_config(),
        {'rest_api': '/api/3/attachments',
         'parameter': {'$limit': '5'}},
    )
    assert result['status_code'] == 200
    body = result['body']
    members = body.get('hydra:member') or []
    assert isinstance(members, list)
    # The endpoint exists; it may be empty in a brand-new tenant.
    if members:
        att = members[0]
        assert att['@type'] == 'Attachment'
        assert att['@id'].startswith('/api/3/attachments/')
        assert 'file' in att  # the nested File sub-record


def test_soar_get_single_attachment_then_dereference_file(ops, soar_tmp_dir):
    """End-to-end: list attachments → pick one → dereference its @id via the
    same path _resolve_attachment_to_path() would take from a playbook."""
    listing = ops.http_get(
        _soar_config(),
        {'rest_api': '/api/3/attachments', 'parameter': {'$limit': '1'}},
    )
    members = (listing['body'].get('hydra:member') or [])
    if not members:
        pytest.skip('no attachments in this tenant')
    iri = members[0]['@id']
    # GET the attachment by IRI — this is the same call _resolve_attachment_to_path
    # makes internally when given an /api/3/attachments/<uuid> IRI.
    one = ops.http_get(_soar_config(), {'rest_api': iri})
    assert one['status_code'] == 200
    body = one['body']
    assert body['@id'] == iri
    file_obj = body.get('file')
    assert isinstance(file_obj, dict)
    assert file_obj.get('@id', '').startswith('/api/3/files/')
    assert isinstance(file_obj.get('filename'), str)


def test_soar_list_files(ops):
    result = ops.http_get(
        _soar_config(),
        {'rest_api': '/api/3/files', 'parameter': {'$limit': '3'}},
    )
    assert result['status_code'] == 200
    members = result['body'].get('hydra:member') or []
    if members:
        f = members[0]
        assert f['@type'] == 'File'
        assert f['@id'].startswith('/api/3/files/')
        assert 'filename' in f and 'size' in f


# ---------------------------------------------------------------------------
# Pagination against real FSR
# ---------------------------------------------------------------------------

def test_soar_paginate_attachments_via_page_param(ops):
    """FSR supports $limit + $page query params. The page_param mode walks them."""
    result = ops.http_paginate(_soar_config(), {
        'rest_api': '/api/3/attachments',
        'pagination_mode': 'page_param',
        'page_param_name': '$page',
        'items_path': 'hydra:member',
        'parameter': {'$limit': '5'},
        'max_pages': 3,
    })
    assert isinstance(result['items'], list)
    # Each item is a real Attachment with @id and @type.
    for item in result['items']:
        assert item.get('@type') == 'Attachment'
        assert item.get('@id', '').startswith('/api/3/attachments/')


def test_soar_fetch_records_shape(ops):
    """fetch_records is what scheduled ingestion uses — verify it plucks hydra:member."""
    result = ops.fetch_records(_soar_config(), {
        'fetch_url': '/api/3/picklist_names',
        'response_path': 'hydra:member',
    })
    assert result['count'] > 0
    assert isinstance(result['records'], list)


# ---------------------------------------------------------------------------
# Real download — pull file bytes off the appliance via /api/3/files/<uuid>/download
# ---------------------------------------------------------------------------

def test_soar_download_real_file(ops, soar_tmp_dir):
    """Find a small attachment, hit its file's download endpoint, save to disk.
    create_attachment=False because we're off-appliance — but the GET path,
    Content-Disposition handling, and on-disk write all exercise real bytes."""
    listing = ops.http_get(
        _soar_config(),
        {'rest_api': '/api/3/attachments', 'parameter': {'$limit': '10'}},
    )
    members = listing['body'].get('hydra:member') or []
    # Pick the smallest file so we don't slurp a huge CSV.
    candidates = [
        m for m in members
        if isinstance(m.get('file'), dict) and isinstance(m['file'].get('size'), (int, float))
    ]
    if not candidates:
        pytest.skip('no attachments with a sized file to download')
    candidates.sort(key=lambda m: m['file']['size'])
    target = candidates[0]
    file_iri = target['file']['@id']

    # FSR file-download endpoint = <file IRI>/download. The connector follows
    # the redirect (or streams the body directly, depending on appliance version).
    result = ops.download_file(_soar_config(), {
        'rest_api': f'{file_iri}/download',
        'create_attachment': False,
    })
    assert result['status_code'] == 200
    assert result['downloaded']['bytes'] == target['file']['size'] or \
           result['downloaded']['bytes'] > 0  # some FSR versions stream re-encoded
    assert os.path.exists(result['downloaded']['file_path'])


# ---------------------------------------------------------------------------
# Authorization scheme verification
# ---------------------------------------------------------------------------

def test_soar_unauthenticated_returns_401(ops):
    """Strip auth → should get a 401 back (since return_on_error is true)."""
    cfg = {
        'server_url': BASE_URL,
        'auth_type': 'None',
        'verify_ssl': True,
        'timeout': 30,
        'return_on_error': True,
    }
    result = ops.http_get(cfg, {'rest_api': '/api/3/picklist_names'})
    assert result['status_code'] in (401, 403)
