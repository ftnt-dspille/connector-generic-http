"""Tests for the generic HTTP connector v2.0.3.

Layout:
- Mock tests (default): use requests-mock and runtime stubs for FortiSOAR
  helpers (download_file_from_cyops, upload_file_to_cyops, make_cyops_request).
- Live tests (opt-in via RUN_LIVE_TESTS=1): hit real public endpoints
  (httpbin.org) and the local filesystem. SOAR-internal helpers are still
  stubbed since we can't run those off-appliance.
"""

import os
import sys
import tempfile
import types
from base64 import b64encode

import pytest
from connectors.core.connector import ConnectorError

LIVE = bool(os.environ.get('RUN_LIVE_TESTS'))


@pytest.fixture
def ops(load_connector):
    # Reset the OAuth token cache between tests.
    mod = load_connector('generic-http')
    mod._OAUTH_TOKEN_CACHE.clear()
    return mod


@pytest.fixture
def soar_stubs(monkeypatch):
    """Install in-test stubs for the FortiSOAR runtime helpers that
    ``upload_file`` / ``download_file`` lazy-import. Tests can read/replace
    the captured kwargs via ``soar_stubs.calls``.
    """
    calls = {'download': [], 'upload': [], 'crudhub': []}

    # connectors.cyops_utilities.builtins — already stubbed for the package,
    # but we extend it with the symbols the new ops touch.
    builtins_mod = sys.modules['connectors.cyops_utilities.builtins']

    def _download(iri, *a, **k):
        calls['download'].append({'iri': iri, 'args': a, 'kwargs': k})
        # Return basename only — operations.py joins it against TMP_FILE_ROOT.
        return {'cyops_file_path': 'stub_payload.bin', 'filename': 'stub_payload.bin'}

    def _upload(file_path, filename, create_attachment=False, name=None, description=None):
        calls['upload'].append({
            'file_path': file_path, 'filename': filename,
            'create_attachment': create_attachment, 'name': name, 'description': description,
        })
        return {
            '@id': '/api/3/attachments/stub-uuid', 'name': name or filename,
            'file': {'@id': '/api/3/files/stub-file-uuid', 'filename': filename},
        }

    monkeypatch.setattr(builtins_mod, 'download_file_from_cyops', _download, raising=False)
    monkeypatch.setattr(builtins_mod, 'upload_file_to_cyops', _upload, raising=False)

    # connectors.cyops_utilities.crudhub — not in default conftest.
    crudhub_mod = sys.modules.get('connectors.cyops_utilities.crudhub')
    if crudhub_mod is None:
        crudhub_mod = types.ModuleType('connectors.cyops_utilities.crudhub')
        sys.modules['connectors.cyops_utilities.crudhub'] = crudhub_mod

    def _make_cyops_request(iri, method='GET', *a, **k):
        calls['crudhub'].append({'iri': iri, 'method': method})
        # Default response: an attachment record pointing at a file.
        if '/attachments/' in iri:
            return {
                '@id': iri,
                'file': {'@id': '/api/3/files/resolved-file-uuid', 'filename': 'resolved.bin'},
            }
        return {}

    monkeypatch.setattr(crudhub_mod, 'make_cyops_request', _make_cyops_request, raising=False)

    # Point TMP_FILE_ROOT at a real tempdir so file-on-disk lookups succeed.
    django_conf = sys.modules['django.conf']
    tmp_root = tempfile.mkdtemp(prefix='http_conn_tests_')

    class _Settings:
        TMP_FILE_ROOT = tmp_root
        def __getattr__(self, item):
            return None

    monkeypatch.setattr(django_conf, 'settings', _Settings(), raising=False)
    calls['tmp_root'] = tmp_root
    return calls


def _config(**overrides):
    base = {
        'server_url': 'https://api.example.com',
        'auth_type': 'None',
        'verify_ssl': False,
        'timeout': 30,
        'return_on_error': True,
    }
    base.update(overrides)
    return base


# ---------- url + body helpers ----------

def test_resolve_url_relative(ops):
    assert ops._resolve_url(_config(), '/v1/things') == 'https://api.example.com/v1/things'


def test_resolve_url_absolute_overrides_base(ops):
    assert ops._resolve_url(_config(), 'https://other.example.com/x') == 'https://other.example.com/x'


def test_resolve_url_no_base_requires_absolute(ops):
    with pytest.raises(Exception) as exc:
        ops._resolve_url(_config(server_url=''), '/v1')
    assert 'No Server URL' in str(exc.value)


def test_to_dict_accepts_dict_and_json_string(ops):
    assert ops._to_dict({'a': 1}) == {'a': 1}
    assert ops._to_dict('{"a":1}') == {'a': 1}
    assert ops._to_dict('') == {}
    assert ops._to_dict(None) == {}
    with pytest.raises(ConnectorError):
        ops._to_dict('not json')


def test_pluck_dot_path(ops):
    obj = {'data': {'results': [{'id': 7}, {'id': 8}]}}
    assert ops._pluck(obj, 'data.results[0].id') == 7
    assert ops._pluck(obj, 'data.results[1].id') == 8
    assert ops._pluck(obj, 'data.missing') is None
    assert ops._pluck(obj, '') is obj


# ---------- auth ----------

def test_auth_none_attaches_nothing(ops, requests_mock):
    requests_mock.get('https://api.example.com/v1/x', json={}, status_code=200)
    ops.http_get(_config(), {'rest_api': '/v1/x'})
    assert 'Authorization' not in requests_mock.last_request.headers


def test_basic_auth(ops, requests_mock):
    requests_mock.get('https://api.example.com/v1/x', json={}, status_code=200)
    ops.http_get(_config(auth_type='Basic', basic_username='alice', basic_password='pw'),
                 {'rest_api': '/v1/x'})
    expected = 'Basic ' + b64encode(b'alice:pw').decode()
    assert requests_mock.last_request.headers['Authorization'] == expected


def test_bearer_auth(ops, requests_mock):
    requests_mock.get('https://api.example.com/v1/x', json={}, status_code=200)
    ops.http_get(_config(auth_type='Bearer Token', bearer_token='tok'), {'rest_api': '/v1/x'})
    assert requests_mock.last_request.headers['Authorization'] == 'Bearer tok'


def test_api_key_header_auth(ops, requests_mock):
    requests_mock.get('https://api.example.com/v1/x', json={}, status_code=200)
    ops.http_get(_config(auth_type='API Key Header',
                         api_key_header_name='X-API-Key', api_key='abc'), {'rest_api': '/v1/x'})
    assert requests_mock.last_request.headers['X-API-Key'] == 'abc'


def test_api_key_query_param_auth(ops, requests_mock):
    requests_mock.get('https://api.example.com/v1/x', json={}, status_code=200)
    ops.http_get(_config(auth_type='API Key Query Param',
                         api_key_param_name='api_key', api_key='abc'), {'rest_api': '/v1/x'})
    assert requests_mock.last_request.qs['api_key'] == ['abc']


def test_oauth2_client_credentials_caches_token(ops, requests_mock):
    requests_mock.post('https://idp.example.com/token',
                       json={'access_token': 'oauth-tok', 'expires_in': 3600},
                       status_code=200)
    requests_mock.get('https://api.example.com/v1/a', json={}, status_code=200)
    requests_mock.get('https://api.example.com/v1/b', json={}, status_code=200)

    cfg = _config(auth_type='OAuth2 Client Credentials',
                  oauth_token_url='https://idp.example.com/token',
                  oauth_client_id='cid', oauth_client_secret='secret')

    ops.http_get(cfg, {'rest_api': '/v1/a'})
    ops.http_get(cfg, {'rest_api': '/v1/b'})

    # Token endpoint hit exactly once thanks to the cache.
    token_calls = [r for r in requests_mock.request_history if r.url.endswith('/token')]
    assert len(token_calls) == 1
    api_calls = [r for r in requests_mock.request_history if '/v1/' in r.path]
    for r in api_calls:
        assert r.headers['Authorization'] == 'Bearer oauth-tok'


def test_per_call_auth_param_is_ignored(ops, requests_mock):
    """v2.0.3 removed per-call auth override — connection-level auth always wins."""
    requests_mock.get('https://api.example.com/v1/x', json={}, status_code=200)
    cfg = _config(auth_type='Bearer Token', bearer_token='global')
    ops.http_get(cfg, {
        'rest_api': '/v1/x',
        'auth_type': 'Bearer Token',
        'bearer_token': 'override',  # noise — should be ignored
    })
    assert requests_mock.last_request.headers['Authorization'] == 'Bearer global'


def test_token_login_logs_in_then_uses_token(ops, requests_mock):
    """Token Login: POST creds → extract token at login_token_path → send on subsequent calls."""
    requests_mock.post('https://api.example.com/auth/login',
                       json={'access_token': 'login-tok'}, status_code=200)
    requests_mock.get('https://api.example.com/v1/a', json={}, status_code=200)
    requests_mock.get('https://api.example.com/v1/b', json={}, status_code=200)

    cfg = _config(
        auth_type='Token Login',
        login_url='/auth/login',
        login_username='u', login_password='p',
        login_token_path='access_token',
        login_header_name='Authorization',
        login_header_prefix='Bearer ',
    )
    ops.http_get(cfg, {'rest_api': '/v1/a'})
    ops.http_get(cfg, {'rest_api': '/v1/b'})

    login_calls = [r for r in requests_mock.request_history if r.path == '/auth/login']
    # Token Login intentionally re-authenticates on every call (no token cache).
    assert len(login_calls) == 2
    assert login_calls[0].json() == {'username': 'u', 'password': 'p'}
    api_calls = [r for r in requests_mock.request_history if r.path.startswith('/v1/')]
    for r in api_calls:
        assert r.headers['Authorization'] == 'Bearer login-tok'


def test_token_login_plain_body_token(ops, requests_mock):
    """filebrowser-style: login response body IS the bare token, no JSON path."""
    requests_mock.post('https://api.example.com/api/login', text='raw-token-string',
                       status_code=200, headers={'Content-Type': 'text/plain'})
    requests_mock.get('https://api.example.com/v1/x', json={}, status_code=200)

    cfg = _config(auth_type='Token Login',
                  login_url='/api/login', login_username='u', login_password='p',
                  login_token_path='', login_header_name='X-Auth')
    ops.http_get(cfg, {'rest_api': '/v1/x'})
    assert requests_mock.last_request.headers['X-Auth'] == 'raw-token-string'


def test_token_login_header_only(ops, requests_mock):
    """Yeti-style: login POST sends no body, credentials go in login_request_headers only.
    The returned access_token is then sent on subsequent API calls as Bearer."""
    requests_mock.post(
        'https://yeti.example.com:16007/api/v2/auth/api-token',
        json={'access_token': 'yeti-jwt-abc123'},
        status_code=200,
    )
    requests_mock.get('https://yeti.example.com:16007/api/v2/observables/', json=[], status_code=200)

    api_key = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test'
    cfg = _config(
        server_url='https://yeti.example.com:16007/api/v2',
        auth_type='Token Login',
        login_body_type='header_only',
        login_url='https://yeti.example.com:16007/api/v2/auth/api-token',
        login_request_headers='{"x-yeti-apikey": "' + api_key + '"}',
        login_token_path='access_token',
        login_header_name='Authorization',
        login_header_prefix='Bearer ',
        verify_ssl=False,
    )
    ops.http_get(cfg, {'rest_api': 'https://yeti.example.com:16007/api/v2/observables/'})

    login_req = requests_mock.request_history[0]
    # Login POST must carry the API key header and send no body.
    assert login_req.headers['x-yeti-apikey'] == api_key
    assert login_req.body is None

    api_req = requests_mock.request_history[1]
    assert api_req.headers['Authorization'] == 'Bearer yeti-jwt-abc123'


def test_token_login_header_only_missing_headers_raises(ops):
    """header_only with no login_request_headers should raise a clear error."""
    import pytest as _pytest
    from connectors.core.connector import ConnectorError
    cfg = _config(
        auth_type='Token Login',
        login_body_type='header_only',
        login_url='/auth/api-token',
    )
    with _pytest.raises(ConnectorError, match='login_request_headers'):
        ops._token_login(cfg)


# ---------- default custom headers ----------

def test_default_headers_merged_into_request(ops, requests_mock):
    requests_mock.get('https://api.example.com/v1/x', json={}, status_code=200)
    ops.http_get(_config(default_headers={'X-Tenant': 'acme', 'User-Agent': 'FortiSOAR'}),
                 {'rest_api': '/v1/x'})
    h = requests_mock.last_request.headers
    assert h['X-Tenant'] == 'acme'
    assert h['User-Agent'] == 'FortiSOAR'


def test_per_call_header_overrides_default(ops, requests_mock):
    requests_mock.get('https://api.example.com/v1/x', json={}, status_code=200)
    ops.http_get(_config(default_headers={'X-Tenant': 'global'}),
                 {'rest_api': '/v1/x', 'header': {'X-Tenant': 'per-call'}})
    assert requests_mock.last_request.headers['X-Tenant'] == 'per-call'


# ---------- response parsing ----------

def test_json_response_parsed(ops, requests_mock):
    requests_mock.get('https://api.example.com/v1/x', json={'a': 1}, status_code=200,
                      headers={'Content-Type': 'application/json'})
    result = ops.http_get(_config(), {'rest_api': '/v1/x'})
    assert result['status_code'] == 200
    assert result['body'] == {'a': 1}


def test_text_response_returned_as_string(ops, requests_mock):
    requests_mock.get('https://api.example.com/v1/x', text='hello world', status_code=200,
                      headers={'Content-Type': 'text/plain'})
    result = ops.http_get(_config(), {'rest_api': '/v1/x'})
    assert result['body'] == 'hello world'


def test_binary_response_base64_envelope(ops, requests_mock):
    requests_mock.get('https://api.example.com/v1/x', content=b'\x00\x01\x02',
                      status_code=200, headers={'Content-Type': 'application/octet-stream'})
    result = ops.http_get(_config(), {'rest_api': '/v1/x'})
    assert result['body']['_binary'] is True
    assert result['body']['content_base64'] == b64encode(b'\x00\x01\x02').decode()


def test_response_path_plucks_subfield(ops, requests_mock):
    requests_mock.get('https://api.example.com/v1/x',
                      json={'data': {'results': [{'id': 7}]}}, status_code=200,
                      headers={'Content-Type': 'application/json'})
    result = ops.http_get(_config(), {'rest_api': '/v1/x', 'response_path': 'data.results[0].id'})
    assert result['body'] == 7


def test_raw_response_returns_base64_envelope(ops, requests_mock):
    requests_mock.get('https://api.example.com/v1/x', content=b'abc',
                      status_code=200, headers={'Content-Type': 'application/json'})
    result = ops.http_get(_config(), {'rest_api': '/v1/x', 'raw_response': True})
    assert result['content_base64'] == b64encode(b'abc').decode()


# ---------- bodies ----------

def test_post_json_body(ops, requests_mock):
    requests_mock.post('https://api.example.com/v1/x', json={}, status_code=200)
    ops.http_post(_config(), {'rest_api': '/v1/x', 'body_type': 'json', 'data': {'a': 1}})
    req = requests_mock.last_request
    assert req.json() == {'a': 1}
    assert req.headers['Content-Type'] == 'application/json'


def test_post_form_body(ops, requests_mock):
    requests_mock.post('https://api.example.com/v1/x', json={}, status_code=200)
    ops.http_post(_config(), {'rest_api': '/v1/x', 'body_type': 'form', 'data': {'a': '1', 'b': '2'}})
    assert requests_mock.last_request.text == 'a=1&b=2'


def test_post_raw_body(ops, requests_mock):
    requests_mock.post('https://api.example.com/v1/x', json={}, status_code=200)
    ops.http_post(_config(), {'rest_api': '/v1/x', 'body_type': 'raw', 'data': 'hello'})
    assert requests_mock.last_request.text == 'hello'


def test_invalid_json_body_raises(ops):
    with pytest.raises(Exception) as exc:
        ops._prepare_body('json', 'not-json')
    assert 'valid JSON' in str(exc.value)


# ---------- pagination ----------

def test_paginate_link_header(ops, requests_mock):
    requests_mock.get(
        'https://api.example.com/v1/items',
        [
            {'json': {'data': [{'id': 1}, {'id': 2}]}, 'status_code': 200,
             'headers': {'Content-Type': 'application/json',
                         'Link': '<https://api.example.com/v1/items?page=2>; rel="next"'}},
        ],
    )
    requests_mock.get(
        'https://api.example.com/v1/items?page=2',
        [
            {'json': {'data': [{'id': 3}]}, 'status_code': 200,
             'headers': {'Content-Type': 'application/json'}},
        ],
    )
    result = ops.http_paginate(_config(), {
        'rest_api': '/v1/items', 'pagination_mode': 'link_header', 'items_path': 'data',
    })
    assert [i['id'] for i in result['items']] == [1, 2, 3]
    assert result['pages_fetched'] == 2


def test_paginate_next_url_path(ops, requests_mock):
    requests_mock.get('https://api.example.com/v1/items',
                      json={'data': [{'id': 1}], 'links': {'next': 'https://api.example.com/v1/items?p=2'}},
                      status_code=200, headers={'Content-Type': 'application/json'})
    requests_mock.get('https://api.example.com/v1/items?p=2',
                      json={'data': [{'id': 2}], 'links': {'next': None}},
                      status_code=200, headers={'Content-Type': 'application/json'})
    result = ops.http_paginate(_config(), {
        'rest_api': '/v1/items', 'pagination_mode': 'next_url_path',
        'items_path': 'data', 'next_url_path': 'links.next',
    })
    assert [i['id'] for i in result['items']] == [1, 2]


def test_paginate_page_param_terminates_on_empty(ops, requests_mock):
    requests_mock.get('https://api.example.com/v1/items', [
        {'json': {'data': [{'id': 1}]}, 'status_code': 200, 'headers': {'Content-Type': 'application/json'}},
        {'json': {'data': []}, 'status_code': 200, 'headers': {'Content-Type': 'application/json'}},
    ])
    result = ops.http_paginate(_config(), {
        'rest_api': '/v1/items', 'pagination_mode': 'page_param',
        'items_path': 'data', 'page_param_name': 'page',
    })
    assert [i['id'] for i in result['items']] == [1]
    assert result['pages_fetched'] == 2


def test_paginate_max_pages_caps_walk(ops, requests_mock):
    # Always returns a "next" link → walk would loop forever without the max_pages cap.
    requests_mock.get('https://api.example.com/v1/items',
                      json={'data': [{'id': 1}]}, status_code=200,
                      headers={'Content-Type': 'application/json',
                               'Link': '<https://api.example.com/v1/items?p=2>; rel="next"'})
    requests_mock.get('https://api.example.com/v1/items?p=2',
                      json={'data': [{'id': 2}]}, status_code=200,
                      headers={'Content-Type': 'application/json',
                               'Link': '<https://api.example.com/v1/items?p=3>; rel="next"'})
    requests_mock.get('https://api.example.com/v1/items?p=3',
                      json={'data': [{'id': 3}]}, status_code=200,
                      headers={'Content-Type': 'application/json',
                               'Link': '<https://api.example.com/v1/items?p=4>; rel="next"'})
    result = ops.http_paginate(_config(), {
        'rest_api': '/v1/items', 'pagination_mode': 'link_header',
        'items_path': 'data', 'max_pages': 2,
    })
    assert result['pages_fetched'] == 2
    assert result['truncated'] is True


# ---------- ingestion ----------

def test_fetch_records_returns_list(ops, requests_mock):
    requests_mock.get('https://api.example.com/v1/alerts',
                      json={'results': [{'id': 1}, {'id': 2}]}, status_code=200,
                      headers={'Content-Type': 'application/json'})
    result = ops.fetch_records(_config(), {'fetch_url': '/v1/alerts', 'response_path': 'results'})
    assert result['count'] == 2


def test_fetch_records_wraps_single_object(ops, requests_mock):
    requests_mock.get('https://api.example.com/v1/x',
                      json={'id': 1, 'name': 'x'}, status_code=200,
                      headers={'Content-Type': 'application/json'})
    result = ops.fetch_records(_config(), {'fetch_url': '/v1/x'})
    assert result['count'] == 1


# ---------- error / retry ----------

def test_return_on_error_true_returns_status(ops, requests_mock):
    requests_mock.get('https://api.example.com/v1/x', status_code=500, text='boom',
                      headers={'Content-Type': 'text/plain'})
    result = ops.http_get(_config(return_on_error=True), {'rest_api': '/v1/x'})
    assert result['status_code'] == 500
    assert result['body'] == 'boom'


def test_return_on_error_false_raises(ops, requests_mock):
    requests_mock.get('https://api.example.com/v1/x', status_code=500, text='boom',
                      headers={'Content-Type': 'text/plain'})
    with pytest.raises(Exception) as exc:
        ops.http_get(_config(return_on_error=False), {'rest_api': '/v1/x'})
    assert '500' in str(exc.value)


# ---------- dispatch ----------

def test_http_ops_dispatch_table(ops):
    expected = {'http_get', 'http_post', 'http_put', 'http_patch', 'http_delete',
                'http_head', 'http_options', 'http_request', 'http_paginate', 'fetch_records'}
    assert expected.issubset(set(ops.http_ops.keys()))


def test_http_request_method_picklist(ops, requests_mock):
    requests_mock.delete('https://api.example.com/v1/x', json={}, status_code=204,
                         headers={'Content-Type': 'application/json'})
    result = ops.http_request(_config(), {'rest_api': '/v1/x', 'method': 'DELETE'})
    assert result['status_code'] == 204


def test_dispatch_includes_upload_and_download(ops):
    assert 'upload_file' in ops.http_ops
    assert 'download_file' in ops.http_ops


# ---------- helpers: filename + attachment IRI resolve ----------

def test_filename_from_content_disposition_quoted(ops):
    assert ops._filename_from_content_disposition('attachment; filename="report.csv"') == 'report.csv'


def test_filename_from_content_disposition_unquoted(ops):
    assert ops._filename_from_content_disposition('inline; filename=raw.bin') == 'raw.bin'


def test_filename_from_content_disposition_rfc5987(ops):
    # RFC 5987 filename* takes precedence over plain filename.
    val = "attachment; filename=plain.bin; filename*=UTF-8''report%20%E2%9C%93.csv"
    assert ops._filename_from_content_disposition(val) == 'report ✓.csv'


def test_filename_from_content_disposition_none(ops):
    assert ops._filename_from_content_disposition(None) is None
    assert ops._filename_from_content_disposition('') is None
    assert ops._filename_from_content_disposition('attachment') is None


def test_resolve_attachment_local_path_passthrough(ops, tmp_path):
    p = tmp_path / 'thing.bin'
    p.write_bytes(b'x')
    path, name = ops._resolve_attachment_to_path(str(p))
    assert path == str(p)
    assert name == 'thing.bin'


def test_resolve_attachment_dict_pulls_at_id(ops, soar_stubs):
    # A File IRI in a dict — no /attachments/ dereference needed.
    (open(os.path.join(soar_stubs['tmp_root'], 'stub_payload.bin'), 'wb')).write(b'1')
    path, _ = ops._resolve_attachment_to_path({'@id': '/api/3/files/abc'})
    assert path.endswith('stub_payload.bin')
    # crudhub should NOT be hit for file IRIs.
    assert soar_stubs['crudhub'] == []


def test_resolve_attachment_dereferences_attachment_iri(ops, soar_stubs):
    open(os.path.join(soar_stubs['tmp_root'], 'stub_payload.bin'), 'wb').write(b'1')
    path, _ = ops._resolve_attachment_to_path('/api/3/attachments/some-uuid')
    assert path.endswith('stub_payload.bin')
    # crudhub was used to dereference the attachment.
    assert soar_stubs['crudhub'][0]['iri'] == '/api/3/attachments/some-uuid'
    # And then the resolved File IRI was passed to download_file_from_cyops.
    assert soar_stubs['download'][0]['iri'] == '/api/3/files/resolved-file-uuid'


def test_resolve_attachment_empty_raises(ops):
    with pytest.raises(Exception) as exc:
        ops._resolve_attachment_to_path(None)
    assert 'required' in str(exc.value).lower()


def test_resolve_attachment_missing_file_in_record_raises(ops, soar_stubs, monkeypatch):
    crudhub = sys.modules['connectors.cyops_utilities.crudhub']
    monkeypatch.setattr(crudhub, 'make_cyops_request',
                        lambda iri, method='GET', *a, **k: {'@id': iri, 'file': None})
    with pytest.raises(Exception) as exc:
        ops._resolve_attachment_to_path('/api/3/attachments/x')
    assert 'no file' in str(exc.value).lower()


# ---------- upload_file ----------

def _seed_tmp(soar_stubs, content=b'payload-bytes'):
    """Drop the stubbed payload onto disk where download_file_from_cyops will point."""
    p = os.path.join(soar_stubs['tmp_root'], 'stub_payload.bin')
    with open(p, 'wb') as fh:
        fh.write(content)
    return p


def test_upload_file_multipart(ops, requests_mock, soar_stubs):
    _seed_tmp(soar_stubs, content=b'csv,bytes,here')
    requests_mock.post('https://api.example.com/api/uploads', json={'ok': True}, status_code=201)

    result = ops.upload_file(_config(), {
        'rest_api': '/api/uploads',
        'method': 'POST',
        'attachment_id': '/api/3/attachments/some-uuid',
        'field_name': 'file',
        'content_type': 'text/csv',
    })

    assert result['status_code'] == 201
    assert result['uploaded']['bytes'] == len(b'csv,bytes,here')
    assert result['uploaded']['mode'] == 'multipart'
    body = requests_mock.last_request.body
    # Body is the raw multipart payload — must include the file bytes and filename.
    assert b'csv,bytes,here' in body
    assert b'stub_payload.bin' in body or b'filename=' in body


def test_upload_file_raw_body(ops, requests_mock, soar_stubs):
    _seed_tmp(soar_stubs, content=b'raw-bytes-here')
    requests_mock.put('https://api.example.com/bucket/x', text='', status_code=200)

    result = ops.upload_file(_config(), {
        'rest_api': '/bucket/x',
        'method': 'PUT',
        'attachment_id': '/api/3/attachments/some-uuid',
        'upload_mode': 'raw_body',
        'content_type': 'application/octet-stream',
    })

    assert result['status_code'] == 200
    assert result['uploaded']['mode'] == 'raw_body'
    assert result['uploaded']['bytes'] == len(b'raw-bytes-here')
    assert requests_mock.last_request.headers['Content-Type'] == 'application/octet-stream'


def test_upload_file_filename_placeholder_substituted(ops, requests_mock, soar_stubs):
    _seed_tmp(soar_stubs, content=b'x')
    requests_mock.put('https://api.example.com/api/resources/my%20report.bin',
                      text='', status_code=200)

    ops.upload_file(_config(), {
        'rest_api': '/api/resources/{filename}',
        'method': 'PUT',
        'attachment_id': '/api/3/attachments/some-uuid',
        'filename': 'my report.bin',
        'upload_mode': 'raw_body',
    })

    assert requests_mock.last_request.url.endswith('/api/resources/my%20report.bin')


def test_upload_file_missing_endpoint_raises(ops, soar_stubs):
    with pytest.raises(Exception) as exc:
        ops.upload_file(_config(), {'attachment_id': '/api/3/attachments/x'})
    assert 'rest_api' in str(exc.value).lower() or 'endpoint' in str(exc.value).lower()


# ---------- download_file ----------

def test_download_file_creates_attachment(ops, requests_mock, soar_stubs):
    requests_mock.get('https://api.example.com/files/report',
                      content=b'csv,a,b\n1,2,3', status_code=200,
                      headers={'Content-Type': 'text/csv',
                               'Content-Disposition': 'attachment; filename="report.csv"'})

    result = ops.download_file(_config(), {
        'rest_api': '/files/report',
        'create_attachment': True,
        'description': 'unit test',
    })

    assert result['status_code'] == 200
    assert result['downloaded']['filename'] == 'report.csv'
    assert result['downloaded']['bytes'] == len(b'csv,a,b\n1,2,3')
    assert result['downloaded']['attachment']['@id'] == '/api/3/attachments/stub-uuid'

    # File actually landed on disk.
    written = os.path.join(soar_stubs['tmp_root'], 'report.csv')
    assert os.path.exists(written)
    with open(written, 'rb') as fh:
        assert fh.read() == b'csv,a,b\n1,2,3'

    # upload_file_to_cyops was called with the resolved name + description.
    assert soar_stubs['upload'][0]['filename'] == 'report.csv'
    assert soar_stubs['upload'][0]['description'] == 'unit test'


def test_download_file_skip_attachment_returns_file_path(ops, requests_mock, soar_stubs):
    requests_mock.get('https://api.example.com/x', content=b'bytes', status_code=200,
                      headers={'Content-Type': 'application/octet-stream'})

    result = ops.download_file(_config(), {
        'rest_api': '/x',
        'create_attachment': False,
    })

    assert 'attachment' not in result['downloaded']
    assert result['downloaded']['file_path'].endswith('x')  # URL basename fallback
    assert soar_stubs['upload'] == []  # no upload helper call


def test_download_file_filename_priority(ops, requests_mock, soar_stubs):
    """Explicit filename param wins over Content-Disposition and URL basename."""
    requests_mock.get('https://api.example.com/dir/server.bin', content=b'1',
                      status_code=200,
                      headers={'Content-Disposition': 'attachment; filename="cd.bin"'})

    result = ops.download_file(_config(), {
        'rest_api': '/dir/server.bin',
        'create_attachment': False,
        'filename': 'explicit.bin',
    })
    assert result['downloaded']['filename'] == 'explicit.bin'


def test_download_file_fallback_filename(ops, requests_mock, soar_stubs):
    """No Content-Disposition, URL path is /, no explicit filename → download.bin."""
    requests_mock.get('https://api.example.com/', content=b'1', status_code=200)

    result = ops.download_file(_config(), {
        'rest_api': '/',
        'create_attachment': False,
    })
    assert result['downloaded']['filename'] == 'download.bin'


def test_download_file_strips_path_separators(ops, requests_mock, soar_stubs):
    """An evil Content-Disposition can't write outside TMP_FILE_ROOT."""
    requests_mock.get('https://api.example.com/x', content=b'1', status_code=200,
                      headers={'Content-Disposition':
                               'attachment; filename="../../etc/passwd"'})

    result = ops.download_file(_config(), {'rest_api': '/x', 'create_attachment': False})
    # basename() should reduce '../../etc/passwd' to 'passwd'.
    assert result['downloaded']['filename'] == 'passwd'
    assert os.path.dirname(result['downloaded']['file_path']) == soar_stubs['tmp_root']


def test_download_file_error_with_return_on_error_false_raises(ops, requests_mock, soar_stubs):
    requests_mock.get('https://api.example.com/x', status_code=404, text='nope')
    with pytest.raises(Exception) as exc:
        ops.download_file(_config(return_on_error=False), {'rest_api': '/x'})
    assert '404' in str(exc.value)


def test_download_missing_url_raises(ops, soar_stubs):
    with pytest.raises(Exception) as exc:
        ops.download_file(_config(), {})
    assert 'url' in str(exc.value).lower() or 'rest_api' in str(exc.value).lower()


# ---------- retry ----------

def test_retry_session_builds_when_max_retries_set(ops):
    """The retry path goes through urllib3.HTTPAdapter, which requests-mock
    intercepts above. We can't exercise the retry loop end-to-end here, so
    just verify the session-builder honors the config."""
    sess = ops._build_session(_config(max_retries=3, retry_on_status='500,502'))
    adapter = sess.get_adapter('https://api.example.com')
    retry = adapter.max_retries
    assert retry.total == 3
    assert 500 in retry.status_forcelist and 502 in retry.status_forcelist


def test_retry_session_disabled_when_zero(ops):
    sess = ops._build_session(_config(max_retries=0))
    adapter = sess.get_adapter('https://api.example.com')
    total = getattr(adapter.max_retries, 'total', adapter.max_retries)
    assert total in (0, None)


# ---------- check_health ----------

def test_check_health_ok(ops, requests_mock):
    requests_mock.get('https://api.example.com', status_code=200, text='ok')
    assert ops.check_health(_config()) is True


def test_check_health_accepts_401(ops, requests_mock):
    """A 401 from the base URL still means the server is reachable."""
    requests_mock.get('https://api.example.com', status_code=401, text='nope')
    assert ops.check_health(_config()) is True


def test_check_health_no_server_url_is_ok(ops):
    # No server URL → connector is meant for absolute-URL use → healthy.
    assert ops.check_health(_config(server_url='')) is True


def test_check_health_connection_error_raises(ops, requests_mock):
    import requests as _requests
    requests_mock.get('https://api.example.com', exc=_requests.exceptions.ConnectionError('down'))
    with pytest.raises(ConnectorError):
        ops.check_health(_config())


# ===========================================================================
# Live tests — opt-in via RUN_LIVE_TESTS=1.
#
# These hit real public endpoints (httpbin.org) to verify the connector
# against an actual HTTP stack. SOAR-internal helpers (upload_file_to_cyops,
# make_cyops_request, download_file_from_cyops) are still stubbed since they
# require an FSR appliance.
# ===========================================================================

pytestmark_live = pytest.mark.skipif(not LIVE, reason='set RUN_LIVE_TESTS=1 to enable')


@pytestmark_live
def test_live_http_get_httpbin(ops):
    result = ops.http_get(_config(server_url='https://httpbin.org', verify_ssl=True),
                          {'rest_api': '/get', 'parameter': {'a': '1'}})
    assert result['status_code'] == 200
    assert result['body']['args'] == {'a': '1'}


@pytestmark_live
def test_live_http_post_json_httpbin(ops):
    result = ops.http_post(_config(server_url='https://httpbin.org', verify_ssl=True),
                           {'rest_api': '/post', 'body_type': 'json', 'data': {'hello': 'world'}})
    assert result['status_code'] == 200
    assert result['body']['json'] == {'hello': 'world'}


@pytestmark_live
def test_live_basic_auth_httpbin(ops):
    result = ops.http_get(
        _config(server_url='https://httpbin.org', verify_ssl=True,
                auth_type='Basic', basic_username='u', basic_password='p'),
        {'rest_api': '/basic-auth/u/p'},
    )
    assert result['status_code'] == 200
    assert result['body']['authenticated'] is True


@pytestmark_live
def test_live_bearer_auth_httpbin(ops):
    result = ops.http_get(
        _config(server_url='https://httpbin.org', verify_ssl=True,
                auth_type='Bearer Token', bearer_token='abc.def.ghi'),
        {'rest_api': '/bearer'},
    )
    assert result['status_code'] == 200
    assert result['body']['token'] == 'abc.def.ghi'


@pytestmark_live
def test_live_download_then_inspect(ops, soar_stubs):
    """End-to-end: GET a real URL, write it to TMP_FILE_ROOT, skip the
    create_attachment step (since SOAR isn't here), and verify the bytes."""
    result = ops.download_file(
        _config(server_url='https://httpbin.org', verify_ssl=True),
        {'rest_api': '/bytes/1024', 'create_attachment': False, 'filename': 'live.bin'},
    )
    assert result['status_code'] == 200
    assert result['downloaded']['bytes'] == 1024
    with open(result['downloaded']['file_path'], 'rb') as fh:
        assert len(fh.read()) == 1024


@pytestmark_live
def test_live_upload_file_multipart_httpbin(ops, soar_stubs):
    """End-to-end upload via httpbin /post which echoes multipart fields back."""
    _seed_tmp(soar_stubs, content=b'live-payload')
    result = ops.upload_file(
        _config(server_url='https://httpbin.org', verify_ssl=True),
        {
            'rest_api': '/post',
            'method': 'POST',
            'attachment_id': '/api/3/attachments/some-uuid',
            'field_name': 'file',
            'filename': 'live.bin',
            'content_type': 'application/octet-stream',
        },
    )
    assert result['status_code'] == 200
    # httpbin echoes the uploaded file back in body.files.<field_name>
    assert 'file' in result['body']['files']
