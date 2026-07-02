# Copyright (C) 2026 Fortinet Inc. — MIT License
"""HTTP connector operation implementations.

The request engine (auth, body, response, session, retry) and the per-action
shims live here. Each public op keeps the FortiSOAR-mandated
``(config: HttpConfig | dict[str, Any], params: dict[str, Any]) -> dict`` signature and parses both into typed
pydantic models (see ``config.py`` / ``models.py``) before delegating to the
typed engine. Helpers the test suite reaches into directly (``_resolve_url``,
``_token_login``, ``_build_session``, ``_to_dict``, ``_pluck`` ...) accept a
raw config dict and parse it via :func:`_parse_config`, so they remain
callable both internally (with an ``HttpConfig``) and from tests (with a dict).
"""

from __future__ import annotations

import json as _json
import os
import re
import time
from base64 import b64encode
from typing import Any
from urllib.parse import quote, urljoin, urlparse

import requests
from connectors.core.connector import ConnectorError, get_logger
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .config import (
    ApiKeyHeaderAuth,
    ApiKeyQueryAuth,
    BasicAuth,
    BearerAuth,
    HttpConfig,
    NoAuth,
    OAuth2ClientCredentialsAuth,
    TokenLoginAuth,
    _parse_config,
    _validate,
    auth_from_config,
)
from .models import (
    BodyType,
    CachedToken,
    DownloadFileParams,
    FetchRecordsParams,
    FileRef,
    HttpDeleteParams,
    HttpGetParams,
    HttpHeadParams,
    HttpOptionsParams,
    HttpPatchParams,
    HttpPostParams,
    HttpPutParams,
    HttpRequestParams,
    Method,
    PaginateParams,
    ParsedResponse,
    PreparedBody,
    UploadFileParams,
    _to_dict,
    _to_list_of_pairs,
)

logger = get_logger("http")

SSL_VALIDATION_ERROR = "SSL certificate validation failed"
CONNECTION_TIMEOUT = "The request timed out while trying to connect to the remote server"
REQUEST_READ_TIMEOUT = "The server did not send any data in the allotted amount of time"

# Module-level OAuth2 token cache keyed by (token_url, client_id, scope).
_OAUTH_TOKEN_CACHE: dict[tuple[str, str, str], CachedToken] = {}


# ---------------------------------------------------------------------------
# Config / URL helpers
# ---------------------------------------------------------------------------


def _build_base_url(config: HttpConfig | dict[str, Any]) -> str:
    cfg = _parse_config(config)
    server_url = cfg.server_url
    if not server_url:
        return ""
    if not server_url.startswith("http://") and not server_url.startswith("https://"):
        server_url = ("https://" if cfg.verify_ssl else "http://") + server_url
    if cfg.port:
        # Insert port if not already present in the netloc.
        parsed = urlparse(server_url)
        if ":" not in parsed.netloc:
            server_url = f"{parsed.scheme}://{parsed.netloc}:{cfg.port}{parsed.path or ''}"
    return server_url.rstrip("/")


def _resolve_url(config: HttpConfig | dict[str, Any], rest_api: str | None) -> str:
    """If rest_api is absolute, use it as-is; else join with the configured base URL."""
    cfg = _parse_config(config)
    rest_api = (rest_api or "").strip()
    if rest_api.startswith("http://") or rest_api.startswith("https://"):
        return rest_api
    base = _build_base_url(cfg)
    if not base:
        raise ConnectorError("No Server URL configured and the request path is not absolute.")
    if not rest_api.startswith("/"):
        rest_api = "/" + rest_api
    return base + rest_api


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------


def _oauth2_client_credentials_token(config: HttpConfig | dict[str, Any]) -> str:
    cfg = _parse_config(config)
    token_url = cfg.oauth_token_url
    client_id = cfg.oauth_client_id
    client_secret = cfg.oauth_client_secret
    scope = cfg.oauth_scope
    if not token_url or not client_id:
        raise ConnectorError("OAuth2 Client Credentials requires Token URL and Client ID.")
    cache_key = (token_url, client_id, scope)
    cached = _OAUTH_TOKEN_CACHE.get(cache_key)
    if cached and cached.expires_at > time.time() + 30:
        return cached.access_token
    data = {"grant_type": "client_credentials", "client_id": client_id, "client_secret": client_secret}
    if scope:
        data["scope"] = scope
    resp = requests.post(token_url, data=data, verify=cfg.verify_ssl, timeout=cfg.timeout or 60)
    if not resp.ok:
        raise ConnectorError(f"OAuth2 token request failed ({resp.status_code}): {resp.text[:300]}")
    body = resp.json()
    token = body.get("access_token")
    if not token:
        raise ConnectorError(f"OAuth2 token response missing 'access_token': {body}")
    expires_in = int(body.get("expires_in") or 3600)
    _OAUTH_TOKEN_CACHE[cache_key] = CachedToken(access_token=token, expires_at=time.time() + expires_in)
    return str(token)


def _token_login(config: HttpConfig | dict[str, Any]) -> str:
    """POST to the configured login URL, return the token string.

    Runs every request — no caching, by design. Two modes controlled by
    ``login_body_type``: ``json`` (default) sends a JSON body with the
    username/password fields; ``header_only`` sends no body and relies on
    ``login_request_headers`` (e.g. Yeti's ``x-yeti-apikey``).
    """
    cfg = _parse_config(config)
    login_url = cfg.login_url
    if not login_url:
        raise ConnectorError("Token Login requires Login URL.")
    body_type = cfg.login_body_type
    token_path = cfg.login_token_path
    url = _resolve_url(cfg, login_url)
    login_headers = cfg.login_request_headers
    if body_type == "header_only":
        if not login_headers:
            raise ConnectorError("Token Login body_type=header_only requires login_request_headers.")
        resp = requests.post(url, headers=login_headers, verify=cfg.verify_ssl, timeout=cfg.timeout or 60)
    else:
        user = cfg.login_username
        if not user:
            raise ConnectorError("Token Login requires Login URL and Username.")
        user_field = cfg.login_username_field or "username"
        pw_field = cfg.login_password_field or "password"
        resp = requests.post(
            url,
            json={user_field: user, pw_field: cfg.login_password},
            headers=login_headers,
            verify=cfg.verify_ssl,
            timeout=cfg.timeout or 60,
        )
    if not resp.ok:
        raise ConnectorError(f"Token login failed ({resp.status_code}): {resp.text[:300]}")
    ctype = (resp.headers.get("Content-Type") or "").lower()
    if token_path or "json" in ctype:
        try:
            body = resp.json()
        except ValueError:
            body = resp.text
        if token_path:
            token = _pluck(body, token_path)
        elif isinstance(body, str):
            token = body
        elif isinstance(body, dict):
            token = body.get("access_token") or body.get("token")
        else:
            token = None
    else:
        token = resp.text.strip()
    if not token or not isinstance(token, str):
        raise ConnectorError(f"Token login response did not yield a token (path={token_path}).")
    return str(token)


def _apply_auth(
    config: HttpConfig | dict[str, Any], headers: dict[str, str], query_params: dict[str, Any]
) -> None:
    """Mutates headers/query_params with auth material based on the configured auth_type.

    NOTE: per-call auth override is intentionally NOT honored — connection-level
    auth always wins (preserves v2.0.x behavior; tests assert this). The
    ``AuthConfig`` discriminated union narrows each branch so only the fields
    belonging to the active scheme are touched.
    """
    cfg = _parse_config(config)
    auth = auth_from_config(cfg)
    if isinstance(auth, NoAuth):
        return
    if isinstance(auth, BasicAuth):
        b64 = b64encode(f"{auth.basic_username}:{auth.basic_password}".encode()).decode("utf-8")
        headers.setdefault("Authorization", f"Basic {b64}")
        return
    if isinstance(auth, BearerAuth):
        headers.setdefault("Authorization", f"Bearer {auth.bearer_token}")
        return
    if isinstance(auth, ApiKeyHeaderAuth):
        if not auth.api_key_header_name:
            raise ConnectorError("API Key Header Name is required for 'API Key Header' auth.")
        headers.setdefault(auth.api_key_header_name, auth.api_key)
        return
    if isinstance(auth, ApiKeyQueryAuth):
        if not auth.api_key_param_name:
            raise ConnectorError("API Key Query Param Name is required for 'API Key Query Param' auth.")
        query_params.setdefault(auth.api_key_param_name, auth.api_key)
        return
    if isinstance(auth, OAuth2ClientCredentialsAuth):
        token = _oauth2_client_credentials_token(cfg)
        headers.setdefault("Authorization", f"Bearer {token}")
        return
    if isinstance(auth, TokenLoginAuth):
        token = _token_login(cfg)
        header_name = auth.login_header_name or "X-Auth"
        headers.setdefault(header_name, f"{auth.login_header_prefix}{token}")
        return
    raise ConnectorError(f"Unsupported Authentication Type: {cfg.auth_type}")


# ---------------------------------------------------------------------------
# Body / response shape
# ---------------------------------------------------------------------------


def _prepare_body(body_type: BodyType, body: Any) -> PreparedBody:
    """Returns a PreparedBody (data, json_payload, files) for requests.request kwargs."""
    bt = (body_type or "none").strip().lower()
    if body in (None, ""):
        return PreparedBody()
    if bt == "none":
        return PreparedBody()
    if bt == "json":
        if isinstance(body, str):
            try:
                body = _json.loads(body)
            except ValueError as err:
                raise ConnectorError("Body Type is 'json' but body is not valid JSON.") from err
        return PreparedBody(json_payload=body)
    if bt == "form":
        return PreparedBody(data=_to_dict(body))
    if bt in ("raw", "text"):
        if isinstance(body, (dict, list)):
            body = _json.dumps(body)
        return PreparedBody(data=body)
    if bt == "multipart":
        # Expect a dict of {field_name: value_or_file_descriptor}.
        return PreparedBody(files=_to_dict(body))
    raise ConnectorError(f"Unsupported Body Type: {bt}")


_DOT_PATH_RE = re.compile(r"([^\.\[\]]+)|\[(\d+)\]")


def _pluck(obj: Any, path: str) -> Any:
    """Navigate a JSON object via a dot/bracket path: 'data.results[0].id'.

    ``Any`` is intentional: the cursor is indexed/`.get`-ed by a computed
    path, so narrowing it to a JSON union would just add casts. The result is
    a JSON node the caller treats opaquely.
    """
    if not path:
        return obj
    cur: Any = obj
    for key, idx in _DOT_PATH_RE.findall(path):
        if idx != "":
            try:
                cur = cur[int(idx)]
            except (KeyError, IndexError, TypeError):
                return None
        else:
            if isinstance(cur, dict):
                cur = cur.get(key)
            else:
                return None
        if cur is None:
            return None
    return cur


def _parse_response(
    response: requests.Response, response_path: str | None = None, raw: bool = False
) -> ParsedResponse:
    if raw:
        return ParsedResponse(
            status_code=response.status_code,
            headers=dict(response.headers),
            content_base64=b64encode(response.content).decode("ascii") if response.content else "",
        )
    ctype = (response.headers.get("Content-Type") or "").lower()
    if response.content and "json" in ctype:
        try:
            body: Any = response.json()
        except ValueError:
            body = response.text
    elif response.content and ("text/" in ctype or "xml" in ctype or "html" in ctype):
        body = response.text
    elif response.content:
        body = {"_binary": True, "content_base64": b64encode(response.content).decode("ascii")}
    else:
        body = None
    if response_path and isinstance(body, (dict, list)):
        body = _pluck(body, response_path)
    return ParsedResponse(status_code=response.status_code, headers=dict(response.headers), body=body)


# ---------------------------------------------------------------------------
# Session w/ retry
# ---------------------------------------------------------------------------


def _build_session(config: HttpConfig | dict[str, Any]) -> requests.Session:
    cfg = _parse_config(config)
    if cfg.max_retries <= 0:
        return requests.Session()
    retry = Retry(
        total=cfg.max_retries,
        backoff_factor=cfg.backoff_factor,
        status_forcelist=cfg.retry_on_status,
        allowed_methods=frozenset(["HEAD", "GET", "PUT", "DELETE", "OPTIONS", "TRACE", "POST", "PATCH"]),
        respect_retry_after_header=True,
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry)
    sess = requests.Session()
    sess.mount("http://", adapter)
    sess.mount("https://", adapter)
    return sess


# ---------------------------------------------------------------------------
# Core request driver
# ---------------------------------------------------------------------------


def _do_request(
    config: HttpConfig | dict[str, Any],
    method: Method,
    rest_api: str | None,
    query_params: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    body_type: BodyType = "none",
    body: Any = None,
    timeout: int | None = None,
    follow_redirects: bool = True,
    response_path: str | None = None,
    raw: bool = False,
) -> ParsedResponse:
    cfg = _parse_config(config)
    url = _resolve_url(cfg, rest_api)
    # Connection-level custom headers (lowest priority — per-call headers win).
    merged_headers: dict[str, str] = {
        **cfg.default_headers,
        **(_to_dict(headers) if headers is not None else {}),
    }
    query: dict[str, Any] = {}
    for k, v in _to_list_of_pairs(query_params or {}):
        query[k] = v
    _apply_auth(cfg, merged_headers, query)
    pb = _prepare_body(body_type, body)
    if pb.json_payload is not None and "Content-Type" not in {
        k.title(): v for k, v in merged_headers.items()
    }:
        merged_headers["Content-Type"] = "application/json"

    t = timeout if timeout not in (None, "", 0) else (cfg.timeout or 60)
    session = _build_session(cfg)
    try:
        response = session.request(
            method=method,
            url=url,
            headers=merged_headers,
            params=query,
            data=pb.data,
            json=pb.json_payload,
            files=pb.files,
            verify=cfg.verify_ssl,
            timeout=t,
            allow_redirects=bool(follow_redirects),
        )
    except requests.exceptions.SSLError as err:
        raise ConnectorError(SSL_VALIDATION_ERROR) from err
    except requests.exceptions.ConnectTimeout as err:
        raise ConnectorError(CONNECTION_TIMEOUT) from err
    except requests.exceptions.ReadTimeout as err:
        raise ConnectorError(REQUEST_READ_TIMEOUT) from err
    except requests.exceptions.ConnectionError as e:
        raise ConnectorError(f"Connection error: {e}") from e
    if not response.ok and not cfg.return_on_error:
        raise ConnectorError(f"HTTP {response.status_code}: {response.text[:500]}")
    return _parse_response(response, response_path=response_path, raw=raw)


# ---------------------------------------------------------------------------
# Per-action params + verb ops
# ---------------------------------------------------------------------------


def http_get(config: HttpConfig | dict[str, Any], params: dict[str, Any]) -> dict[str, Any]:
    cfg = _parse_config(config)
    p = _validate(HttpGetParams, params, "http_get")
    return _do_request(
        cfg,
        "GET",
        p.rest_api,
        query_params=p.parameter,
        headers=p.header,
        timeout=p.timeout,
        follow_redirects=p.follow_redirects,
        response_path=p.response_path,
        raw=p.raw_response,
    ).as_output()


def http_post(config: HttpConfig | dict[str, Any], params: dict[str, Any]) -> dict[str, Any]:
    cfg = _parse_config(config)
    p = _validate(HttpPostParams, params, "http_post")
    return _do_request(
        cfg,
        "POST",
        p.rest_api,
        query_params=p.parameter,
        headers=p.header,
        body_type=p.body_type,
        body=p.data,
        timeout=p.timeout,
        follow_redirects=p.follow_redirects,
        response_path=p.response_path,
        raw=p.raw_response,
    ).as_output()


def http_put(config: HttpConfig | dict[str, Any], params: dict[str, Any]) -> dict[str, Any]:
    cfg = _parse_config(config)
    p = _validate(HttpPutParams, params, "http_put")
    return _do_request(
        cfg,
        "PUT",
        p.rest_api,
        query_params=p.parameter,
        headers=p.header,
        body_type=p.body_type,
        body=p.data,
        timeout=p.timeout,
        follow_redirects=p.follow_redirects,
        response_path=p.response_path,
        raw=p.raw_response,
    ).as_output()


def http_patch(config: HttpConfig | dict[str, Any], params: dict[str, Any]) -> dict[str, Any]:
    cfg = _parse_config(config)
    p = _validate(HttpPatchParams, params, "http_patch")
    return _do_request(
        cfg,
        "PATCH",
        p.rest_api,
        query_params=p.parameter,
        headers=p.header,
        body_type=p.body_type,
        body=p.data,
        timeout=p.timeout,
        follow_redirects=p.follow_redirects,
        response_path=p.response_path,
        raw=p.raw_response,
    ).as_output()


def http_delete(config: HttpConfig | dict[str, Any], params: dict[str, Any]) -> dict[str, Any]:
    cfg = _parse_config(config)
    p = _validate(HttpDeleteParams, params, "http_delete")
    return _do_request(
        cfg,
        "DELETE",
        p.rest_api,
        query_params=p.parameter,
        headers=p.header,
        body_type=p.body_type,
        body=p.data,
        timeout=p.timeout,
        follow_redirects=p.follow_redirects,
        response_path=p.response_path,
        raw=p.raw_response,
    ).as_output()


def http_head(config: HttpConfig | dict[str, Any], params: dict[str, Any]) -> dict[str, Any]:
    cfg = _parse_config(config)
    p = _validate(HttpHeadParams, params, "http_head")
    return _do_request(
        cfg,
        "HEAD",
        p.rest_api,
        query_params=p.parameter,
        headers=p.header,
        timeout=p.timeout,
        follow_redirects=p.follow_redirects,
        response_path=p.response_path,
        raw=p.raw_response,
    ).as_output()


def http_options(config: HttpConfig | dict[str, Any], params: dict[str, Any]) -> dict[str, Any]:
    cfg = _parse_config(config)
    p = _validate(HttpOptionsParams, params, "http_options")
    return _do_request(
        cfg,
        "OPTIONS",
        p.rest_api,
        query_params=p.parameter,
        headers=p.header,
        timeout=p.timeout,
        follow_redirects=p.follow_redirects,
        response_path=p.response_path,
        raw=p.raw_response,
    ).as_output()


def http_request(config: HttpConfig | dict[str, Any], params: dict[str, Any]) -> dict[str, Any]:
    """Freeform HTTP call where the user picks the method."""
    cfg = _parse_config(config)
    p = _validate(HttpRequestParams, params, "http_request")
    return _do_request(
        cfg,
        p.method,
        p.rest_api,
        query_params=p.parameter,
        headers=p.header,
        body_type=p.body_type,
        body=p.data,
        timeout=p.timeout,
        follow_redirects=p.follow_redirects,
        response_path=p.response_path,
        raw=p.raw_response,
    ).as_output()


# ---------------------------------------------------------------------------
# File upload / download
# ---------------------------------------------------------------------------


def _resolve_attachment_to_path(value: FileRef) -> tuple[str, str]:
    """Accept an attachment IRI, file IRI, attachment-record dict, or local file path.
    Returns (local_path, filename). Streams the file to TMP via FSR's helper."""
    if value in (None, ""):
        raise ConnectorError("Attachment / File reference is required.")
    # Local path passthrough.
    if isinstance(value, str) and (value.startswith("/") or value.startswith("./")) and os.path.exists(value):
        return value, os.path.basename(value)
    # Pull @id from a record dict if that's what was passed.
    if isinstance(value, dict):
        nested_file = value.get("file")
        nested_file_iri = nested_file.get("@id") if isinstance(nested_file, dict) else None
        value = (
            value.get("@id")
            or value.get("id")
            or value.get("iri")
            or nested_file_iri
            or (nested_file if isinstance(nested_file, str) else None)
        )
    if not isinstance(value, str) or not value.strip():
        raise ConnectorError("Could not resolve attachment reference to a string IRI.")
    iri = value.strip()
    try:
        from connectors.cyops_utilities.builtins import download_file_from_cyops
        from connectors.cyops_utilities.crudhub import make_cyops_request
        from django.conf import settings
    except ImportError as err:
        raise ConnectorError("FortiSOAR runtime helpers unavailable; cannot download file.") from err
    # If we were given an Attachment IRI, dereference it to its underlying File IRI.
    # download_file_from_cyops resolves File records, not Attachment wrappers.
    if "/attachments/" in iri:
        try:
            rec = make_cyops_request(iri, "GET") or {}
        except Exception as exc:
            raise ConnectorError(f"Failed to fetch Attachment {iri}: {exc}") from exc
        file_obj = rec.get("file") if isinstance(rec, dict) else None
        file_iri = (file_obj or {}).get("@id") if isinstance(file_obj, dict) else None
        if not file_iri:
            raise ConnectorError(f"Attachment {iri} has no file.@id to download.")
        iri = file_iri
    info = download_file_from_cyops(iri) or {}
    raw_path = info.get("cyops_file_path") or info.get("file_path") or info.get("path") or ""
    name = info.get("filename") or info.get("name") or os.path.basename(raw_path)
    # download_file_from_cyops returns the basename; join with TMP_FILE_ROOT to get the absolute path.
    tmp_root = getattr(settings, "TMP_FILE_ROOT", None) or "/tmp/"
    candidates = []
    if raw_path:
        candidates.append(raw_path if os.path.isabs(raw_path) else os.path.join(tmp_root, raw_path))
    if name:
        candidates.append(os.path.join(tmp_root, name))
    for p in candidates:
        if p and os.path.exists(p):
            return p, name or os.path.basename(p)
    raise ConnectorError(f"Resolved file not found on disk for IRI {iri} (tried: {candidates})")


def upload_file(config: HttpConfig | dict[str, Any], params: dict[str, Any]) -> dict[str, Any]:
    """POST/PUT a file to an arbitrary endpoint.

    Accepts an attachment IRI, file IRI, or attachment record (any of:
    ``attachment_id``, ``file_iri``, or a full @id-bearing dict passed as
    ``attachment_id``). Streams bytes — the 25 MB CSV never lives in playbook
    engine memory.

    Modes: ``multipart`` (default, standard file upload) or ``raw_body``
    (send file bytes as the request body — good for S3 PUT, filebrowser, etc.).
    """
    cfg = _parse_config(config)
    p = _validate(UploadFileParams, params, "upload_file")
    if not p.rest_api:
        raise ConnectorError("Endpoint (rest_api) is required.")
    method = p.method
    upload_mode = p.upload_mode
    field_name = p.field_name
    content_type = p.content_type

    ref = p.attachment_id or p.file_iri or p.file_path
    local_path, derived_name = _resolve_attachment_to_path(ref)
    filename = p.filename or derived_name
    # Support {filename} placeholder in the destination URL (e.g. /api/resources/{filename}).
    rest_api = p.rest_api.replace("{filename}", quote(filename, safe=""))

    url = _resolve_url(cfg, rest_api)
    merged_headers: dict[str, str] = {**cfg.default_headers, **p.header}
    query: dict[str, Any] = {}
    for k, v in _to_list_of_pairs(p.parameter):
        query[k] = v
    _apply_auth(cfg, merged_headers, query)

    timeout = p.timeout if p.timeout not in (None, 0) else (cfg.timeout or 300)
    session = _build_session(cfg)
    follow_redirects = p.follow_redirects

    try:
        with open(local_path, "rb") as fh:
            if upload_mode == "raw_body":
                merged_headers.setdefault("Content-Type", content_type)
                response = session.request(
                    method=method,
                    url=url,
                    headers=merged_headers,
                    params=query,
                    data=fh,
                    verify=cfg.verify_ssl,
                    timeout=timeout,
                    allow_redirects=follow_redirects,
                )
            else:
                extra = _to_dict(p.extra_fields)
                files = {field_name: (filename, fh, content_type)}
                response = session.request(
                    method=method,
                    url=url,
                    headers=merged_headers,
                    params=query,
                    data=extra,
                    files=files,
                    verify=cfg.verify_ssl,
                    timeout=timeout,
                    allow_redirects=follow_redirects,
                )
    except requests.exceptions.SSLError as err:
        raise ConnectorError(SSL_VALIDATION_ERROR) from err
    except requests.exceptions.ConnectTimeout as err:
        raise ConnectorError(CONNECTION_TIMEOUT) from err
    except requests.exceptions.ReadTimeout as err:
        raise ConnectorError(REQUEST_READ_TIMEOUT) from err
    except requests.exceptions.ConnectionError as e:
        raise ConnectorError(f"Connection error: {e}") from e
    if not response.ok and not cfg.return_on_error:
        raise ConnectorError(f"HTTP {response.status_code}: {response.text[:500]}")
    out = _parse_response(response, response_path=p.response_path, raw=p.raw_response).as_output()
    try:
        size = os.path.getsize(local_path)
    except OSError:
        size = None
    out["uploaded"] = {"filename": filename, "bytes": size, "mode": upload_mode}
    return out


# ---------------------------------------------------------------------------
# Pagination
# ---------------------------------------------------------------------------

_LINK_NEXT_RE = re.compile(r"<([^>]+)>;\s*rel=\"?next\"?", re.IGNORECASE)


def _next_url_from_link_header(link_header: str | None, current_url: str) -> str | None:
    if not link_header:
        return None
    m = _LINK_NEXT_RE.search(link_header)
    if not m:
        return None
    next_url = m.group(1)
    if next_url.startswith("http://") or next_url.startswith("https://"):
        return next_url
    return urljoin(current_url, next_url)


def http_paginate(config: HttpConfig | dict[str, Any], params: dict[str, Any]) -> dict[str, Any]:
    """Walks a paginated endpoint and concatenates results.

    Modes:
      - 'link_header'  -> follow RFC 5988 'next' link header.
      - 'next_url_path' -> next URL is at a given dot-path inside the JSON response.
      - 'page_param'   -> bump a query-param page number until response_path is empty.
    """
    cfg = _parse_config(config)
    p = _validate(PaginateParams, params, "http_paginate")
    mode = p.pagination_mode
    items_path = p.items_path or p.response_path
    next_path = p.next_url_path
    page_param = p.page_param_name
    page_no = p.start_page
    max_pages = p.max_pages
    method = p.method
    body_type = p.body_type
    body = p.data

    items: list[Any] = []
    current_url: str | None = p.rest_api
    page_count = 0
    seen_urls: set[str] = set()
    base_query: dict[str, Any] = dict(_to_list_of_pairs(p.parameter))
    while page_count < max_pages:
        page_query = dict(base_query)
        if mode == "page_param":
            page_query[page_param] = page_no
        result = _do_request(
            cfg,
            method,
            current_url,
            query_params=page_query,
            headers=p.header,
            body_type=body_type,
            body=body,
            timeout=p.timeout,
            follow_redirects=p.follow_redirects,
            response_path=None,
            raw=False,
        )
        body_obj = result.body
        page_items = (
            _pluck(body_obj, items_path) if items_path else (body_obj if isinstance(body_obj, list) else [])
        )
        if isinstance(page_items, list):
            items.extend(page_items)
        elif page_items is not None:
            items.append(page_items)
        page_count += 1
        # Decide next URL.
        if mode == "link_header":
            link = result.headers.get("Link") or result.headers.get("link")
            current_url = _next_url_from_link_header(link, _resolve_url(cfg, current_url))
            if not current_url or current_url in seen_urls:
                break
            seen_urls.add(current_url)
            base_query = {}  # next URL already carries its own query
        elif mode == "next_url_path":
            nxt = _pluck(body_obj, next_path) if next_path else None
            if not nxt or nxt in seen_urls:
                break
            seen_urls.add(nxt)
            current_url = nxt
            base_query = {}
        elif mode == "page_param":
            if not page_items:
                break
            if isinstance(page_items, list) and len(page_items) == 0:
                break
            page_no += 1
        else:
            raise ConnectorError(f"Unknown pagination_mode: {mode}")
    return {"items": items, "pages_fetched": page_count, "truncated": page_count >= max_pages}


# ---------------------------------------------------------------------------
# Ingestion
# ---------------------------------------------------------------------------


def fetch_records(config: HttpConfig | dict[str, Any], params: dict[str, Any]) -> dict[str, Any]:
    """Used by scheduled data ingestion. Calls a configured endpoint, plucks
    records via response_path, and returns them as a flat list shaped for the
    connector's ingest_mapping_template.
    """
    cfg = _parse_config(config)
    p = _validate(FetchRecordsParams, params, "fetch_records")
    fetch_url = p.fetch_url or cfg.default_fetch_url or ""
    response_path = p.response_path or cfg.default_response_path
    method = p.method
    if p.pagination_mode and p.pagination_mode != "none":
        return http_paginate(
            cfg,
            {
                "rest_api": fetch_url,
                "method": method,
                "response_path": response_path,
                "items_path": response_path,
                "pagination_mode": p.pagination_mode,
                "page_param_name": p.page_param_name,
                "start_page": p.start_page,
                "max_pages": p.max_pages,
                "next_url_path": p.next_url_path,
                "body_type": p.body_type,
                "data": p.data,
                "header": p.header,
                "parameter": p.parameter,
                "timeout": p.timeout,
                "follow_redirects": p.follow_redirects,
            },
        )
    result = _do_request(
        cfg,
        method,
        fetch_url,
        query_params=p.parameter,
        headers=p.header,
        body_type=p.body_type,
        body=p.data,
        timeout=p.timeout,
        follow_redirects=p.follow_redirects,
        response_path=response_path,
        raw=False,
    )
    body = result.body
    if isinstance(body, list):
        records = body
    elif body is None:
        records = []
    else:
        records = [body]
    return {"records": records, "count": len(records)}


# ---------------------------------------------------------------------------
# Download
# ---------------------------------------------------------------------------


def _filename_from_content_disposition(value: str | None) -> str | None:
    """Extract filename from a Content-Disposition header, or None."""
    if not value:
        return None
    m = re.search(r"filename\*=(?:UTF-8'')?([^;]+)", value, re.IGNORECASE)
    if m:
        from urllib.parse import unquote

        return unquote(m.group(1).strip().strip('"'))
    m = re.search(r'filename="?([^";]+)"?', value, re.IGNORECASE)
    if m:
        return m.group(1).strip()
    return None


def download_file(config: HttpConfig | dict[str, Any], params: dict[str, Any]) -> dict[str, Any]:
    """GET (or any verb) a remote URL and save the response body as an FSR
    attachment. The reverse of ``upload_file`` — bytes stream directly from the
    HTTP response to disk; nothing is buffered through the playbook engine.

    Output mirrors the standard HTTP response (``status_code``, ``headers``)
    plus a ``downloaded`` block:

      downloaded:
        filename:      <resolved filename>
        bytes:         <size on disk>
        attachment:    <attachment record returned by FortiSOAR>  # if create_attachment
        file_path:     <absolute path on the integration agent>   # if not creating an attachment
    """
    cfg = _parse_config(config)
    p = _validate(DownloadFileParams, params, "download_file")
    if not p.rest_api:
        raise ConnectorError("URL (rest_api) is required.")
    method = p.method
    create_attachment = p.create_attachment
    explicit_name = p.filename
    display_name = p.attachment_name
    description = p.description

    url = _resolve_url(cfg, p.rest_api)
    merged_headers: dict[str, str] = {**cfg.default_headers, **p.header}
    query: dict[str, Any] = {}
    for k, v in _to_list_of_pairs(p.parameter):
        query[k] = v
    _apply_auth(cfg, merged_headers, query)

    # Optional request body (rare for downloads but some APIs require POST).
    pb = _prepare_body(p.body_type, p.data)

    timeout = p.timeout if p.timeout is not None else (cfg.timeout or 300)
    follow_redirects = p.follow_redirects
    session = _build_session(cfg)

    # Pick a destination. We need a file on disk before we can hand it to
    # FortiSOAR's upload helper.
    try:
        from django.conf import settings

        tmp_root = getattr(settings, "TMP_FILE_ROOT", None) or "/tmp/"
    except ImportError:
        tmp_root = "/tmp/"
    if not os.path.isdir(tmp_root):
        os.makedirs(tmp_root, exist_ok=True)

    try:
        response = session.request(
            method=method,
            url=url,
            headers=merged_headers,
            params=query,
            data=pb.data,
            json=pb.json_payload,
            files=pb.files,
            verify=cfg.verify_ssl,
            timeout=timeout,
            allow_redirects=follow_redirects,
            stream=True,
        )
    except requests.exceptions.SSLError as err:
        raise ConnectorError(SSL_VALIDATION_ERROR) from err
    except requests.exceptions.ConnectTimeout as err:
        raise ConnectorError(CONNECTION_TIMEOUT) from err
    except requests.exceptions.ReadTimeout as err:
        raise ConnectorError(REQUEST_READ_TIMEOUT) from err
    except requests.exceptions.ConnectionError as e:
        raise ConnectorError(f"Connection error: {e}") from e

    if not response.ok and not cfg.return_on_error:
        body_preview = ""
        try:
            body_preview = response.text[:500]
        except Exception:
            pass
        raise ConnectorError(f"HTTP {response.status_code}: {body_preview}")

    # Resolve filename: explicit > Content-Disposition > URL basename > fallback.
    resolved_name = (
        explicit_name
        or _filename_from_content_disposition(response.headers.get("Content-Disposition"))
        or os.path.basename(urlparse(response.url).path)
        or "download.bin"
    )
    # Strip any path separators that snuck in.
    resolved_name = os.path.basename(resolved_name) or "download.bin"
    dest_path = os.path.join(tmp_root, resolved_name)

    bytes_written = 0
    try:
        with open(dest_path, "wb") as fh:
            for chunk in response.iter_content(chunk_size=64 * 1024):
                if not chunk:
                    continue
                fh.write(chunk)
                bytes_written += len(chunk)
    finally:
        response.close()

    out: dict[str, Any] = {
        "status_code": response.status_code,
        "headers": dict(response.headers),
    }
    downloaded: dict[str, Any] = {"filename": resolved_name, "bytes": bytes_written}

    if create_attachment:
        try:
            from connectors.cyops_utilities.builtins import upload_file_to_cyops
        except ImportError as err:
            raise ConnectorError(
                "FortiSOAR runtime helpers unavailable; cannot create attachment. "
                f"Set 'create_attachment' to false to keep the file at {dest_path}."
            ) from err
        attach = upload_file_to_cyops(
            file_path=resolved_name,
            filename=resolved_name,
            create_attachment=True,
            name=display_name or resolved_name,
            description=description or f"Downloaded via HTTP connector from {url}",
        )
        downloaded["attachment"] = attach
    else:
        downloaded["file_path"] = dest_path

    out["downloaded"] = downloaded
    return out


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------


def check_health(config: HttpConfig | dict[str, Any]) -> bool:
    cfg = _parse_config(config)
    try:
        url = _build_base_url(cfg)
        if not url:
            # No server URL configured — accept this as healthy (connector is meant to be used
            # with absolute URLs per call).
            return True
        resp = requests.get(url, verify=cfg.verify_ssl, timeout=cfg.timeout or 30)
        return resp.ok or resp.status_code in (401, 403, 404)
    except requests.exceptions.SSLError as err:
        raise ConnectorError(SSL_VALIDATION_ERROR) from err
    except requests.exceptions.ConnectTimeout as err:
        raise ConnectorError(CONNECTION_TIMEOUT) from err
    except requests.exceptions.ReadTimeout as err:
        raise ConnectorError(REQUEST_READ_TIMEOUT) from err
    except Exception as err:
        raise ConnectorError(str(err)) from err


http_ops = {
    "http_get": http_get,
    "http_post": http_post,
    "http_options": http_options,
    "http_put": http_put,
    "http_head": http_head,
    "http_delete": http_delete,
    "http_patch": http_patch,
    "http_request": http_request,
    "http_paginate": http_paginate,
    "fetch_records": fetch_records,
    "upload_file": upload_file,
    "download_file": download_file,
}
