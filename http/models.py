# Copyright (C) 2026 Fortinet Inc. — MIT License
"""Pydantic models for the HTTP connector's operation params and parsed
responses, plus the small coercion helpers the config/param validators share.

The public surface FortiSOAR calls is a flat ``params`` dict, so each
operation has a dedicated model that normalizes the legacy shapes (JSON
strings, ``[{key, value}]`` lists, string-y ints, ``'text'`` body alias)
into clean typed fields.

``ParsedResponse`` is the structured value every verb action returns; its
``as_output()`` reproduces the exact dict shape the legacy connector produced
(``{status_code, headers, body}`` or ``{status_code, headers, content_base64}``
in raw mode), so playbook and test consumers are unchanged.
"""

from __future__ import annotations

import json as _json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Literal, Optional, Union

from connectors.core.connector import ConnectorError
from pydantic import BaseModel, ConfigDict, Field, field_validator

# A file reference accepted by upload_file: an attachment/file IRI string, an
# attachment-record dict, or a local filesystem path. Union form (not `X | Y`)
# so it evaluates on Python 3.9 (the 7.6.x appliance runtime).
FileRef = Union[str, dict[str, Any], None]

# --------------------------------------------------------------------------- #
# Coercion helpers (used by the param/config before-validators and by the
# request engine in operations.py). Kept here so config.py can import them
# without a circular dependency.
# --------------------------------------------------------------------------- #


def _to_dict(value: Any) -> dict[str, Any]:
    """Coerce a parameter into a dict. Accepts dict, JSON string, or '' / None."""
    if value in (None, "", 0, "0"):
        return {}
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = _json.loads(value)
        except ValueError as err:
            raise ConnectorError(f"Expected JSON object, got: {value[:120]!r}") from err
        if not isinstance(parsed, dict):
            raise ConnectorError(f"Expected JSON object, got: {type(parsed).__name__}")
        return parsed
    raise ConnectorError(f"Expected dict or JSON object string, got: {type(value).__name__}")


def _to_list_of_pairs(value: Any) -> list[tuple[str, Any]]:
    """Accept a dict OR a list of {'key':..,'value':..} entries -> list of (k, v) tuples."""
    if value in (None, "", 0):
        return []
    if isinstance(value, dict):
        return list(value.items())
    if isinstance(value, list):
        out: list[tuple[str, Any]] = []
        for item in value:
            if isinstance(item, dict) and "key" in item:
                out.append((item["key"], item.get("value", "")))
        return out
    raise ConnectorError("Expected dict or list of key/value entries.")


# --------------------------------------------------------------------------- #
# Enums / Literals
# --------------------------------------------------------------------------- #

BodyType = Literal["none", "json", "form", "raw", "multipart"]  # 'text' aliased to 'raw'
Method = Literal["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]
PaginationMode = Literal["link_header", "next_url_path", "page_param"]
IngestPaginationMode = Literal["none", "link_header", "next_url_path", "page_param"]
UploadMode = Literal["multipart", "raw_body"]
LoginBodyType = Literal["json", "header_only"]


# --------------------------------------------------------------------------- #
# Shared before-validators
# --------------------------------------------------------------------------- #


def _strip(v: Any) -> str:
    return str(v).strip() if v is not None else ""


def _strip_or_none(v: Any) -> Optional[str]:
    v = _strip(v)
    return v or None


def _coerce_int(default: int) -> Callable[[Any], int]:
    def _coerce(v: Any) -> int:
        if v in (None, "", 0):
            return default
        return int(v)

    return _coerce


def _coerce_int_or_none(v: Any) -> Optional[int]:
    if v in (None, "", 0):
        return None
    return int(v)


def _coerce_bool(v: Any) -> bool:
    return bool(v) if v is not None else True


def _coerce_bool_false(v: Any) -> bool:
    return bool(v) if v is not None else False


def _coerce_param_dict(v: Any) -> dict[str, Any]:
    """Query-param / header dict: accept dict, JSON string, or list-of-pairs."""
    if v in (None, "", 0, "0"):
        return {}
    if isinstance(v, dict):
        return v
    if isinstance(v, str):
        return _to_dict(v)
    if isinstance(v, list):
        return {k: val for k, val in _to_list_of_pairs(v)}
    return {}


def _coerce_method(v: Any) -> str:
    return str(v).upper() if v is not None else "GET"


def _coerce_body_type(v: Any) -> str:
    v = str(v).strip().lower() if v is not None else "none"
    return "raw" if v == "text" else v


# --------------------------------------------------------------------------- #
# Operation params
# --------------------------------------------------------------------------- #


class CommonRequestParams(BaseModel):
    """Fields shared by the verb actions and http_request."""

    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    rest_api: str = ""
    parameter: dict[str, Any] = Field(default_factory=dict)
    header: dict[str, str] = Field(default_factory=dict)
    timeout: Optional[int] = None
    follow_redirects: bool = True
    response_path: Optional[str] = None
    raw_response: bool = False

    @field_validator("rest_api", mode="before")
    @classmethod
    def _v_rest_api(cls, v: Any) -> str:
        return _strip(v)

    @field_validator("parameter", mode="before")
    @classmethod
    def _v_parameter(cls, v: Any) -> dict[str, Any]:
        return _coerce_param_dict(v)

    @field_validator("header", mode="before")
    @classmethod
    def _v_header(cls, v: Any) -> dict[str, str]:
        return _to_dict(v)

    @field_validator("timeout", mode="before")
    @classmethod
    def _v_timeout(cls, v: Any) -> Optional[int]:
        return _coerce_int_or_none(v)

    @field_validator("follow_redirects", mode="before")
    @classmethod
    def _v_follow_redirects(cls, v: Any) -> bool:
        return _coerce_bool(v)

    @field_validator("raw_response", mode="before")
    @classmethod
    def _v_raw_response(cls, v: Any) -> bool:
        return _coerce_bool_false(v)

    @field_validator("response_path", mode="before")
    @classmethod
    def _v_response_path(cls, v: Any) -> Optional[str]:
        return _strip_or_none(v)


class HttpGetParams(CommonRequestParams):
    """method is pinned to GET; no body."""


class HttpHeadParams(CommonRequestParams):
    pass


class HttpOptionsParams(CommonRequestParams):
    pass


class HttpDeleteParams(CommonRequestParams):
    body_type: BodyType = "none"
    data: Any = None  # arbitrary JSON body

    @field_validator("body_type", mode="before")
    @classmethod
    def _v_body_type(cls, v: Any) -> str:
        return _coerce_body_type(v)


class HttpPostParams(CommonRequestParams):
    body_type: BodyType = "json"
    data: Any = None  # arbitrary JSON body

    @field_validator("body_type", mode="before")
    @classmethod
    def _v_body_type(cls, v: Any) -> str:
        return _coerce_body_type(v)


class HttpPutParams(HttpPostParams):
    pass


class HttpPatchParams(HttpPostParams):
    pass


class HttpRequestParams(CommonRequestParams):
    method: Method = "GET"
    body_type: BodyType = "none"
    data: Any = None  # arbitrary JSON body

    @field_validator("method", mode="before")
    @classmethod
    def _v_method(cls, v: Any) -> str:
        return _coerce_method(v)

    @field_validator("body_type", mode="before")
    @classmethod
    def _v_body_type(cls, v: Any) -> str:
        return _coerce_body_type(v)


class UploadFileParams(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    rest_api: str = ""
    method: Method = "POST"
    upload_mode: UploadMode = "multipart"
    field_name: str = "file"
    content_type: str = "application/octet-stream"
    # Any of these may carry the file reference (str IRI / dict record / local path).
    attachment_id: FileRef = None
    file_iri: FileRef = None
    file_path: FileRef = None
    filename: str = ""
    extra_fields: dict[str, Any] = Field(default_factory=dict)
    header: dict[str, str] = Field(default_factory=dict)
    parameter: dict[str, Any] = Field(default_factory=dict)
    timeout: Optional[int] = None
    follow_redirects: bool = True
    response_path: Optional[str] = None
    raw_response: bool = False

    @field_validator("rest_api", "filename", mode="before")
    @classmethod
    def _v_strip(cls, v: Any) -> str:
        return _strip(v)

    @field_validator("method", mode="before")
    @classmethod
    def _v_method(cls, v: Any) -> str:
        return _coerce_method(v)

    @field_validator("upload_mode", mode="before")
    @classmethod
    def _v_upload_mode(cls, v: Any) -> str:
        return str(v).strip().lower() if v else "multipart"

    @field_validator("field_name", mode="before")
    @classmethod
    def _v_field_name(cls, v: Any) -> str:
        return _strip(v) or "file"

    @field_validator("content_type", mode="before")
    @classmethod
    def _v_content_type(cls, v: Any) -> str:
        return _strip(v) or "application/octet-stream"

    @field_validator("extra_fields", mode="before")
    @classmethod
    def _v_extra_fields(cls, v: Any) -> dict[str, Any]:
        return _to_dict(v)

    @field_validator("header", mode="before")
    @classmethod
    def _v_header(cls, v: Any) -> dict[str, str]:
        return _to_dict(v)

    @field_validator("parameter", mode="before")
    @classmethod
    def _v_parameter(cls, v: Any) -> dict[str, Any]:
        return _coerce_param_dict(v)

    @field_validator("timeout", mode="before")
    @classmethod
    def _v_timeout(cls, v: Any) -> Optional[int]:
        return _coerce_int_or_none(v)

    @field_validator("follow_redirects", mode="before")
    @classmethod
    def _v_follow_redirects(cls, v: Any) -> bool:
        return _coerce_bool(v)

    @field_validator("raw_response", mode="before")
    @classmethod
    def _v_raw_response(cls, v: Any) -> bool:
        return _coerce_bool_false(v)

    @field_validator("response_path", mode="before")
    @classmethod
    def _v_response_path(cls, v: Any) -> Optional[str]:
        return _strip_or_none(v)


class DownloadFileParams(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    rest_api: str = ""
    method: Method = "GET"
    create_attachment: bool = True
    filename: str = ""
    attachment_name: str = ""
    description: str = ""
    header: dict[str, str] = Field(default_factory=dict)
    parameter: dict[str, Any] = Field(default_factory=dict)
    body_type: BodyType = "none"
    data: Any = None  # arbitrary JSON body
    timeout: Optional[int] = None
    follow_redirects: bool = True

    @field_validator("rest_api", "filename", "attachment_name", "description", mode="before")
    @classmethod
    def _v_strip(cls, v: Any) -> str:
        return _strip(v)

    @field_validator("method", mode="before")
    @classmethod
    def _v_method(cls, v: Any) -> str:
        return _coerce_method(v)

    @field_validator("create_attachment", mode="before")
    @classmethod
    def _v_create_attachment(cls, v: Any) -> bool:
        return _coerce_bool(v)

    @field_validator("header", mode="before")
    @classmethod
    def _v_header(cls, v: Any) -> dict[str, str]:
        return _to_dict(v)

    @field_validator("parameter", mode="before")
    @classmethod
    def _v_parameter(cls, v: Any) -> dict[str, Any]:
        return _coerce_param_dict(v)

    @field_validator("body_type", mode="before")
    @classmethod
    def _v_body_type(cls, v: Any) -> str:
        return _coerce_body_type(v)

    @field_validator("timeout", mode="before")
    @classmethod
    def _v_timeout(cls, v: Any) -> Optional[int]:
        return _coerce_int_or_none(v)

    @field_validator("follow_redirects", mode="before")
    @classmethod
    def _v_follow_redirects(cls, v: Any) -> bool:
        return _coerce_bool(v)


class PaginateParams(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    rest_api: str = ""
    pagination_mode: PaginationMode = "link_header"
    items_path: Optional[str] = None
    next_url_path: Optional[str] = None
    page_param_name: str = "page"
    start_page: int = 1
    max_pages: int = 50
    method: Method = "GET"
    body_type: BodyType = "none"
    data: Any = None  # arbitrary JSON body
    header: dict[str, str] = Field(default_factory=dict)
    parameter: dict[str, Any] = Field(default_factory=dict)
    timeout: Optional[int] = None
    follow_redirects: bool = True
    response_path: Optional[str] = None

    @field_validator("rest_api", mode="before")
    @classmethod
    def _v_rest_api(cls, v: Any) -> str:
        return _strip(v)

    @field_validator("pagination_mode", mode="before")
    @classmethod
    def _v_pagination_mode(cls, v: Any) -> str:
        return str(v).strip() if v else "link_header"

    @field_validator("items_path", "next_url_path", "response_path", mode="before")
    @classmethod
    def _v_strip_or_none(cls, v: Any) -> Optional[str]:
        return _strip_or_none(v)

    @field_validator("page_param_name", mode="before")
    @classmethod
    def _v_page_param_name(cls, v: Any) -> str:
        return _strip(v) or "page"

    @field_validator("start_page", mode="before")
    @classmethod
    def _v_start_page(cls, v: Any) -> int:
        return _coerce_int(1)(v)

    @field_validator("max_pages", mode="before")
    @classmethod
    def _v_max_pages(cls, v: Any) -> int:
        return _coerce_int(50)(v)

    @field_validator("method", mode="before")
    @classmethod
    def _v_method(cls, v: Any) -> str:
        return _coerce_method(v)

    @field_validator("body_type", mode="before")
    @classmethod
    def _v_body_type(cls, v: Any) -> str:
        return _coerce_body_type(v)

    @field_validator("header", mode="before")
    @classmethod
    def _v_header(cls, v: Any) -> dict[str, str]:
        return _to_dict(v)

    @field_validator("parameter", mode="before")
    @classmethod
    def _v_parameter(cls, v: Any) -> dict[str, Any]:
        return _coerce_param_dict(v)

    @field_validator("timeout", mode="before")
    @classmethod
    def _v_timeout(cls, v: Any) -> Optional[int]:
        return _coerce_int_or_none(v)

    @field_validator("follow_redirects", mode="before")
    @classmethod
    def _v_follow_redirects(cls, v: Any) -> bool:
        return _coerce_bool(v)


class FetchRecordsParams(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    fetch_url: Optional[str] = None
    method: Method = "GET"
    pagination_mode: IngestPaginationMode = "none"
    response_path: Optional[str] = None
    body_type: BodyType = "none"
    data: Any = None  # arbitrary JSON body
    header: dict[str, str] = Field(default_factory=dict)
    parameter: dict[str, Any] = Field(default_factory=dict)
    timeout: Optional[int] = None
    follow_redirects: bool = True
    # Pagination sub-params (used when pagination_mode != 'none' -> delegates to http_paginate).
    page_param_name: str = "page"
    start_page: int = 1
    max_pages: int = 50
    next_url_path: Optional[str] = None
    items_path: Optional[str] = None

    @field_validator("fetch_url", "response_path", "next_url_path", "items_path", mode="before")
    @classmethod
    def _v_strip_or_none(cls, v: Any) -> Optional[str]:
        return _strip_or_none(v)

    @field_validator("method", mode="before")
    @classmethod
    def _v_method(cls, v: Any) -> str:
        return _coerce_method(v)

    @field_validator("pagination_mode", mode="before")
    @classmethod
    def _v_pagination_mode(cls, v: Any) -> str:
        return str(v).strip() if v else "none"

    @field_validator("body_type", mode="before")
    @classmethod
    def _v_body_type(cls, v: Any) -> str:
        return _coerce_body_type(v)

    @field_validator("header", mode="before")
    @classmethod
    def _v_header(cls, v: Any) -> dict[str, str]:
        return _to_dict(v)

    @field_validator("parameter", mode="before")
    @classmethod
    def _v_parameter(cls, v: Any) -> dict[str, Any]:
        return _coerce_param_dict(v)

    @field_validator("timeout", mode="before")
    @classmethod
    def _v_timeout(cls, v: Any) -> Optional[int]:
        return _coerce_int_or_none(v)

    @field_validator("follow_redirects", mode="before")
    @classmethod
    def _v_follow_redirects(cls, v: Any) -> bool:
        return _coerce_bool(v)

    @field_validator("page_param_name", mode="before")
    @classmethod
    def _v_page_param_name(cls, v: Any) -> str:
        return _strip(v) or "page"

    @field_validator("start_page", mode="before")
    @classmethod
    def _v_start_page(cls, v: Any) -> int:
        return _coerce_int(1)(v)

    @field_validator("max_pages", mode="before")
    @classmethod
    def _v_max_pages(cls, v: Any) -> int:
        return _coerce_int(50)(v)


# --------------------------------------------------------------------------- #
# Response
# --------------------------------------------------------------------------- #


class ParsedResponse(BaseModel):
    """Structured value returned by every verb action.

    ``as_output()`` reproduces the legacy dict shape exactly: in normal mode
    ``body`` is set and ``content_base64`` is None (excluded); in raw mode
    ``content_base64`` is set and ``body`` is None (excluded).
    """

    model_config = ConfigDict(populate_by_name=True)

    status_code: int
    headers: dict[str, str]
    # Any JSON value: dict, list, str, int, float, bool, or None (a response_path
    # pluck can yield a scalar; raw bytes are wrapped in a dict envelope).
    body: Any = None  # arbitrary JSON value (dict/list/str/scalar/None)
    content_base64: Optional[str] = None

    def as_output(self) -> dict[str, Any]:
        return self.model_dump(exclude_none=True)


# --------------------------------------------------------------------------- #
# Internal data shapes (non-API, program-built -> dataclasses)
# --------------------------------------------------------------------------- #


@dataclass
class CachedToken:
    """Value held in the module-level OAuth2 token cache."""

    access_token: str
    expires_at: float


@dataclass
class PreparedBody:
    """Output of _prepare_body: the requests.request kwargs for a body."""

    data: Any = None  # arbitrary JSON body
    json_payload: Any = None
    files: Any = None
