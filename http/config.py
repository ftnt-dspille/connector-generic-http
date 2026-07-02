# Copyright (C) 2026 Fortinet Inc. — MIT License
"""Pydantic model for the HTTP connector's configuration (the ``config``
dict FortiSOAR passes to every operation) and the discriminated union over
the seven authentication schemes.

``HttpConfig`` accepts the FortiSOAR field names and coerces the string-y
numeric / JSON / CSV fields (``port``, ``timeout``, ``retry_on_status``,
``default_headers``, ``login_request_headers``) into their typed equivalents.

Per-auth-type *required* fields are intentionally NOT enforced here. The
legacy connector loads a config with missing auth fields cleanly and surfaces
the error only when the auth is actually used (so ``check_health`` on a
partially-configured Token-Login connection still succeeds). That behavior is
preserved by keeping the required-field checks at the call site
(``_apply_auth`` / ``_token_login`` / ``_oauth2_client_credentials_token``).
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any, Final, Literal, TypeVar, Union

from connectors.core.connector import ConnectorError
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from .models import _to_dict

# --------------------------------------------------------------------------- #
# Auth discriminator
# --------------------------------------------------------------------------- #

AuthType = Literal[
    "None",
    "Basic",
    "Bearer Token",
    "API Key Header",
    "API Key Query Param",
    "OAuth2 Client Credentials",
    "Token Login",
]

# Discriminator values (also the Literal members above).
AUTH_NONE: Final = "None"
AUTH_BASIC: Final = "Basic"
AUTH_BEARER: Final = "Bearer Token"
AUTH_API_KEY_HEADER: Final = "API Key Header"  # pragma: allowlist secret
AUTH_API_KEY_QUERY: Final = "API Key Query Param"  # pragma: allowlist secret
AUTH_OAUTH2_CC: Final = "OAuth2 Client Credentials"
AUTH_TOKEN_LOGIN: Final = "Token Login"


# --------------------------------------------------------------------------- #
# Shared before-validators
# --------------------------------------------------------------------------- #


def _strip(v: Any) -> str:
    return str(v).strip() if v is not None else ""


def _coerce_int(default: int) -> Callable[[Any], int]:
    def _coerce(v: Any) -> int:
        if v in (None, "", 0):
            return default
        return int(v)

    return _coerce


def _coerce_float(default: float) -> Callable[[Any], float]:
    def _coerce(v: Any) -> float:
        if v in (None, ""):
            return default
        return float(v)

    return _coerce


def _coerce_bool(v: Any) -> bool:
    return bool(v) if v is not None else True


def _coerce_retry_statuses(v: Any) -> tuple[int, ...]:
    if v in (None, ""):
        return (429, 500, 502, 503, 504)
    if isinstance(v, str):
        return tuple(int(x.strip()) for x in v.split(",") if x.strip().isdigit())
    if isinstance(v, (list, tuple)):
        return tuple(int(x) for x in v if str(x).isdigit())
    return (429, 500, 502, 503, 504)


# --------------------------------------------------------------------------- #
# Connection configuration
# --------------------------------------------------------------------------- #


class HttpConfig(BaseModel):
    """Flat mirror of the FortiSOAR connection config dict.

    All auth-variant fields live at the top level (FSR's config is flat); the
    :func:`auth_from_config` helper groups them into the typed
    :data:`AuthConfig` variant for narrowing in ``_apply_auth``.
    """

    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    # Connection / base URL
    server_url: str = ""
    port: int | str | None = None
    verify_ssl: bool = True
    # None when unset so each call site applies its own default (60 for requests,
    # 30 for check_health, 300 for upload/download) — matches legacy behavior.
    timeout: int | None = None
    default_headers: dict[str, str] = Field(default_factory=dict)
    return_on_error: bool = True

    # Retry
    max_retries: int = 0
    backoff_factor: float = 0.5
    retry_on_status: tuple[int, ...] = (429, 500, 502, 503, 504)

    # Ingestion defaults
    default_fetch_url: str | None = None
    default_response_path: str | None = None

    # Auth discriminator + flat auth fields (one variant's keys per auth_type)
    auth_type: AuthType = AUTH_NONE
    basic_username: str = ""
    basic_password: str = ""
    bearer_token: str = ""
    api_key_header_name: str = ""
    api_key_param_name: str = ""
    api_key: str = ""
    oauth_token_url: str = ""
    oauth_client_id: str = ""
    oauth_client_secret: str = ""
    oauth_scope: str = ""
    login_url: str = ""
    login_body_type: Literal["json", "header_only"] = "json"
    login_request_headers: dict[str, str] = Field(default_factory=dict)
    login_username: str = ""
    login_password: str = ""
    login_username_field: str = ""
    login_password_field: str = ""
    login_token_path: str | None = None
    login_header_name: str = ""
    login_header_prefix: str = ""

    @field_validator("timeout", mode="before")
    @classmethod
    def _v_timeout(cls, v: Any) -> int | None:
        if v in (None, "", 0):
            return None
        return int(v)

    @field_validator("max_retries", mode="before")
    @classmethod
    def _v_max_retries(cls, v: Any) -> int:
        return _coerce_int(0)(v)

    @field_validator("backoff_factor", mode="before")
    @classmethod
    def _v_backoff(cls, v: Any) -> float:
        return _coerce_float(0.5)(v)

    @field_validator("verify_ssl", "return_on_error", mode="before")
    @classmethod
    def _v_bool(cls, v: Any) -> bool:
        return _coerce_bool(v)

    @field_validator("retry_on_status", mode="before")
    @classmethod
    def _v_retry_on_status(cls, v: Any) -> tuple[int, ...]:
        return _coerce_retry_statuses(v)

    @field_validator("default_headers", "login_request_headers", mode="before")
    @classmethod
    def _v_json_dict(cls, v: Any) -> dict[str, str]:
        return _to_dict(v)

    @field_validator(
        "server_url",
        "basic_username",
        "basic_password",
        "bearer_token",
        "api_key_header_name",
        "api_key_param_name",
        "api_key",
        "oauth_token_url",
        "oauth_client_id",
        "oauth_client_secret",
        "oauth_scope",
        "login_url",
        "login_username",
        "login_password",
        "login_username_field",
        "login_password_field",
        "login_header_name",
        mode="before",
    )
    @classmethod
    def _v_strip(cls, v: Any) -> str:
        return _strip(v)

    @field_validator("login_header_prefix", mode="before")
    @classmethod
    def _v_login_header_prefix(cls, v: Any) -> str:
        # NOT stripped — a prefix like 'Bearer ' intentionally keeps its trailing space.
        return v if v is not None else ""

    @field_validator("auth_type", mode="before")
    @classmethod
    def _v_auth_type(cls, v: Any) -> str:
        v = _strip(v)
        return v or AUTH_NONE

    @field_validator("login_token_path", "default_fetch_url", "default_response_path", mode="before")
    @classmethod
    def _v_strip_or_none(cls, v: Any) -> str | None:
        v = _strip(v)
        return v or None


# --------------------------------------------------------------------------- #
# Auth discriminated union — groups each scheme's fields for type narrowing.
# Required-field enforcement happens at the call site (see operations.py).
# --------------------------------------------------------------------------- #


class NoAuth(BaseModel):
    auth_type: Literal["None"] = AUTH_NONE


class BasicAuth(BaseModel):
    auth_type: Literal["Basic"] = AUTH_BASIC
    basic_username: str = ""
    basic_password: str = ""


class BearerAuth(BaseModel):
    auth_type: Literal["Bearer Token"] = AUTH_BEARER
    bearer_token: str = ""


class ApiKeyHeaderAuth(BaseModel):
    auth_type: Literal["API Key Header"] = AUTH_API_KEY_HEADER
    api_key_header_name: str = ""
    api_key: str = ""


class ApiKeyQueryAuth(BaseModel):
    auth_type: Literal["API Key Query Param"] = AUTH_API_KEY_QUERY
    api_key_param_name: str = ""
    api_key: str = ""


class OAuth2ClientCredentialsAuth(BaseModel):
    auth_type: Literal["OAuth2 Client Credentials"] = AUTH_OAUTH2_CC
    oauth_token_url: str = ""
    oauth_client_id: str = ""
    oauth_client_secret: str = ""
    oauth_scope: str = ""


class TokenLoginAuth(BaseModel):
    auth_type: Literal["Token Login"] = AUTH_TOKEN_LOGIN
    login_url: str = ""
    login_body_type: Literal["json", "header_only"] = "json"
    login_request_headers: dict[str, str] = Field(default_factory=dict)
    login_username: str = ""
    login_password: str = ""
    login_username_field: str = ""
    login_password_field: str = ""
    login_token_path: str | None = None
    login_header_name: str = ""
    login_header_prefix: str = ""


AuthConfig = Union[
    NoAuth,
    BasicAuth,
    BearerAuth,
    ApiKeyHeaderAuth,
    ApiKeyQueryAuth,
    OAuth2ClientCredentialsAuth,
    TokenLoginAuth,
]


def auth_from_config(cfg: HttpConfig) -> AuthConfig:
    """Build the typed auth variant from the flat config, dispatched on auth_type."""
    a = cfg.auth_type
    if a == AUTH_NONE:
        return NoAuth()
    if a == AUTH_BASIC:
        return BasicAuth(basic_username=cfg.basic_username, basic_password=cfg.basic_password)
    if a == AUTH_BEARER:
        return BearerAuth(bearer_token=cfg.bearer_token)
    if a == AUTH_API_KEY_HEADER:
        return ApiKeyHeaderAuth(api_key_header_name=cfg.api_key_header_name, api_key=cfg.api_key)
    if a == AUTH_API_KEY_QUERY:
        return ApiKeyQueryAuth(api_key_param_name=cfg.api_key_param_name, api_key=cfg.api_key)
    if a == AUTH_OAUTH2_CC:
        return OAuth2ClientCredentialsAuth(
            oauth_token_url=cfg.oauth_token_url,
            oauth_client_id=cfg.oauth_client_id,
            oauth_client_secret=cfg.oauth_client_secret,
            oauth_scope=cfg.oauth_scope,
        )
    if a == AUTH_TOKEN_LOGIN:
        return TokenLoginAuth(
            login_url=cfg.login_url,
            login_body_type=cfg.login_body_type,
            login_request_headers=cfg.login_request_headers,
            login_username=cfg.login_username,
            login_password=cfg.login_password,
            login_username_field=cfg.login_username_field,
            login_password_field=cfg.login_password_field,
            login_token_path=cfg.login_token_path,
            login_header_name=cfg.login_header_name,
            login_header_prefix=cfg.login_header_prefix,
        )
    # Unreachable: auth_type is a Literal, so pydantic rejects unknown values at parse.
    raise ConnectorError(f"Unsupported Authentication Type: {a}")


# --------------------------------------------------------------------------- #
# Parse helpers — wrap pydantic ValidationError as ConnectorError for the UI
# --------------------------------------------------------------------------- #


def _parse_config(config: HttpConfig | Mapping[str, Any] | None) -> HttpConfig:
    """Parse the raw FortiSOAR config dict into HttpConfig.

    Accepts a dict (the normal case) or an already-parsed HttpConfig (so
    internal callers can pass either without re-validating). Validation
    errors surface as ConnectorError so the FortiSOAR UI shows a message.
    """
    if isinstance(config, HttpConfig):
        return config
    try:
        return HttpConfig.model_validate(config or {})
    except ValidationError as e:
        raise ConnectorError(f"HTTP connector configuration is invalid: {e}") from e


_TModel = TypeVar("_TModel", bound=BaseModel)


def _validate(model_cls: type[_TModel], data: Mapping[str, Any] | None, ctx: str = "") -> _TModel:
    """Validate a params dict into the given model, surfacing ValidationError as ConnectorError."""
    try:
        return model_cls.model_validate(data or {})
    except ValidationError as e:
        prefix = f"HTTP connector {ctx}: " if ctx else "HTTP connector: "
        raise ConnectorError(f"{prefix}{e}") from e
