#### 3.0.2

##### What's Changed

- **The README now has a table of contents, and every section is linkable.** Section titles that were bold text are real headings, so each one has an anchor you can point someone at (for example `#oauth2-client-credentials-machine-to-machine`). Headings are ASCII only, which keeps those anchors stable and predictable.
- Documentation and connection-field tooltips were rewritten to drop em-dashes, so the prose reads the same without them.
- Fixed three corrupted replacement characters in the 2.1.0 release notes, left behind by a bad encoding round-trip and shipped in every release since.

No functional change: `name` (`generic-http`), `label` (`Generic HTTP`), operations, parameters, and connection fields are unchanged from 3.0.1. Tooltip wording is the only thing that moves in the product UI.

---

#### 3.0.1

##### What's Changed

- **Display label is now "Generic HTTP"** (was "HTTP"). The bare "HTTP" label read as though it owned the protocol namespace in the connector store and the playbook step picker, the same confusion the 3.0.0 `name` rename set out to fix. The sample playbook step labels and collection name follow the new label.
- Docs: the auth-pattern walkthroughs ("Static API key in a header", "OAuth2 client credentials (machine-to-machine)", etc.) are real headings now instead of bold text, so they get anchor links and appear in the README outline.

No functional change: `name` (`generic-http`), operations, parameters, and connection fields are unchanged from 3.0.0.

---

#### 3.0.0

##### Breaking changes

- **The connector's `name` has changed from `http` to `generic-http`.** The old name collided with the FortiSOAR namespace. FortiSOAR keys a connector by its `name`, so this installs as a *new* connector rather than upgrading the existing one:
  - The existing `http` connector configuration does **not** carry over, so re-create the configuration under `generic-http` after installing.
  - Any playbook step bound to the old `http` connector must be re-pointed at `generic-http`. Such steps fail rather than silently following the rename.
  - Uninstall the old `http` connector once every playbook has been migrated.
- The connector package directory is now `generic-http/` (was `http/`), and the release tarball is `connector-generic-http-<version>.tgz`. This also resolves the old directory shadowing Python's stdlib `http` module.

##### What's Changed

- No operation, parameter, or connection-field changes. Every action behaves exactly as in 2.1.0. This release is a rename only.

---

#### 2.1.0

##### What's Added

- **Typed configuration & operation params (pydantic v2).** The connector's configuration and every operation's `params` are now validated and normalized through pydantic models. Legacy shapes (JSON strings, `[{key, value}]` lists, string-y ints, the `'text'` body alias) are coerced into clean typed fields automatically, with no behavior change for existing playbooks, but invalid configs now fail fast with a clear validation message instead of a downstream `KeyError`.
- **`pydantic>=2.7` is now a runtime dependency** (see `requirements.txt`). The FortiSOAR 8.0 appliance runtime already ships pydantic v2; on 7.6.x it installs automatically when the connector is deployed.

##### What's Fixed

- Type annotations now use `Optional[X]`/`Union[X, Y]` (not PEP 604 `X | None`) in pydantic model fields, so the connector imports cleanly on the Python 3.9 appliance runtime (7.6.x). `from __future__ import annotations` does not defer pydantic field-resolution, so the union form is required.

##### Breaking changes

- None for existing configurations or playbooks. The 2.0.x connection-level fields and action parameters are unchanged; the pydantic layer is additive validation only.

---

#### The HTTP connector has been substantially expanded in version 2.0.0:

##### What's Added

- **Authentication Type configuration picklist** with conditional credential fields:
    - `None` (existing behavior)
    - `Basic` (username + password)
    - `Bearer Token`
    - `API Key Header` (configurable header name + masked value)
    - `API Key Query Param` (configurable param name + masked value)
    - `OAuth2 Client Credentials` (token URL + client ID + client secret + scope; access tokens are cached in-process keyed by `(token_url, client_id, scope)` and refreshed 30 seconds before expiry)
- **Per-action authentication override** on every action: if `Per-Call Auth Override` is set, that single call uses the supplied auth instead of the connection-level one. All matching credential fields are exposed.
- **Connection-level Default Custom Headers**: a JSON field whose contents are merged into every outgoing request. Per-action `Headers` win on collision.
- **Per-action knobs** added across all verb actions:
    - `Body Type` selector: `none` / `json` / `form` / `raw` / `multipart`.
    - `Timeout` override.
    - `Follow Redirects` toggle.
    - `Response Path`: pluck a sub-field from the response body via dot/bracket notation (e.g. `data.results[0].id`).
    - `Raw Response (binary-safe)`: return content as base64 instead of parsing.
- **Smart response parsing**: the connector now auto-detects the `Content-Type` and returns JSON as a parsed object, text/XML/HTML as a string, and binary content wrapped in a base64 envelope. Every response includes `status_code`, `headers`, and `body`.
- **Retry / backoff**: connection-level `Max Retries`, `Retry Backoff Factor`, and `Retry On Status` (defaults to `429,500,502,503,504`). Implemented with `urllib3`'s `Retry` and respects the `Retry-After` header.
- **Return On HTTP Error** toggle: when true (default), non-2xx responses are returned to the playbook so it can branch on `status_code`; when false, they raise.
- **New operation: HTTP Request (Any Method)**: a single freeform action with a method picklist, replacing the need to choose between seven verb-specific actions for ad-hoc calls.
- **New operation: HTTP Paginate**: walks paginated endpoints and concatenates results. Three modes:
    - `link_header`: RFC 5988 `next` rel link.
    - `next_url_path`: next URL plucked from a JSON path inside the response body.
    - `page_param`: bumps a numeric query parameter until the items list comes back empty.
    Returns `{items, pages_fetched, truncated}` with a configurable `Max Pages` cap and infinite-loop protection via a seen-URL set.
- **New operation: Fetch Records (Ingestion)**: calls a configured endpoint, optionally paginates, plucks records via a response path, and returns a flat list. Used by scheduled data ingestion.
- **Data ingestion support**: `ingestion_supported: true` with `scheduled` mode and an `ingestion_config_schema` covering fetch URL, method, response path, pagination mode, and pagination parameters. The `ingest_mapping_template` is intentionally minimal so playbooks can map fields per deployment.

##### What's Improved

- The Server URL is now optional, allowing the connector to be used purely with absolute URLs supplied per action.
- Health check now treats `401` / `403` / `404` responses as healthy (the server is reachable, even if the root URL requires auth).

#### Breaking changes

- The previous connection-level configuration only had `Server URL`, `Port`, and `Verify SSL`. Existing configurations continue to work unchanged: `Authentication Type` defaults to `None`, all new fields default to safe values, and the seven existing verb actions retain their original parameters with the new optional knobs added on top.
