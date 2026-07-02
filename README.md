# HTTP Connector

The full connector documentation is the README that ships inside the connector package:

**→ [`http/README.md`](http/README.md)**

That file is the single source of truth (it ships in the RPM and renders in the FortiSOAR
connector store). This root README is intentionally a thin pointer to avoid keeping two
byte-identical copies in sync.

## Tests

```bash
pip install -r requirements-dev.txt
pytest -v
```

The mock test suite (`tests/test_http.py`) runs offline against `requests-mock`. Live
tests against a real FortiSOAR appliance (`tests/test_http_live_soar.py`) are opt-in and
read-only — enable with `RUN_SOAR_LIVE_TESTS=1` and a `.env` (or env vars) providing
`BASE_URL` + `API_KEY`.

