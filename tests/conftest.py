"""Shared test fixtures for the HTTP connector test suite.

The connector imports from FortiSOAR's runtime packages (``connectors.core.connector``,
``connectors.cyops_utilities.builtins``, ``integrations.crudhub``, etc.) which are not
installable outside the FortiSOAR appliance. This conftest installs lightweight stubs
into ``sys.modules`` *before* any test imports the connector, so ``operations.py`` can
be imported and unit-tested in isolation.

It also exposes a ``load_connector`` fixture that imports the connector's ``operations``
module from the sibling ``generic-http/`` package under an isolated alias.
"""

from __future__ import annotations

import importlib.util
import logging
import sys
import types
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Framework stubs — installed at import time so that any subsequent
# `from connectors.core.connector import ...` resolves cleanly.
# ---------------------------------------------------------------------------

def _install_framework_stubs() -> None:
    if 'connectors' in sys.modules:
        return

    connectors_pkg = types.ModuleType('connectors')
    connectors_pkg.__path__ = []  # mark as package
    core_pkg = types.ModuleType('connectors.core')
    core_pkg.__path__ = []
    cyops_pkg = types.ModuleType('connectors.cyops_utilities')
    cyops_pkg.__path__ = []
    integrations_pkg = types.ModuleType('integrations')
    integrations_pkg.__path__ = []

    core_connector = types.ModuleType('connectors.core.connector')

    class ConnectorError(Exception):
        """Stub matching FortiSOAR's ConnectorError."""

    class Connector:
        """Stub base class — connectors only override execute() / check_health()."""

        def execute(self, config, operation, params, **kwargs):  # pragma: no cover
            raise NotImplementedError

        def check_health(self, config):  # pragma: no cover
            return True

    def get_logger(name):
        return logging.getLogger(name)

    core_connector.ConnectorError = ConnectorError
    core_connector.Connector = Connector
    core_connector.get_logger = get_logger

    builtins_mod = types.ModuleType('connectors.cyops_utilities.builtins')
    builtins_mod.download_file_from_cyops = lambda *a, **k: {'@id': 'stub', 'filename': 'stub'}
    builtins_mod.create_file_from_string = lambda *a, **k: {'@id': 'stub'}

    crudhub_mod = types.ModuleType('integrations.crudhub')
    crudhub_mod.make_request = lambda *a, **k: {}

    sys.modules['connectors'] = connectors_pkg
    sys.modules['connectors.core'] = core_pkg
    sys.modules['connectors.core.connector'] = core_connector
    sys.modules['connectors.cyops_utilities'] = cyops_pkg
    sys.modules['connectors.cyops_utilities.builtins'] = builtins_mod
    sys.modules['integrations'] = integrations_pkg
    sys.modules['integrations.crudhub'] = crudhub_mod

    # operations.py imports `from django.conf import settings` at module load.
    if 'django' not in sys.modules:
        django_pkg = types.ModuleType('django')
        django_pkg.__path__ = []
        django_conf = types.ModuleType('django.conf')

        class _Settings:
            def __getattr__(self, item):
                return None

        django_conf.settings = _Settings()
        sys.modules['django'] = django_pkg
        sys.modules['django.conf'] = django_conf

    # operations.py imports requests_toolbelt for multipart upload.
    if 'requests_toolbelt' not in sys.modules:
        try:
            import requests_toolbelt  # noqa: F401
        except ImportError:
            rt_pkg = types.ModuleType('requests_toolbelt')
            rt_pkg.__path__ = []
            rt_multipart = types.ModuleType('requests_toolbelt.multipart')
            rt_multipart.__path__ = []
            rt_encoder = types.ModuleType('requests_toolbelt.multipart.encoder')

            class _MultipartEncoder:
                def __init__(self, fields, *a, **k):
                    self.fields = fields
                    self.content_type = 'multipart/form-data; boundary=stub'

            rt_encoder.MultipartEncoder = _MultipartEncoder
            sys.modules['requests_toolbelt'] = rt_pkg
            sys.modules['requests_toolbelt.multipart'] = rt_multipart
            sys.modules['requests_toolbelt.multipart.encoder'] = rt_encoder


_install_framework_stubs()


# ---------------------------------------------------------------------------
# Connector module loader fixture
# ---------------------------------------------------------------------------

# tests/ sits next to the generic-http/ package at the repo root.
CONNECTOR_DIR = Path(__file__).resolve().parent.parent


def _load_connector_operations(connector_name: str):
    """Import a connector's operations.py as a top-level module so its
    `from .constants import *` style relative imports do not blow up.

    Strategy: register the connector dir as a package, then load operations
    via importlib.
    """
    conn_dir = CONNECTOR_DIR / connector_name
    if not conn_dir.is_dir():
        raise RuntimeError(f"Connector dir not found: {conn_dir}")

    pkg_alias = 'fsr_test_pkg_{}'.format(connector_name.replace('-', '_'))

    # Re-register fresh each call so per-test side effects on module globals don't leak.
    for mod_name in list(sys.modules):
        if mod_name == pkg_alias or mod_name.startswith(pkg_alias + '.'):
            del sys.modules[mod_name]

    pkg = types.ModuleType(pkg_alias)
    pkg.__path__ = [str(conn_dir)]
    sys.modules[pkg_alias] = pkg

    # Pre-load constants if present so `from .constants import *` resolves.
    constants_path = conn_dir / 'constants.py'
    if constants_path.is_file():
        spec = importlib.util.spec_from_file_location(pkg_alias + '.constants', constants_path)
        constants_mod = importlib.util.module_from_spec(spec)
        sys.modules[pkg_alias + '.constants'] = constants_mod
        spec.loader.exec_module(constants_mod)

    ops_path = conn_dir / 'operations.py'
    spec = importlib.util.spec_from_file_location(pkg_alias + '.operations', ops_path)
    ops_mod = importlib.util.module_from_spec(spec)
    sys.modules[pkg_alias + '.operations'] = ops_mod
    spec.loader.exec_module(ops_mod)
    return ops_mod


@pytest.fixture
def load_connector():
    """Returns a callable: ``ops = load_connector('generic-http')``."""
    return _load_connector_operations
