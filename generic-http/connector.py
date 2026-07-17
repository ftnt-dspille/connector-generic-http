from typing import Any

from connectors.core.connector import Connector, ConnectorError, get_logger

from .operations import check_health, http_ops

logger = get_logger("generic-http")


class HTTP(Connector):  # type: ignore[misc]
    """Connector base comes from the untyped FortiSOAR runtime (connectors.core),
    so mypy sees it as Any; the subclass-ignore is intentional."""

    def execute(
        self, config: dict[str, Any], operation: str, params: dict[str, Any], **kwargs: Any
    ) -> dict[str, Any]:
        logger.info(f"In execute() Operation:[{operation}]")
        func = http_ops.get(operation)
        if func is None:
            logger.info(f"Unsupported operation [{operation}]")
            raise ConnectorError("Unsupported operation")
        return func(config, params)

    def check_health(self, config: dict[str, Any]) -> bool:
        return check_health(config)
