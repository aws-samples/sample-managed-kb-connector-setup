"""Connector specs, keyed by config `type`."""

from __future__ import annotations

from kb_connector.connectors.base import ConnectorSpec


def get_spec(connector_type: str) -> ConnectorSpec | None:
    """The spec for a config `type`, or None for an unknown type."""
    return all_specs().get(connector_type)


def all_specs() -> dict[str, ConnectorSpec]:
    from kb_connector.connectors.confluence import ConfluenceConnector
    from kb_connector.connectors.googledrive import GoogleDriveConnector
    from kb_connector.connectors.onedrive import OneDriveConnector
    from kb_connector.connectors.s3 import S3Connector
    from kb_connector.connectors.sharepoint import SharePointConnector
    from kb_connector.connectors.web import WebConnector

    specs: list[ConnectorSpec] = [
        SharePointConnector(), OneDriveConnector(), S3Connector(),
        WebConnector(), ConfluenceConnector(), GoogleDriveConnector(),
    ]
    return {s.type: s for s in specs}
