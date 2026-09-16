"""Unit tests for probe driver pure-logic helpers (no network)."""

from kb_connector.probe.driver import (
    _diff_round_trip,
    _flatten_paths,
    _substitute,
)


def test_flatten_paths_nested():
    obj = {
        "type": "WEB",
        "connectionConfiguration": {"authType": "NO_AUTH"},
        "crawlConfiguration": {"crawlDepth": 3},
    }
    flat = _flatten_paths(obj)
    assert flat["type"] == "WEB"
    assert flat["connectionConfiguration.authType"] == "NO_AUTH"
    assert flat["crawlConfiguration.crawlDepth"] == 3


def test_flatten_paths_list_is_leaf():
    obj = {"siteUrls": ["a", "b"]}
    flat = _flatten_paths(obj)
    assert flat["siteUrls"] == ["a", "b"]


def test_flatten_paths_empty_dict_is_leaf():
    obj = {"emptyConfig": {}}
    flat = _flatten_paths(obj)
    assert flat["emptyConfig"] == {}


def test_substitute_exact_match():
    obj = {"secretArn": "__SECRET_ARN__", "other": "keep"}
    result = _substitute(obj, "__SECRET_ARN__", "arn:aws:real")
    assert result["secretArn"] == "arn:aws:real"
    assert result["other"] == "keep"


def test_substitute_nested():
    obj = {"connection": {"secretArn": "__SECRET_ARN__"}}
    result = _substitute(obj, "__SECRET_ARN__", "arn:real")
    assert result["connection"]["secretArn"] == "arn:real"


def test_substitute_in_list():
    obj = {"items": ["__SECRET_ARN__", "other"]}
    result = _substitute(obj, "__SECRET_ARN__", "arn:real")
    assert result["items"] == ["arn:real", "other"]


def test_substitute_no_partial_match():
    # Only exact-equal leaf strings are replaced, not substrings
    obj = {"text": "prefix__SECRET_ARN__suffix"}
    result = _substitute(obj, "__SECRET_ARN__", "arn:real")
    assert result["text"] == "prefix__SECRET_ARN__suffix"


def test_diff_round_trip_detects_dropped(tmp_path):
    """Round-trip diff captures fields the service dropped."""
    sent = {"type": "WEB", "aclEnabled": True, "customField": "value"}
    # GetDataSource returns connectorParameters as a JSON string, missing customField
    import json
    get_resp = {
        "dataSource": {
            "status": "AVAILABLE",
            "dataSourceConfiguration": {
                "managedKnowledgeBaseConnectorConfiguration": {
                    "connectorParameters": json.dumps(
                        {"type": "WEB", "aclEnabled": True}
                    )
                }
            },
        }
    }
    events: list = []
    _diff_round_trip(sent, get_resp, str(tmp_path), events)

    # Read the written diff
    diff_file = tmp_path / "03b-round-trip-diff.json"
    assert diff_file.exists()
    diff = json.loads(diff_file.read_text())
    assert "customField" in diff["dropped_by_service"]
    assert diff["data_source_status"] == "AVAILABLE"


def test_diff_round_trip_detects_injected(tmp_path):
    """Round-trip diff captures fields the service injected."""
    import json
    sent = {"type": "WEB"}
    get_resp = {
        "dataSource": {
            "status": "AVAILABLE",
            "dataSourceConfiguration": {
                "managedKnowledgeBaseConnectorConfiguration": {
                    "connectorParameters": json.dumps(
                        {"type": "WEB", "version": "1"}
                    )
                }
            },
        }
    }
    events: list = []
    _diff_round_trip(sent, get_resp, str(tmp_path), events)
    diff = json.loads((tmp_path / "03b-round-trip-diff.json").read_text())
    assert "version" in diff["injected_by_service"]


# --- Capturing a failed step --------------------------------------------------


def _target_whose_calls_fail():
    """A real BmkbTarget whose SDK client fails every operation."""
    from botocore.exceptions import ClientError

    from kb_connector.targets.bmkb import BmkbTarget

    error = ClientError(
        {"Error": {"Code": "ValidationException", "Message": "bad input"}},
        "CreateDataSource",
    )

    class _RaisingClient:
        def __getattr__(self, operation):
            def call(**kwargs):
                raise error

            return call

    class _FakeSession:
        def client(self, service_name, **kwargs):
            return _RaisingClient()

    target = BmkbTarget(session=_FakeSession(), region="us-west-2")
    target._client = _RaisingClient()
    target._runtime = _RaisingClient()
    return target


def test_attempt_captures_a_service_failure_instead_of_letting_it_escape():
    """A probe run exists to record what the service did, so a failing call has
    to be captured rather than abort the run before the summary is written.

    This goes through a real target on purpose: capturing depends on the target
    reporting SDK failures as AwsError, and if that translation is dropped the
    exception escapes here and the run produces no summary at all.
    """
    from kb_connector.probe.driver import _attempt

    target = _target_whose_calls_fail()
    ok, resp = _attempt(lambda: target.create_data_source_raw("KB123456789", {}))
    assert ok is False
    assert "ValidationException" in resp["error"]
