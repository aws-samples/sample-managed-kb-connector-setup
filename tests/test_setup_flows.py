"""Setup, re-run and teardown for every connector type, through the CLI.

AWS and Microsoft Graph are replaced by `_FakeCloud`, which keeps knowledge
bases, data sources, roles, secrets and Entra apps in memory across commands, so
a re-run sees what setup created and teardown sees what is left.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from kb_connector.core.tagging import Ownership, ProvisionedResource

_ACCOUNT = "111122223333"
_TENANT = "11111111-2222-3333-4444-555555555555"


class _FakeTarget:
    def __init__(self, cloud: _FakeCloud):
        self.cloud = cloud

    def create_knowledge_base(self, *, name, role_arn, kms_key_arn=None, tags=None,
                              overrides=None, embedding_model_arn=None):
        kb_id = f"KB{len(self.cloud.kbs):08d}"
        self.cloud.kbs[kb_id] = {"name": name, "roleArn": role_arn, "tags": tags}
        return {"knowledgeBase": {"knowledgeBaseId": kb_id}}

    def get_knowledge_base(self, kb_id):
        return {"knowledgeBase": {"knowledgeBaseId": kb_id, **self.cloud.kbs[kb_id]}}

    def wait_until_kb_active(self, kb_id, **_):
        return "ACTIVE"

    def create_data_source_raw(self, kb_id, payload):
        ds_id = f"DS{len(self.cloud.data_sources):08d}"
        self.cloud.data_sources[ds_id] = {"kb": kb_id, "payload": payload}
        return {"dataSource": {"dataSourceId": ds_id}}

    def get_data_source(self, kb_id, ds_id):
        if ds_id not in self.cloud.data_sources:
            raise RuntimeError("ResourceNotFoundException")
        return {"dataSource": {"status": "AVAILABLE"}}

    def wait_until_ds_available(self, kb_id, ds_id, **_):
        return "AVAILABLE"

    def list_ingestion_jobs(self, kb_id, ds_id, **_):
        return {"ingestionJobSummaries": []}

    def delete_data_source(self, kb_id, ds_id):
        del self.cloud.data_sources[ds_id]

    def delete_knowledge_base(self, kb_id):
        del self.cloud.kbs[kb_id]


class _FakeCloud:
    """In-memory AWS and Entra, installed over the functions setup and teardown call."""

    def __init__(self, monkeypatch, secret_factory):
        self.kbs: dict = {}
        self.data_sources: dict = {}
        self.roles: dict = {}          # name -> {"policies": {...}}
        self.secrets: dict = {}        # name -> body
        self.apps: dict = {}           # display name -> app dict
        self.extended: list = []       # (role_name, secret_arn) for foreign roles
        self.secret_factory = secret_factory
        self._install(monkeypatch)

    # --- data source payload helpers ---------------------------------------------

    def params(self) -> dict:
        (ds,) = self.data_sources.values()
        return ds["payload"]["dataSourceConfiguration"][
            "managedKnowledgeBaseConnectorConfiguration"]["connectorParameters"]

    # --- install ------------------------------------------------------------------

    def _install(self, mp):
        from kb_connector.cli import setup as setup_mod
        from kb_connector.core import provisioning
        from kb_connector.core import teardown as td
        from kb_connector.providers.microsoft import apps
        from kb_connector.providers.microsoft.client import GraphClient

        target = _FakeTarget(self)
        mp.setattr(setup_mod, "_aws_session_and_account", lambda cfg: (MagicMock(), _ACCOUNT))
        mp.setattr(setup_mod, "_build_target", lambda cfg, session: target)
        mp.setattr(setup_mod, "_preflight_aws_ownership", lambda *a, **k: None)
        mp.setattr("time.sleep", lambda _: None)

        def ensure_kb_role(*, role_name, secret_arn, connector_name, **_):
            created = role_name not in self.roles
            role = self.roles.setdefault(role_name, {"policies": {}})
            role["policies"]["kb-connector-access"] = secret_arn
            return ProvisionedResource(
                arn=f"arn:aws:iam::{_ACCOUNT}:role/{role_name}",
                ownership=Ownership.CREATED if created else Ownership.OURS,
            )

        def put_secret(*, name, body, **_):
            created = name not in self.secrets
            self.secrets[name] = body
            return ProvisionedResource(
                arn=f"arn:aws:secretsmanager:us-west-2:{_ACCOUNT}:secret:{name}-a1",
                ownership=Ownership.CREATED if created else Ownership.OURS,
            )

        def add_content_policy(session, role_name, bucket, account_id, *,
                               inclusion_prefixes=None,
                               policy_name="kb-connector-s3-content-access"):
            self.roles.setdefault(role_name, {"policies": {}})["policies"][
                policy_name] = bucket

        def extend(*, role_name, secret_arn, **_):
            self.extended.append((role_name, secret_arn))
            return {"secret_added": True, "cert_added": False, "policies_updated": ["p"]}

        mp.setattr(provisioning, "ensure_kb_role", ensure_kb_role)
        mp.setattr(provisioning, "put_secret", put_secret)
        mp.setattr(provisioning, "extend_kb_role_for_secret", extend)
        mp.setattr(provisioning, "ensure_cert_bucket",
                   lambda **k: ProvisionedResource(arn=k["bucket"], ownership=Ownership.CREATED))
        mp.setattr(provisioning, "upload_certificate_to_s3", lambda **k: f"s3://{k['bucket']}/{k['key']}")
        mp.setattr(setup_mod, "_add_s3_content_policy", add_content_policy)

        # Entra
        graph = MagicMock()
        mp.setattr(GraphClient, "from_auth", lambda **kw: graph)

        def find_app(g, name):
            return self.apps.get(name)

        def create_app(g, name):
            obj = f"00000000-0000-0000-0000-{len(self.apps):012d}"
            self.apps[name] = {"appId": f"app-{obj}", "id": obj, "certs": []}
            return apps.AppRegistration(f"app-{obj}", obj, f"sp-{obj}")

        def by_object(object_id):
            return next(a for a in self.apps.values() if a["id"] == object_id)

        mp.setattr(apps, "find_application_by_name", find_app)
        mp.setattr(apps, "create_application", create_app)
        mp.setattr(apps, "ensure_service_principal", lambda g, app_id: {"id": f"sp-{app_id}"})
        mp.setattr(apps, "resolve_grants", lambda g, plan: [])
        mp.setattr(apps, "grant_admin_consent", lambda *a: None)
        mp.setattr(apps, "declare_required_resource_access", lambda *a: None)
        mp.setattr(apps, "list_certificate_thumbprints", lambda g, obj: list(by_object(obj)["certs"]))
        mp.setattr(apps, "upload_certificate",
                   lambda g, obj, cert: by_object(obj).__setitem__("certs", [cert.thumbprint_b64url]))
        mp.setattr(apps, "add_client_secret", lambda g, obj, **k: self.secret_factory("client"))

        # Teardown
        mp.setattr("kb_connector.context.default_session_factory", lambda r, p: MagicMock())
        mp.setattr("kb_connector.context.default_target_factory", lambda **kw: target)

        def delete_role(session, role_arn):
            del self.roles[td.role_name_from_arn(role_arn)]

        def delete_secret(session, arn):
            name = arn.split(":secret:", 1)[1].rsplit("-", 1)[0]
            del self.secrets[name]

        def delete_app(*, object_id, **_):
            name = next(n for n, a in self.apps.items() if a["id"] == object_id)
            del self.apps[name]

        mp.setattr(td, "delete_role", delete_role)
        mp.setattr(td, "delete_secret", delete_secret)
        mp.setattr(td, "delete_cert", lambda s, b, k: None)
        mp.setattr(td, "delete_entra_app", delete_app)


@pytest.fixture
def cloud(monkeypatch, tmp_path, fixture_secret_factory):
    monkeypatch.chdir(tmp_path)
    return _FakeCloud(monkeypatch, fixture_secret_factory)


def _write_config(body: str) -> None:
    Path("kb-connector.toml").write_text(
        '[defaults]\nregion = "us-west-2"\n\n[defaults.microsoft]\n'
        f'tenant_id = "{_TENANT}"\n\n' + body
    )


def _cli(*argv: str) -> int:
    from kb_connector.cli.main import build_parser

    args = build_parser().parse_args(list(argv))
    return args.func(args)


def _state(name: str = "c") -> dict:
    return json.loads(Path("kb-connector.state.json").read_text())["connectors"].get(name)


def _full_lifecycle(cloud, capsys, *, ds_count=1):
    assert _cli("setup", "c") == 0
    state = _state()
    assert set(state["created_resources"].values()) <= {"tool"}
    assert len(cloud.kbs) == 1 and len(cloud.data_sources) == ds_count
    params = cloud.params()

    capsys.readouterr()
    assert _cli("setup", "c") == 0
    rerun = capsys.readouterr().out
    assert "Reusing existing data source" in rerun
    assert len(cloud.kbs) == 1 and len(cloud.data_sources) == ds_count
    assert _state()["created_resources"] == state["created_resources"]

    assert _cli("teardown", "c", "--yes") == 0
    assert not (cloud.kbs or cloud.data_sources or cloud.roles or cloud.secrets or cloud.apps)
    assert _state() is None
    return params, rerun


# --- one test per connector type ------------------------------------------------------


def test_s3(cloud, capsys):
    _write_config(
        '[connectors.c]\ntype = "s3"\nbucket_name = "media"\n'
        'inclusion_patterns = ["*.mp4"]\nmax_file_size_mb = 100\n'
    )
    params, rerun = _full_lifecycle(cloud, capsys)
    assert params["connectionConfiguration"] == {"bucketName": "media", "bucketOwnerAccountId": _ACCOUNT}
    assert params["filterConfiguration"] == {
        "inclusionPatterns": ["*.mp4"], "maxFileSizeInMegaBytes": "100",
    }
    assert "Updated IAM role" in rerun


def test_web_basic_auth(cloud, capsys, monkeypatch, fixture_secret):
    monkeypatch.setattr("kb_connector.cli.setup.getpass", lambda prompt="": fixture_secret)
    _write_config(
        '[connectors.c]\ntype = "web"\nseed_urls = ["https://example.com/docs"]\n'
        'auth_mode = "basic_auth"\nusername = "crawler"\nsync_scope = "SUB_DOMAINS"\n'
    )
    params, _ = _full_lifecycle(cloud, capsys)
    assert params["connectionConfiguration"]["authType"] == "BASIC_AUTH"
    assert params["connectionConfiguration"]["secretArn"].endswith("-a1")
    assert params["crawlConfiguration"]["syncScope"] == "SUB_DOMAINS"


def test_confluence_sends_the_filter_keys(cloud, capsys, monkeypatch, fixture_secret):
    monkeypatch.setattr("builtins.input", lambda prompt="": "bot@example.com")
    monkeypatch.setattr("kb_connector.cli.setup.getpass", lambda prompt="": fixture_secret)
    _write_config(
        '[connectors.c]\ntype = "confluence"\nhost_url = "https://x.atlassian.net"\n'
        'credential = "basic"\nacl = true\nspace_keys = ["ENG"]\n'
        'exclusion_space_keys = ["ARCHIVE"]\ninclusion_mime_types = ["text/html"]\n'
        "data_entities = { crawl_blog = false }\n"
    )
    params, _ = _full_lifecycle(cloud, capsys)
    assert params["filterConfiguration"] == {
        "inclusionSpaceKeys": ["ENG"], "exclusionSpaceKeys": ["ARCHIVE"],
        "inclusionMimeTypes": ["text/html"],
    }
    assert params["dataEntityConfiguration"] == {"crawlBlog": False}
    assert params["aclEnabled"] is True


_secret_written: dict = {}


def test_google_drive_sends_the_filter_keys(cloud, capsys, monkeypatch, tmp_path):
    from kb_connector.core import provisioning

    real_put = provisioning.put_secret

    def _capture(**kw):
        _secret_written.clear()
        _secret_written.update(kw["body"])
        return real_put(**kw)

    monkeypatch.setattr(provisioning, "put_secret", _capture)
    key_file = tmp_path / "sa.json"
    key = {"client_email": "sa@x"}
    key["private" + "_key"] = "generated-in-test"
    key_file.write_text(json.dumps(key))
    monkeypatch.setattr("builtins.input", lambda prompt="": str(key_file))
    _write_config(
        '[connectors.c]\ntype = "googledrive"\ncredential = "service_account"\n'
        'admin_account_email = "admin@example.com"\n'
        'shared_drive_ids = ["D1"]\ninclusion_folder_ids = ["F1"]\n'
    )
    params, _ = _full_lifecycle(cloud, capsys)
    assert params["filterConfiguration"] == {
        "inclusionSharedDriveIds": ["D1"], "inclusionFolderIds": ["F1"],
    }
    assert params["connectionConfiguration"]["authType"] == "SERVICE_ACCOUNT"
    assert _secret_written["adminAccountEmail"] == "admin@example.com"


def test_sharepoint(cloud, capsys):
    _write_config(
        '[connectors.c]\ntype = "sharepoint"\ncredential = "cert"\nacl = true\n'
        'site_urls = ["https://x.sharepoint.com/sites/eng"]\ncrawl_pages = false\n'
    )
    params, rerun = _full_lifecycle(cloud, capsys)
    assert params["connectionConfiguration"]["certificateS3Path"] == {
        "s3BucketName": f"kb-connector-certs-{_ACCOUNT}-us-west-2",
        "s3KeyName": "kb-connector/c.p12",
    }
    assert params["dataEntityConfiguration"]["siteUrls"] == ["https://x.sharepoint.com/sites/eng"]
    assert params["dataEntityConfiguration"]["crawlPages"] is False
    assert "Keeping the existing certificate" in rerun
    assert "Extending existing KB role" not in rerun


def test_onedrive(cloud, capsys):
    _write_config(
        '[connectors.c]\ntype = "onedrive"\ncredential = "cert"\nacl = true\n'
        'inclusion_user_emails = ["a@example.com"]\n'
    )
    params, _ = _full_lifecycle(cloud, capsys)
    assert params["dataEntityConfiguration"]["inclusionUserEmailAddresses"] == ["a@example.com"]
    assert params["connectionConfiguration"]["authType"] == "ENTRA_APP_ID"


# --- attaching to an existing knowledge base --------------------------------------------


def _existing_kb(cloud) -> str:
    cloud.kbs["KBSHARED01"] = {
        "name": "shared", "roleArn": f"arn:aws:iam::{_ACCOUNT}:role/shared-kb-role", "tags": {},
    }
    cloud.roles["shared-kb-role"] = {"policies": {}}
    return "KBSHARED01"


def test_s3_on_an_existing_kb_gives_its_role_bucket_read(cloud):
    kb_id = _existing_kb(cloud)
    _write_config('[connectors.c]\ntype = "s3"\nbucket_name = "media"\n')
    assert _cli("setup", "c", "--kb", kb_id) == 0
    assert cloud.roles["shared-kb-role"]["policies"]["kb-connector-s3-content-access-c"] == "media"
    assert "kb-connector-c-role" not in cloud.roles
    state = _state()
    assert state["created_resources"]["kb"] == "external"
    assert state["created_resources"]["role"] == "external"

    assert _cli("teardown", "c", "--yes") == 0
    assert kb_id in cloud.kbs and "shared-kb-role" in cloud.roles
    assert not cloud.data_sources


def test_web_on_an_existing_kb_gives_its_role_the_secret(cloud, monkeypatch, fixture_secret):
    monkeypatch.setattr("kb_connector.cli.setup.getpass", lambda prompt="": fixture_secret)
    kb_id = _existing_kb(cloud)
    _write_config(
        '[connectors.c]\ntype = "web"\nseed_urls = ["https://example.com"]\n'
        'auth_mode = "basic_auth"\nusername = "u"\n'
    )
    assert _cli("setup", "c", "--kb", kb_id) == 0
    ((role, secret_arn),) = cloud.extended
    assert role == "shared-kb-role" and secret_arn.endswith("-a1")


def test_a_given_role_is_used_as_is(cloud):
    _write_config('[connectors.c]\ntype = "s3"\nbucket_name = "media"\n')
    given = f"arn:aws:iam::{_ACCOUNT}:role/team-role"
    assert _cli("setup", "c", "--kb-role-arn", given) == 0
    (kb,) = cloud.kbs.values()
    assert kb["roleArn"] == given and cloud.roles == {}
    assert _state()["created_resources"]["role"] == "external"


# --- checks that stop setup before any call -------------------------------------------


def test_an_oversized_file_limit_stops_setup_before_any_call(cloud, capsys, monkeypatch):
    from kb_connector.cli.main import main

    _write_config('[connectors.c]\ntype = "s3"\nbucket_name = "media"\nmax_file_size_mb = 1500\n')
    monkeypatch.setattr("sys.argv", ["kb-connector", "setup", "c"])
    assert main() == 1
    assert "media extraction" in capsys.readouterr().err
    assert not (cloud.kbs or cloud.roles)


def test_two_s3_connectors_on_one_kb_keep_both_bucket_grants(cloud):
    _write_config(
        '[connectors.a]\ntype = "s3"\nbucket_name = "bucket-a"\n\n'
        '[connectors.b]\ntype = "s3"\nbucket_name = "bucket-b"\n'
    )
    assert _cli("setup", "a") == 0
    kb_id = _state("a")["knowledge_base_id"]
    assert _cli("setup", "b", "--kb", kb_id) == 0
    policies = cloud.roles["kb-connector-a-role"]["policies"]
    assert policies["kb-connector-s3-content-access"] == "bucket-a"
    assert policies["kb-connector-s3-content-access-b"] == "bucket-b"


def test_a_reserved_data_source_name_gets_the_wait_message():
    from unittest.mock import MagicMock

    from kb_connector.cli.setup import _create_data_source_with_diagnostics
    from kb_connector.core.errors import AwsError

    target = MagicMock()
    target.create_data_source_raw.side_effect = AwsError(
        "AWS error (ConflictException): DataSource with name c-ds already exists.",
        code="ConflictException",
    )
    with pytest.raises(AwsError, match="wait a minute"):
        _create_data_source_with_diagnostics(target=target, kb_id="KB", ds_name="c-ds", payload={})
