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
from botocore.exceptions import ClientError

from kb_connector.core.tagging import Ownership, ProvisionedResource

_ACCOUNT = "111122223333"
_TENANT = "11111111-2222-3333-4444-555555555555"
_QUICK_REGION = "us-east-1"
_CALLER_ARN = f"arn:aws:sts::{_ACCOUNT}:assumed-role/Admin/tester"
_QUICK_USER_ARN = f"arn:aws:quicksight:{_QUICK_REGION}:{_ACCOUNT}:user/default/Admin/tester"


def _client_error(code: str, message: str, operation: str, status: int = 400) -> ClientError:
    return ClientError(
        {"Error": {"Code": code, "Message": message},
         "ResponseMetadata": {"HTTPStatusCode": status}},
        operation,
    )


# --- Quick, KMS, IAM, CloudTrail and STS fakes ----------------------------------------
#
# Reached through _FakeSession.client(), which setup gets from
# _aws_session_and_account and every other command from default_session_factory.


class _FakeQuickSight:
    """In-memory Amazon Quick data sources, knowledge bases, users and tags."""

    def __init__(self, deletions: list):
        self.data_sources: dict = {}     # id -> DataSource dict
        self.kbs: dict = {}              # id -> KnowledgeBase dict
        self.tags: dict = {}             # ARN -> [{"Key", "Value"}]
        self.users: dict = {"Admin/tester": _QUICK_USER_ARN}
        self.role_type = "QUICKSIGHT_MANAGED"
        self.customer_role_arn: str | None = None
        self.authorized_keys: set = set()
        self.kb_ingestion = "QUEUED"
        self.deny_tagging = False        # creates with Tags fail as TagResource denied
        self.calls: list = []            # (operation, kwargs) for every create
        self.deletions = deletions       # shared with _FakeCloud, in order

    def _arn(self, kind: str, rid: str) -> str:
        return f"arn:aws:quicksight:{_QUICK_REGION}:{_ACCOUNT}:{kind}/{rid}"

    def _check_tagging(self, kw: dict, operation: str) -> None:
        if self.deny_tagging and kw.get("Tags"):
            raise _client_error(
                "AccessDeniedException",
                "User is not authorized to perform: quicksight:TagResource",
                operation, 403,
            )

    def creates(self, operation: str) -> list:
        """The kwargs of every call to `operation` (create_data_source, ...)."""
        return [kw for op, kw in self.calls if op == operation]

    def create_data_source(self, **kw):
        self.calls.append(("create_data_source", kw))
        ds_id = kw["DataSourceId"]
        auth = next(iter(kw.get("Credentials", {}).values()), {})
        if auth.get("KmsKeyArn") not in self.authorized_keys:
            raise _client_error(
                "InvalidParameterValueException",
                "Failed to validate credentials: Failed to generate JWT assertion",
                "CreateDataSource",
            )
        if ds_id in self.data_sources:
            raise _client_error("ResourceExistsException", f"{ds_id} exists",
                                "CreateDataSource", 409)
        self._check_tagging(kw, "CreateDataSource")
        arn = self._arn("datasource", ds_id)
        self.data_sources[ds_id] = {
            "Arn": arn, "DataSourceId": ds_id, "Name": kw["Name"], "Type": kw["Type"],
            "Status": "CREATION_SUCCESSFUL",
            "DataSourceParameters": kw.get("DataSourceParameters", {}),
        }
        if kw.get("Tags"):
            self.tags[arn] = list(kw["Tags"])
        return {"Arn": arn, "DataSourceId": ds_id, "CreationStatus": "CREATION_IN_PROGRESS"}

    def describe_data_source(self, *, AwsAccountId, DataSourceId):
        if DataSourceId not in self.data_sources:
            raise _client_error("ResourceNotFoundException", "no data source",
                                "DescribeDataSource", 404)
        return {"DataSource": dict(self.data_sources[DataSourceId])}

    def list_data_sources(self, *, AwsAccountId, NextToken=None):
        return {"DataSources": [dict(ds) for ds in self.data_sources.values()]}

    def delete_data_source(self, *, AwsAccountId, DataSourceId):
        if DataSourceId not in self.data_sources:
            raise _client_error("ResourceNotFoundException", "no data source",
                                "DeleteDataSource", 404)
        self.deletions.append(("ds", DataSourceId))
        del self.data_sources[DataSourceId]
        return {"DataSourceId": DataSourceId}

    def create_knowledge_base(self, **kw):
        self.calls.append(("create_knowledge_base", kw))
        kb_id = kw["KnowledgeBaseId"]
        if kb_id in self.kbs:
            raise _client_error("ResourceExistsException", f"{kb_id} exists",
                                "CreateKnowledgeBase", 409)
        self._check_tagging(kw, "CreateKnowledgeBase")
        arn = self._arn("knowledgebase", kb_id)
        self.kbs[kb_id] = {
            "KnowledgeBaseArn": arn, "KnowledgeBaseId": kb_id, "Name": kw["Name"],
            "Status": "ACTIVE", "DataSourceArn": kw["DataSourceArn"],
            "KnowledgeBaseConfiguration": kw["KnowledgeBaseConfiguration"],
            "AccessControlConfiguration": kw.get("AccessControlConfiguration", {}),
            "PrimaryOwnerArn": kw.get("PrimaryOwnerArn"),
            "DocumentCount": 0,
            "LatestIngestionSummary": {"IngestionId": "ing-1",
                                       "IngestionStatus": self.kb_ingestion},
        }
        if kw.get("Tags"):
            self.tags[arn] = list(kw["Tags"])
        return {"KnowledgeBaseArn": arn, "KnowledgeBaseId": kb_id, "CreationStatus": "CREATING"}

    def describe_knowledge_base(self, *, AwsAccountId, KnowledgeBaseId):
        if KnowledgeBaseId not in self.kbs:
            raise _client_error("ResourceNotFoundException", "no knowledge base",
                                "DescribeKnowledgeBase", 404)
        return {"KnowledgeBase": dict(self.kbs[KnowledgeBaseId])}

    def list_knowledge_bases(self, *, AwsAccountId, MaxResults=None, NextToken=None):
        if MaxResults is not None and MaxResults > 25:
            raise _client_error("InvalidParameterValueException",
                                "MaxResults must be at most 25", "ListKnowledgeBases")
        keys = ("KnowledgeBaseArn", "KnowledgeBaseId", "Name", "Status", "DataSourceArn")
        return {"KnowledgeBaseSummaries": [
            {k: kb[k] for k in keys} for kb in self.kbs.values()
        ]}

    def delete_knowledge_base(self, *, AwsAccountId, KnowledgeBaseId):
        if KnowledgeBaseId not in self.kbs:
            raise _client_error("ResourceNotFoundException", "no knowledge base",
                                "DeleteKnowledgeBase", 404)
        self.deletions.append(("kb", KnowledgeBaseId))
        kb = self.kbs.pop(KnowledgeBaseId)
        return {"KnowledgeBaseArn": kb["KnowledgeBaseArn"], "KnowledgeBaseId": KnowledgeBaseId}

    def describe_resource_permissions(self, *, AwsAccountId):
        resp: dict = {"RoleType": self.role_type}
        if self.customer_role_arn:
            resp["CustomerManagedRoleArn"] = self.customer_role_arn
        return resp

    def describe_user(self, *, AwsAccountId, Namespace, UserName):
        if UserName not in self.users:
            raise _client_error("ResourceNotFoundException", "no user", "DescribeUser", 404)
        return {"User": {"Arn": self.users[UserName], "UserName": UserName}}

    def list_tags_for_resource(self, *, ResourceArn):
        return {"Tags": list(self.tags.get(ResourceArn, []))}


_KMS_PRIVATE_KEY = None


def _kms_private_key():
    """One RSA-2048 key for the whole module; generating one per test is slow."""
    global _KMS_PRIVATE_KEY
    if _KMS_PRIVATE_KEY is None:
        from cryptography.hazmat.primitives.asymmetric import rsa

        _KMS_PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return _KMS_PRIVATE_KEY


class _FakeKms:
    """Asymmetric signing keys with a real RSA key behind GetPublicKey and Sign."""

    class exceptions:  # noqa: N801 - mirrors the boto3 client attribute
        class NotFoundException(Exception):
            pass

    def __init__(self):
        self.keys: dict = {}             # ARN -> KeyMetadata
        self.aliases: dict = {}          # alias -> ARN
        self.key_tags: dict = {}         # ARN -> [{"TagKey", "TagValue"}]
        self.extra_statements: list = []  # key-policy statements beyond the root one
        self.grants: list = []

    def _resolve(self, key_id: str) -> str:
        arn = self.aliases.get(key_id, key_id)
        if arn not in self.keys:
            raise self.exceptions.NotFoundException(key_id)
        return arn

    def create_key(self, **kw):
        key_id = f"xxxxxxxx-0000-0000-0000-{len(self.keys):012d}"
        arn = f"arn:aws:kms:{_QUICK_REGION}:{_ACCOUNT}:key/{key_id}"
        self.keys[arn] = {
            "Arn": arn, "KeyId": key_id, "KeySpec": kw["KeySpec"],
            "KeyUsage": kw["KeyUsage"], "Enabled": True, "KeyState": "Enabled",
            "MultiRegion": False,
        }
        self.key_tags[arn] = list(kw.get("Tags", []))
        return {"KeyMetadata": dict(self.keys[arn])}

    def create_alias(self, *, AliasName, TargetKeyId):
        arn = next(a for a, m in self.keys.items() if m["KeyId"] == TargetKeyId)
        self.aliases[AliasName] = arn

    def describe_key(self, *, KeyId):
        return {"KeyMetadata": dict(self.keys[self._resolve(KeyId)])}

    def list_resource_tags(self, *, KeyId):
        return {"Tags": list(self.key_tags.get(self._resolve(KeyId), []))}

    def get_public_key(self, *, KeyId):
        from cryptography.hazmat.primitives import serialization

        meta = self.keys[self._resolve(KeyId)]
        der = _kms_private_key().public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return {"PublicKey": der, "KeySpec": meta["KeySpec"], "KeyUsage": meta["KeyUsage"]}

    def sign(self, *, KeyId, Message, MessageType, SigningAlgorithm):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding, utils

        self._resolve(KeyId)
        assert MessageType == "DIGEST"
        signature = _kms_private_key().sign(
            Message, padding.PKCS1v15(), utils.Prehashed(hashes.SHA256())
        )
        return {"Signature": signature, "SigningAlgorithm": SigningAlgorithm}

    def get_key_policy(self, *, KeyId, PolicyName="default"):
        self._resolve(KeyId)
        root = {
            "Sid": "Enable IAM User Permissions", "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{_ACCOUNT}:root"},
            "Action": "kms:*", "Resource": "*",
        }
        return {"Policy": json.dumps({
            "Version": "2012-10-17", "Statement": [root, *self.extra_statements],
        })}

    def list_grants(self, *, KeyId, **_):
        self._resolve(KeyId)
        return {"Grants": list(self.grants)}


class _FakeIam:
    def __init__(self):
        self.roles_present: set = {"aws-quicksight-kms-role-v0"}
        self.identity_allowed_keys: set = set()
        self.simulations: list = []      # kwargs of every simulate_principal_policy

    def get_role(self, *, RoleName):
        if RoleName not in self.roles_present:
            raise _client_error("NoSuchEntity", f"role {RoleName} not found", "GetRole", 404)
        return {"Role": {"RoleName": RoleName,
                         "Arn": f"arn:aws:iam::{_ACCOUNT}:role/service-role/{RoleName}"}}

    def simulate_principal_policy(self, **kw):
        self.simulations.append(kw)
        return {"EvaluationResults": [
            {"EvalActionName": action, "EvalResourceName": resource,
             "EvalDecision": "allowed" if resource in self.identity_allowed_keys
             else "implicitDeny"}
            for action in kw.get("ActionNames", [])
            for resource in kw.get("ResourceArns", ["*"])
        ]}


class _FakeCloudTrail:
    def __init__(self):
        self.events: list = []
        self.lookups: list = []

    def lookup_events(self, **kw):
        self.lookups.append(kw)
        return {"Events": list(self.events)}


class _FakeSts:
    def __init__(self):
        self.arn = _CALLER_ARN

    def get_caller_identity(self):
        return {"Arn": self.arn, "Account": _ACCOUNT, "UserId": "AROAEXAMPLE:tester"}


class _FakeSession:
    def __init__(self, cloud: _FakeCloud):
        self.region_name = _QUICK_REGION
        self._clients = {
            "quicksight": cloud.quicksight, "kms": cloud.kms, "iam": cloud.iam,
            "cloudtrail": cloud.cloudtrail, "sts": cloud.sts,
        }

    def client(self, name, **_kw):
        return self._clients.get(name) or MagicMock()


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
        self.deletions: list = []      # (kind, id) in the order Quick and Entra deletes ran
        self.quicksight = _FakeQuickSight(self.deletions)
        self.kms = _FakeKms()
        self.iam = _FakeIam()
        self.cloudtrail = _FakeCloudTrail()
        self.sts = _FakeSts()
        self.session = _FakeSession(self)
        self._install(monkeypatch)

    def authorize(self, key_arn: str) -> None:
        """The Quick console "Select keys" step: Quick may sign with the key after it."""
        self.quicksight.authorized_keys.add(key_arn)

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
        mp.setattr(setup_mod, "_aws_session_and_account", lambda cfg: (self.session, _ACCOUNT))
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
        def resolve_grants(g, plan):
            return [
                apps.ResolvedGrant(req, f"sp-{req.resource_app_id}", f"role-{req.value}")
                for req in plan.requirements
            ]

        def grant_admin_consent(g, client_sp_id, grants):
            # create_app names the service principal sp-<object id>;
            # ensure_service_principal names it sp-<app id>.
            app = next(a for a in self.apps.values()
                       if client_sp_id in (f"sp-{a['id']}", f"sp-{a['appId']}"))
            consent = app.setdefault("consent", [])
            for grant in grants:
                key = (grant.resource_sp_id, grant.app_role_id)
                if key not in consent:
                    consent.append(key)

        mp.setattr(apps, "resolve_grants", resolve_grants)
        mp.setattr(apps, "grant_admin_consent", grant_admin_consent)
        mp.setattr(apps, "declare_required_resource_access", lambda *a: None)
        mp.setattr(apps, "list_certificate_thumbprints", lambda g, obj: list(by_object(obj)["certs"]))
        mp.setattr(apps, "upload_certificate",
                   lambda g, obj, cert: by_object(obj).__setitem__("certs", [cert.thumbprint_b64url]))
        mp.setattr(apps, "add_client_secret", lambda g, obj, **k: self.secret_factory("client"))

        # Teardown
        mp.setattr("kb_connector.context.default_session_factory", lambda r, p: self.session)
        mp.setattr("kb_connector.context.default_target_factory", lambda **kw: target)

        def delete_role(session, role_arn):
            del self.roles[td.role_name_from_arn(role_arn)]

        def delete_secret(session, arn):
            name = arn.split(":secret:", 1)[1].rsplit("-", 1)[0]
            del self.secrets[name]

        def delete_app(*, object_id, **_):
            name = next(n for n, a in self.apps.items() if a["id"] == object_id)
            self.deletions.append(("app", object_id))
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


def _quick_config(connector_type: str = "sharepoint", extra: str = "") -> None:
    body = (
        f'[connectors.c]\ntype = "{connector_type}"\ntarget = "quick"\n'
        f'credential = "cert"\nregion = "{_QUICK_REGION}"\nacl = true\n'
    )
    if connector_type == "sharepoint":
        body += 'site_urls = ["https://x.sharepoint.com/sites/eng"]\n'
    _write_config(body + extra)


# --- Quick teardown and monitor ------------------------------------------------------


def _seed_quick(cloud, *, ds: str | None = "tool", kb: str | None = "tool",
                signing_key: str = "tool") -> dict:
    """A Quick connector as setup leaves it, written straight to the fakes and state."""
    key = cloud.kms.create_key(KeySpec="RSA_2048", KeyUsage="SIGN_VERIFY")["KeyMetadata"]
    cloud.authorize(key["Arn"])
    obj = "00000000-0000-0000-0000-00000000000a"
    cloud.apps["kb-connector-c"] = {"appId": f"app-{obj}", "id": obj, "certs": ["tp"]}
    entry = {
        "connector_type": "sharepoint", "target": "quick", "region": _QUICK_REGION,
        "tenant_id": _TENANT, "client_app_id": f"app-{obj}", "client_app_object_id": obj,
        "cert_thumbprint_b64url": "tp", "signing_key_arn": key["Arn"],
        "created_resources": {"app": "tool", "signing_key": signing_key},
    }
    qs = cloud.quicksight
    if ds:
        ds_arn = qs.create_data_source(
            AwsAccountId=_ACCOUNT, DataSourceId="kb-connector-c-ds", Name="c-ds",
            Type="SHAREPOINT", Credentials={"SharePointClientCredentials": {
                "KmsKeyArn": key["Arn"], "CertThumbprint": "tp"}},
            DataSourceParameters={"SharePointParameters": {
                "SharePointDomain": "x.sharepoint.com", "ClientId": f"app-{obj}"}},
        )["Arn"]
        entry["data_source_id"] = "kb-connector-c-ds"
        entry["created_resources"]["ds"] = ds
        if kb:
            qs.create_knowledge_base(
                AwsAccountId=_ACCOUNT, KnowledgeBaseId="kb-connector-c-kb",
                Name="kb-connector-c", DataSourceArn=ds_arn,
                KnowledgeBaseConfiguration={"templateConfiguration": {"template": {}}},
            )
            entry["knowledge_base_id"] = "kb-connector-c-kb"
            entry["created_resources"]["kb"] = kb
    qs.calls.clear()
    Path("kb-connector.state.json").write_text(json.dumps({"connectors": {"c": entry}}))
    return entry


def test_quick_teardown_deletes_kb_then_ds_then_app_and_keeps_the_key(cloud, capsys):
    _quick_config()
    entry = _seed_quick(cloud)
    capsys.readouterr()
    assert _cli("teardown", "c", "--yes") == 0
    out = capsys.readouterr().out
    assert cloud.deletions == [
        ("kb", "kb-connector-c-kb"), ("ds", "kb-connector-c-ds"),
        ("app", entry["client_app_object_id"]),
    ]
    assert "Quick knowledge base kb-connector-c-kb" in out
    assert "Quick data source kb-connector-c-ds" in out
    assert f"KMS signing key {entry['signing_key_arn']} (never deleted by teardown)" in out
    assert f"schedule-key-deletion --key-id {entry['signing_key_arn']}" in out
    assert entry["signing_key_arn"] in cloud.kms.keys
    assert not (cloud.quicksight.kbs or cloud.quicksight.data_sources or cloud.apps)
    assert _state() is None


def test_quick_teardown_dry_run_prints_the_key_line_and_deletes_nothing(cloud, capsys):
    _quick_config()
    entry = _seed_quick(cloud)
    capsys.readouterr()
    assert _cli("teardown", "c", "--dry-run") == 0
    out = capsys.readouterr().out
    assert f"schedule-key-deletion --key-id {entry['signing_key_arn']}" in out
    assert cloud.deletions == []


def test_quick_teardown_leaves_an_external_signing_key_alone(cloud, capsys):
    _quick_config()
    entry = _seed_quick(cloud, signing_key="external")
    capsys.readouterr()
    assert _cli("teardown", "c", "--yes") == 0
    out = capsys.readouterr().out
    assert "schedule-key-deletion" not in out
    assert f"KMS signing key {entry['signing_key_arn']} is recorded as external" in out


def test_quick_teardown_keeps_an_external_kb_and_data_source(cloud, capsys):
    _quick_config()
    _seed_quick(cloud, ds="external", kb="external")
    capsys.readouterr()
    assert _cli("teardown", "c", "--yes") == 0
    out = capsys.readouterr().out
    assert "Kept (adopted by this tool, not created by it):" in out
    assert "• Quick knowledge base kb-connector-c-kb" in out
    assert "• Quick data source kb-connector-c-ds" in out
    assert "the kept Quick data source authenticates with" in out
    assert [kind for kind, _ in cloud.deletions] == ["app"]
    assert "kb-connector-c-kb" in cloud.quicksight.kbs
    assert "kb-connector-c-ds" in cloud.quicksight.data_sources
    assert _state()["knowledge_base_id"] == "kb-connector-c-kb"


def test_quick_teardown_keeps_a_tool_data_source_under_an_external_kb(cloud, capsys):
    _quick_config()
    _seed_quick(cloud, ds="tool", kb="external")
    capsys.readouterr()
    assert _cli("teardown", "c", "--yes") == 0
    out = capsys.readouterr().out
    assert "Kept (created by this tool, used by an external resource):" in out
    assert (
        "• Quick data source kb-connector-c-ds (used by external Quick knowledge "
        "base kb-connector-c-kb)" in out
    )
    assert "delete Quick knowledge base kb-connector-c-kb in the Amazon Quick console" in out
    assert "re-run `kb-connector teardown c`" in out
    assert "the kept Quick data source authenticates with" in out
    assert [kind for kind, _ in cloud.deletions] == ["app"]
    assert "kb-connector-c-kb" in cloud.quicksight.kbs
    assert "kb-connector-c-ds" in cloud.quicksight.data_sources
    state = _state()
    assert state["data_source_id"] == "kb-connector-c-ds"
    assert state["created_resources"]["ds"] == "tool"


def test_quick_teardown_deletes_the_data_source_once_the_external_kb_is_gone(
    cloud, capsys
):
    _quick_config()
    entry = _seed_quick(cloud, ds="tool", kb="external")
    del cloud.quicksight.kbs["kb-connector-c-kb"]   # deleted in the Quick console
    capsys.readouterr()

    assert _cli("teardown", "c", "--dry-run") == 0
    out = capsys.readouterr().out
    assert "Quick knowledge base kb-connector-c-kb (external) is not found in Quick" in out
    assert "• Quick data source kb-connector-c-ds" in out
    assert cloud.deletions == []
    assert _state()["knowledge_base_id"] == "kb-connector-c-kb"

    assert _cli("teardown", "c", "--yes") == 0
    out = capsys.readouterr().out
    assert "Removed Quick knowledge base kb-connector-c-kb from state" in out
    assert cloud.deletions == [
        ("ds", "kb-connector-c-ds"), ("app", entry["client_app_object_id"]),
    ]
    assert _state() is None


def test_quick_teardown_keeps_the_data_source_and_app_when_the_kb_check_fails(
    cloud, capsys, monkeypatch
):
    _quick_config()
    entry = _seed_quick(cloud, ds="tool", kb="external")

    def refuse(**_):
        raise _client_error("AccessDeniedException", "not allowed", "DescribeKnowledgeBase", 403)

    monkeypatch.setattr(cloud.quicksight, "describe_knowledge_base", refuse)
    capsys.readouterr()
    assert _cli("teardown", "c", "--yes") == 0
    out = capsys.readouterr().out
    assert (
        "Quick knowledge base kb-connector-c-kb could not be checked "
        "(AccessDeniedException), so the data source and the Entra app are kept." in out
    )
    assert f"• Entra app {entry['client_app_id']}" in out
    assert cloud.deletions == []
    state = _state()
    assert state["knowledge_base_id"] == "kb-connector-c-kb"
    assert state["data_source_id"] == "kb-connector-c-ds"
    assert state["client_app_id"] == entry["client_app_id"]


def test_quick_teardown_of_credential_only_state_deletes_the_app(cloud, capsys):
    """State written by 1.4 Quick setup: an Entra app and a signing key, no DS or KB."""
    _quick_config()
    entry = _seed_quick(cloud, ds=None, kb=None)
    capsys.readouterr()
    assert _cli("teardown", "c", "--yes") == 0
    out = capsys.readouterr().out
    assert [kind for kind, _ in cloud.deletions] == ["app"]
    assert f"schedule-key-deletion --key-id {entry['signing_key_arn']}" in out
    assert _state() is None


def test_quick_teardown_keeps_the_data_source_when_the_kb_delete_fails(
    cloud, capsys, monkeypatch
):
    _quick_config()
    entry = _seed_quick(cloud)

    def refuse(**_):
        raise _client_error("AccessDeniedException", "not allowed", "DeleteKnowledgeBase", 403)

    monkeypatch.setattr(cloud.quicksight, "delete_knowledge_base", refuse)
    capsys.readouterr()
    assert _cli("teardown", "c", "--yes") == 1
    out = capsys.readouterr().out
    assert "Failed to delete Quick knowledge base kb-connector-c-kb" in out
    assert "Skipping Quick data source kb-connector-c-ds" in out
    assert cloud.deletions == []
    assert "kb-connector-c-ds" in cloud.quicksight.data_sources
    assert entry["client_app_object_id"] == cloud.apps["kb-connector-c"]["id"]
    state = _state()
    assert state["knowledge_base_id"] == "kb-connector-c-kb"
    assert state["data_source_id"] == "kb-connector-c-ds"
    assert state["client_app_id"] == entry["client_app_id"]


def test_monitor_refuses_a_quick_connector(cloud, capsys, monkeypatch):
    from kb_connector.cli.main import main

    _quick_config()
    _seed_quick(cloud)
    monkeypatch.setattr("sys.argv", ["kb-connector", "monitor", "c"])
    assert main() != 0
    err = capsys.readouterr().err
    assert "no knowledge-base sync API" in err
    assert "kb-connector validate c" in err


# --- Quick setup ------------------------------------------------------------------------


def _resolved(name: str = "c"):
    from kb_connector.core.config import load_config

    return load_config(None).resolve_connector(name)


def _assert_no_key_access_written(cloud) -> None:
    """Setup never writes a key policy statement, a grant or an IAM policy."""
    assert cloud.kms.extra_statements == [] and cloud.kms.grants == []
    assert cloud.iam.simulations == []


def _setup_unauthorized(cloud, capsys) -> str:
    """First Quick run: the key is not yet authorized. Returns its output."""
    capsys.readouterr()
    assert _cli("setup", "c") == 0
    return capsys.readouterr().out


def test_quick_sharepoint_setup_lifecycle(cloud, capsys):
    from kb_connector.quick import templates

    _quick_config()

    # Run 1: Quick cannot sign with the new key yet.
    out = _setup_unauthorized(cloud, capsys)
    state = _state()
    key_arn = state["signing_key_arn"]
    thumbprint = state["cert_thumbprint_b64url"]
    assert "not yet authorized" in out
    assert "Setup is not finished" in out and "Setup complete." not in out
    assert "Select keys" in out and key_arn in out
    assert "Failed to generate JWT assertion" in out
    assert "aws-quicksight-kms-role-v0" not in out
    assert not (cloud.quicksight.data_sources or cloud.quicksight.kbs)
    assert state["knowledge_base_id"] is None and state["data_source_id"] is None
    assert "ds" not in state["created_resources"] and "kb" not in state["created_resources"]
    _assert_no_key_access_written(cloud)

    # The console step, then run 2 creates the data source and the knowledge base.
    cloud.authorize(key_arn)
    capsys.readouterr()
    assert _cli("setup", "c") == 0
    out = capsys.readouterr().out
    assert "Setup complete." in out and "Next: kb-connector validate c" in out
    assert "KB is ACTIVE" in out and "Latest sync: QUEUED" in out
    assert list(cloud.quicksight.data_sources) == ["kb-connector-c-ds"]
    assert list(cloud.quicksight.kbs) == ["kb-connector-c-kb"]
    # The first call is run 1's, refused while the key was unauthorized.
    ds_call = cloud.quicksight.creates("create_data_source")[-1]
    assert ds_call["Type"] == "SHAREPOINT"
    sp = ds_call["DataSourceParameters"]["SharePointParameters"]
    assert sp["SharePointDomain"] == "x.sharepoint.com"
    assert sp["TenantId"] == _TENANT and sp["ClientId"] == state["client_app_id"]
    assert ds_call["Credentials"]["SharePointClientCredentials"] == {
        "KmsKeyArn": key_arn, "CertThumbprint": thumbprint,
    }
    assert ds_call["Permissions"][0]["Principal"] == _QUICK_USER_ARN
    (kb_call,) = cloud.quicksight.creates("create_knowledge_base")
    assert kb_call["KnowledgeBaseConfiguration"] == {
        "templateConfiguration": {"template": templates.knowledge_base_template(_resolved())},
    }
    assert kb_call["AccessControlConfiguration"] == {"isACLEnabled": True}
    assert kb_call["PrimaryOwnerArn"] == _QUICK_USER_ARN
    assert kb_call["DataSourceArn"] == cloud.quicksight.data_sources["kb-connector-c-ds"]["Arn"]
    for call in (ds_call, kb_call):
        tags = {t["Key"]: t["Value"] for t in call["Tags"]}
        assert tags["ManagedBy"] == "kb-connector" and tags["KbConnectorName"] == "c"
    state = _state()
    assert state["data_source_id"] == "kb-connector-c-ds"
    assert state["knowledge_base_id"] == "kb-connector-c-kb"
    assert state["created_resources"]["ds"] == "tool"
    assert state["created_resources"]["kb"] == "tool"
    assert len(cloud.kms.keys) == 1
    assert state["signing_key_arn"] == key_arn
    assert state["cert_thumbprint_b64url"] == thumbprint
    _assert_no_key_access_written(cloud)

    # Run 3 finds both in state and creates nothing.
    calls = len(cloud.quicksight.calls)
    capsys.readouterr()
    assert _cli("setup", "c") == 0
    out = capsys.readouterr().out
    assert len(cloud.quicksight.calls) == calls
    assert "Using Quick data source kb-connector-c-ds (recorded in state)" in out
    assert "Select keys" not in out
    assert _state()["created_resources"] == state["created_resources"]

    # Teardown removes the knowledge base, the data source and the app; the key stays.
    capsys.readouterr()
    assert _cli("teardown", "c", "--yes") == 0
    out = capsys.readouterr().out
    assert [kind for kind, _ in cloud.deletions] == ["kb", "ds", "app"]
    assert f"schedule-key-deletion --key-id {key_arn}" in out
    assert key_arn in cloud.kms.keys
    assert _state() is None


def test_quick_onedrive_setup_creates_a_onedrive_data_source(cloud, capsys):
    _quick_config("onedrive", 'inclusion_user_emails = ["a@example.com"]\n')
    capsys.readouterr()
    assert _cli("setup", "c") == 0
    err = capsys.readouterr().err
    assert "WARNING: inclusion_user_emails has no effect" in err

    cloud.authorize(_state()["signing_key_arn"])
    assert _cli("setup", "c") == 0
    ds = cloud.quicksight.data_sources["kb-connector-c-ds"]
    assert ds["Type"] == "ONE_DRIVE"
    ds_call = cloud.quicksight.creates("create_data_source")[-1]
    assert set(ds_call["Credentials"]) == {"OneDriveClientCredentials"}
    assert ds_call["DataSourceParameters"]["OneDriveParameters"]["AuthType"] == "TWO_LEGGED_OAUTH"
    (kb_call,) = cloud.quicksight.creates("create_knowledge_base")
    template = kb_call["KnowledgeBaseConfiguration"]["templateConfiguration"]["template"]
    assert template["type"] == "ONEDRIVEV3"
    assert kb_call["AccessControlConfiguration"] == {"isACLEnabled": True}


def test_quick_setup_on_a_terminal_retries_after_the_console_step(cloud, capsys, monkeypatch):
    _quick_config()
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("sys.stdout.isatty", lambda: True)
    prompts: list = []

    def operator(prompt=""):
        prompts.append(prompt)
        cloud.authorize(next(iter(cloud.kms.keys)))
        return ""

    monkeypatch.setattr("builtins.input", operator)
    assert _cli("setup", "c") == 0
    out = capsys.readouterr().out
    assert len(prompts) == 1 and "Press Enter" in prompts[0]
    assert "Setup complete." in out
    assert "kb-connector-c-ds" in cloud.quicksight.data_sources
    assert "kb-connector-c-kb" in cloud.quicksight.kbs


def test_quick_setup_on_a_terminal_stops_on_q(cloud, capsys, monkeypatch):
    _quick_config()
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("sys.stdout.isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt="": "q")
    assert _cli("setup", "c") == 0
    assert "Setup is not finished" in capsys.readouterr().out
    assert not cloud.quicksight.data_sources


def test_quick_setup_records_a_console_made_data_source_and_kb_as_external(cloud, capsys):
    """State as 1.4 left it (app, key, certificate) plus a DS and KB made in the console."""
    _quick_config()
    _setup_unauthorized(cloud, capsys)
    state = _state()
    key_arn = state["signing_key_arn"]
    cloud.authorize(key_arn)
    qs = cloud.quicksight
    ds_arn = qs.create_data_source(
        AwsAccountId=_ACCOUNT, DataSourceId="xxxxxxxx-console-ds", Name="console",
        Type="SHAREPOINT", Credentials={"SharePointClientCredentials": {
            "KmsKeyArn": key_arn, "CertThumbprint": state["cert_thumbprint_b64url"]}},
        DataSourceParameters={"SharePointParameters": {
            "SharePointDomain": "x.sharepoint.com", "ClientId": state["client_app_id"]}},
    )["Arn"]
    qs.create_knowledge_base(
        AwsAccountId=_ACCOUNT, KnowledgeBaseId="xxxxxxxx-console-kb", Name="console",
        DataSourceArn=ds_arn,
        KnowledgeBaseConfiguration={"templateConfiguration": {"template": {}}},
        AccessControlConfiguration={"isACLEnabled": True},
    )
    qs.calls.clear()

    capsys.readouterr()
    assert _cli("setup", "c") == 0
    out = capsys.readouterr().out
    assert qs.calls == []
    assert "made outside this tool" in out
    state = _state()
    assert state["data_source_id"] == "xxxxxxxx-console-ds"
    assert state["knowledge_base_id"] == "xxxxxxxx-console-kb"
    assert state["created_resources"]["ds"] == "external"
    assert state["created_resources"]["kb"] == "external"

    assert _cli("teardown", "c", "--yes") == 0
    assert [kind for kind, _ in cloud.deletions] == ["app"]
    assert "xxxxxxxx-console-ds" in qs.data_sources and "xxxxxxxx-console-kb" in qs.kbs


def test_quick_setup_prints_the_statement_for_a_customer_managed_role(cloud, capsys):
    role = f"arn:aws:iam::{_ACCOUNT}:role/team-quick-service-role"
    cloud.quicksight.role_type = "CUSTOMER_MANAGED"
    cloud.quicksight.customer_role_arn = role
    _quick_config()
    out = _setup_unauthorized(cloud, capsys)
    assert "customer-managed Quick service role" in out
    statement = out[out.index('"Sid": "QuickSignEntraAssertionStatement"'):]
    assert f'"AWS": "{role}"' in statement
    assert _state()["signing_key_arn"] in statement
    assert "aws-quicksight-kms-role-v0" not in out
    _assert_no_key_access_written(cloud)


def test_quick_owner_arn_is_used_as_given(cloud, capsys):
    owner = f"arn:aws:quicksight:{_QUICK_REGION}:{_ACCOUNT}:group/default/kb-owners"
    cloud.quicksight.users = {}  # DescribeUser would fail if setup asked it
    _quick_config(extra=f'quick_owner_arn = "{owner}"\n')
    _setup_unauthorized(cloud, capsys)
    cloud.authorize(_state()["signing_key_arn"])
    assert _cli("setup", "c") == 0
    ds_call = cloud.quicksight.creates("create_data_source")[-1]
    assert ds_call["Permissions"][0]["Principal"] == owner
    (kb_call,) = cloud.quicksight.creates("create_knowledge_base")
    assert kb_call["PrimaryOwnerArn"] == owner


def test_quick_setup_without_a_quick_user_stops_before_creating(cloud, capsys):
    from kb_connector.core.errors import ConfigError

    cloud.quicksight.users = {}
    _quick_config()
    with pytest.raises(ConfigError, match="quick_owner_arn"):
        _cli("setup", "c")
    assert cloud.quicksight.creates("create_data_source") == []
    assert not cloud.quicksight.data_sources


def test_quick_setup_falls_back_to_untagged_when_tagging_is_denied(cloud, capsys):
    _quick_config()
    _setup_unauthorized(cloud, capsys)
    cloud.authorize(_state()["signing_key_arn"])
    cloud.quicksight.deny_tagging = True
    assert _cli("setup", "c") == 0
    err = capsys.readouterr().err
    assert "without tags (quicksight:TagResource denied)" in err
    state = _state()
    assert state["created_resources"]["ds"] == "tool-untagged"
    assert state["created_resources"]["kb"] == "tool-untagged"
    assert cloud.quicksight.tags == {}


def _quick_authorized(cloud, capsys) -> dict:
    """Credentials made and the key authorized; no data source or KB yet. Returns state."""
    _quick_config()
    _setup_unauthorized(cloud, capsys)
    state = _state()
    cloud.authorize(state["signing_key_arn"])
    return state


def _console_data_source(cloud, state: dict, ds_id: str, *, client_id: str | None = None,
                         **fields) -> str:
    """A data source made outside this tool, for this app unless `client_id` says another."""
    arn = cloud.quicksight.create_data_source(
        AwsAccountId=_ACCOUNT, DataSourceId=ds_id, Name=ds_id, Type="SHAREPOINT",
        Credentials={"SharePointClientCredentials": {
            "KmsKeyArn": state["signing_key_arn"],
            "CertThumbprint": state["cert_thumbprint_b64url"]}},
        DataSourceParameters={"SharePointParameters": {
            "SharePointDomain": "x.sharepoint.com",
            "ClientId": client_id or state["client_app_id"]}},
    )["Arn"]
    cloud.quicksight.data_sources[ds_id].update(fields)
    return arn


def _console_knowledge_base(cloud, kb_id: str, ds_arn: str, **fields) -> None:
    cloud.quicksight.create_knowledge_base(
        AwsAccountId=_ACCOUNT, KnowledgeBaseId=kb_id, Name=kb_id, DataSourceArn=ds_arn,
        KnowledgeBaseConfiguration={"templateConfiguration": {"template": {}}},
        AccessControlConfiguration={"isACLEnabled": True},
    )
    cloud.quicksight.kbs[kb_id].update(fields)


def test_quick_setup_kb_flag_records_the_named_kb_and_its_data_source(cloud, capsys):
    state = _quick_authorized(cloud, capsys)
    ds_arn = _console_data_source(cloud, state, "xxxxxxxx-console-ds")
    _console_knowledge_base(cloud, "xxxxxxxx-console-kb", ds_arn)
    cloud.quicksight.calls.clear()
    capsys.readouterr()
    assert _cli("setup", "c", "--kb", "xxxxxxxx-console-kb") == 0
    out = capsys.readouterr().out
    assert cloud.quicksight.calls == []
    assert "Setup complete." in out and "KB is ACTIVE" in out
    state = _state()
    assert state["knowledge_base_id"] == "xxxxxxxx-console-kb"
    assert state["data_source_id"] == "xxxxxxxx-console-ds"
    assert state["created_resources"]["kb"] == "external"
    assert state["created_resources"]["ds"] == "external"


def test_quick_setup_kb_flag_refuses_a_kb_on_another_apps_data_source(cloud, capsys):
    from kb_connector.core.errors import AwsError

    state = _quick_authorized(cloud, capsys)
    ds_arn = _console_data_source(cloud, state, "xxxxxxxx-other-ds", client_id="app-other")
    _console_knowledge_base(cloud, "xxxxxxxx-other-kb", ds_arn)
    cloud.quicksight.calls.clear()
    with pytest.raises(AwsError, match="does not use this connector's Entra app"):
        _cli("setup", "c", "--kb", "xxxxxxxx-other-kb")
    assert cloud.quicksight.calls == []
    assert _state()["knowledge_base_id"] is None


def test_quick_setup_kb_flag_keeps_a_tool_made_data_source_as_the_tools(cloud, capsys):
    state = _quick_authorized(cloud, capsys)
    assert _cli("setup", "c") == 0
    ds_arn = cloud.quicksight.data_sources["kb-connector-c-ds"]["Arn"]
    _console_knowledge_base(cloud, "xxxxxxxx-console-kb", ds_arn)
    capsys.readouterr()
    assert _cli("setup", "c", "--kb", "xxxxxxxx-console-kb") == 0
    err = capsys.readouterr().err
    assert (
        "WARNING: state records Quick knowledge base kb-connector-c-kb as created "
        "by this tool." in err
    )
    assert "kb-connector-c-kb is no longer tracked" in err
    state = _state()
    assert state["knowledge_base_id"] == "xxxxxxxx-console-kb"
    assert state["created_resources"]["kb"] == "external"
    assert state["data_source_id"] == "kb-connector-c-ds"
    assert state["created_resources"]["ds"] == "tool"


def test_quick_setup_with_several_data_sources_for_the_app_is_not_finished(cloud, capsys):
    state = _quick_authorized(cloud, capsys)
    for ds_id in ("xxxxxxxx-console-ds1", "xxxxxxxx-console-ds2"):
        _console_data_source(cloud, state, ds_id)
    cloud.quicksight.calls.clear()
    capsys.readouterr()
    assert _cli("setup", "c") == 0
    out = capsys.readouterr().out
    assert "xxxxxxxx-console-ds1" in out and "xxxxxxxx-console-ds2" in out
    assert "Setup is not finished: several Quick data sources" in out
    assert "--kb" in out and "Setup complete." not in out
    assert cloud.quicksight.calls == []
    state = _state()
    assert state["data_source_id"] is None and state["knowledge_base_id"] is None


def test_quick_setup_with_several_kbs_on_the_data_source_is_not_finished(cloud, capsys):
    state = _quick_authorized(cloud, capsys)
    ds_arn = _console_data_source(cloud, state, "xxxxxxxx-console-ds")
    for kb_id in ("xxxxxxxx-console-kb1", "xxxxxxxx-console-kb2"):
        _console_knowledge_base(cloud, kb_id, ds_arn)
    cloud.quicksight.calls.clear()
    capsys.readouterr()
    assert _cli("setup", "c") == 0
    out = capsys.readouterr().out
    assert "xxxxxxxx-console-kb1" in out and "xxxxxxxx-console-kb2" in out
    assert "Setup is not finished: several Quick knowledge bases" in out
    assert "Setup complete." not in out
    assert cloud.quicksight.calls == []
    assert _state()["knowledge_base_id"] is None


def test_quick_setup_refuses_an_untagged_data_source_under_the_derived_id(cloud, capsys):
    from kb_connector.core.errors import AwsError

    state = _quick_authorized(cloud, capsys)
    _console_data_source(cloud, state, "kb-connector-c-ds")
    cloud.quicksight.calls.clear()
    with pytest.raises(AwsError, match="Quick data source 'kb-connector-c-ds' already exists"):
        _cli("setup", "c")
    assert cloud.quicksight.calls == []
    assert _state()["data_source_id"] is None

    assert _cli("setup", "c", "--adopt-existing-resources") == 0
    state = _state()
    assert state["data_source_id"] == "kb-connector-c-ds"
    assert state["created_resources"]["ds"] == "external"
    assert state["created_resources"]["kb"] == "tool"


def test_quick_setup_refuses_an_untagged_kb_under_the_derived_id(cloud, capsys):
    from kb_connector.core.errors import AwsError

    state = _quick_authorized(cloud, capsys)
    ds_arn = _console_data_source(cloud, state, "xxxxxxxx-console-ds")
    _console_knowledge_base(cloud, "kb-connector-c-kb", ds_arn)
    with pytest.raises(AwsError, match="Quick knowledge base 'kb-connector-c-kb' already exists"):
        _cli("setup", "c")
    assert _state()["knowledge_base_id"] is None


def test_quick_setup_refuses_a_state_data_source_for_another_app(cloud, capsys):
    from kb_connector.core.errors import AwsError

    _quick_authorized(cloud, capsys)
    assert _cli("setup", "c") == 0
    params = cloud.quicksight.data_sources["kb-connector-c-ds"]["DataSourceParameters"]
    params["SharePointParameters"]["ClientId"] = "app-other"
    with pytest.raises(AwsError, match="recorded in state uses Entra app app-other"):
        _cli("setup", "c")


def test_quick_setup_stops_on_a_failed_data_source(cloud, capsys):
    from kb_connector.core.errors import AwsError

    state = _quick_authorized(cloud, capsys)
    _console_data_source(cloud, state, "xxxxxxxx-console-ds", Status="CREATION_FAILED",
                         ErrorInfo={"Type": "ACCESS_DENIED", "Message": "Tenant refused."})
    cloud.quicksight.calls.clear()
    capsys.readouterr()
    with pytest.raises(AwsError, match=r"failed to create \(ACCESS_DENIED\): Tenant refused"):
        _cli("setup", "c")
    out = capsys.readouterr().out
    assert "Setup complete." not in out and "Setup did not complete." in out
    assert cloud.quicksight.creates("create_knowledge_base") == []


def test_quick_setup_stops_on_a_failed_knowledge_base(cloud, capsys):
    from kb_connector.core.errors import AwsError

    state = _quick_authorized(cloud, capsys)
    ds_arn = _console_data_source(cloud, state, "xxxxxxxx-console-ds")
    _console_knowledge_base(cloud, "xxxxxxxx-console-kb", ds_arn, Status="FAILED")
    capsys.readouterr()
    with pytest.raises(AwsError, match="xxxxxxxx-console-kb failed to create"):
        _cli("setup", "c")
    out = capsys.readouterr().out
    assert "Setup complete." not in out and "KB is ACTIVE" not in out


def test_quick_setup_uses_an_updated_data_source(cloud, capsys):
    state = _quick_authorized(cloud, capsys)
    _console_data_source(cloud, state, "xxxxxxxx-console-ds", Status="UPDATE_SUCCESSFUL")
    assert _cli("setup", "c") == 0
    (kb_call,) = cloud.quicksight.creates("create_knowledge_base")
    assert kb_call["DataSourceArn"].endswith("/xxxxxxxx-console-ds")


def test_quick_rotate_cert_warns_that_the_data_source_keeps_the_old_one(cloud, capsys):
    _quick_authorized(cloud, capsys)
    assert _cli("setup", "c") == 0
    old = _state()["cert_thumbprint_b64url"]
    capsys.readouterr()
    assert _cli("setup", "c", "--rotate-cert") == 0
    err = capsys.readouterr().err
    new = _state()["cert_thumbprint_b64url"]
    assert new != old
    assert "WARNING: Quick data source kb-connector-c-ds keeps the certificate" in err
    assert "kb-connector teardown c --only kb" in err
    assert "kb-connector teardown c --only ds" in err

    # The recovery the warning gives: a new data source carries the new thumbprint.
    assert _cli("teardown", "c", "--only", "kb", "--yes") == 0
    assert _cli("teardown", "c", "--only", "ds", "--yes") == 0
    capsys.readouterr()
    assert _cli("setup", "c") == 0
    assert "WARNING" not in capsys.readouterr().err
    ds_call = cloud.quicksight.creates("create_data_source")[-1]
    assert ds_call["Credentials"]["SharePointClientCredentials"]["CertThumbprint"] == new
    assert set(cloud.quicksight.kbs) == {"kb-connector-c-kb"}


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
