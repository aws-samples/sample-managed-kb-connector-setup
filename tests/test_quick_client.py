"""QuickClient against a real quicksight client with botocore's Stubber.

The Stubber runs botocore's parameter validation on every request and checks
every canned response against the output shape, so these tests fail if a
request does not match the quicksight model the boto3 floor guarantees.
"""
from __future__ import annotations

import boto3
import pytest
from botocore.stub import ANY, Stubber

from kb_connector.core.errors import AwsError
from kb_connector.quick import client as quick_client
from kb_connector.quick import templates
from kb_connector.quick.client import KeyNotAuthorized, QuickClient, SignerRole
from kb_connector.core.config import ConnectorConfig

_ACCOUNT = "123456789012"
_TENANT = "11111111-1111-1111-1111-111111111111"
_CLIENT = "22222222-2222-2222-2222-222222222222"
_KEY = f"arn:aws:kms:us-east-1:{_ACCOUNT}:key/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
_OWNER = f"arn:aws:quicksight:us-east-1:{_ACCOUNT}:user/default/Admin/tester"
_DS_ARN = f"arn:aws:quicksight:us-east-1:{_ACCOUNT}:datasource/c-ds"
_KB_ARN = f"arn:aws:quicksight:us-east-1:{_ACCOUNT}:knowledgebase/c-kb"
_THUMBPRINT = "dGh1bWJwcmludA"  # base64url of "thumbprint"
_SITE = "https://contoso.sharepoint.com/sites/eng"


class _Session:
    """Hands out one real quicksight client so the test can stub it."""

    def __init__(self) -> None:
        self.qs = boto3.Session(
            region_name="us-east-1",
            aws_access_key_id="testing",
            aws_secret_access_key="testing",  # nosec B106 - dummy, never sent
        ).client("quicksight")

    def client(self, name: str, **_kw):
        assert name == "quicksight"
        return self.qs


@pytest.fixture
def stubbed():
    session = _Session()
    quick = QuickClient(session=session, region="us-east-1", account_id=_ACCOUNT)
    with Stubber(session.qs) as stub:
        yield quick, stub
        stub.assert_no_pending_responses()


def _cfg(kind: str) -> ConnectorConfig:
    raw = {"type": kind, "site_urls": [_SITE]} if kind == "sharepoint" else {"type": kind}
    return ConnectorConfig(name="c", type=kind, raw=raw, target="quick", acl=True)


@pytest.mark.parametrize("kind, ds_type, arm", [
    ("sharepoint", "SHAREPOINT", "SharePointClientCredentials"),
    ("onedrive", "ONE_DRIVE", "OneDriveClientCredentials"),
])
def test_create_data_source_request_matches_the_model(stubbed, kind, ds_type, arm):
    quick, stub = stubbed
    got_type, params = templates.data_source_request(
        _cfg(kind), tenant_id=_TENANT, client_id=_CLIENT
    )
    assert got_type == ds_type
    tags = [{"Key": "ManagedBy", "Value": "kb-connector"}]
    stub.add_response(
        "create_data_source",
        {"Arn": _DS_ARN, "DataSourceId": "c-ds", "CreationStatus": "CREATION_IN_PROGRESS"},
        {
            "AwsAccountId": _ACCOUNT, "DataSourceId": "c-ds", "Name": "c-ds",
            "Type": ds_type, "DataSourceParameters": params,
            "Credentials": {arm: {"KmsKeyArn": _KEY, "CertThumbprint": _THUMBPRINT}},
            "Permissions": [{"Principal": _OWNER, "Actions": quick_client.DATA_SOURCE_ACTIONS}],
            "Tags": tags,
        },
    )
    arn = quick.create_data_source(
        ds_id="c-ds", name="c-ds", ds_type=got_type, parameters=params,
        key_arn=_KEY, thumbprint=_THUMBPRINT, owner_arn=_OWNER, tags=tags,
    )
    assert arn == _DS_ARN


def test_create_data_source_omits_tags_when_none(stubbed):
    quick, stub = stubbed
    _, params = templates.data_source_request(_cfg("onedrive"), tenant_id=_TENANT,
                                              client_id=_CLIENT)
    stub.add_response(
        "create_data_source", {"Arn": _DS_ARN},
        {"AwsAccountId": _ACCOUNT, "DataSourceId": "c-ds", "Name": "c-ds",
         "Type": "ONE_DRIVE", "DataSourceParameters": params,
         "Credentials": ANY, "Permissions": ANY},
    )
    quick.create_data_source(
        ds_id="c-ds", name="c-ds", ds_type="ONE_DRIVE", parameters=params,
        key_arn=_KEY, thumbprint=_THUMBPRINT, owner_arn=_OWNER, tags=None,
    )


@pytest.mark.parametrize("message", [
    "Failed to validate credentials: Failed to generate JWT assertion",
    "Failed to validate OneDrive credentials: Failed to generate JWT assertion",
])
def test_jwt_assertion_failure_is_key_not_authorized(stubbed, message):
    quick, stub = stubbed
    stub.add_client_error("create_data_source", "InvalidParameterValueException",
                          message, http_status_code=400)
    with pytest.raises(KeyNotAuthorized) as exc:
        quick.create_data_source(
            ds_id="c-ds", name="c-ds", ds_type="SHAREPOINT",
            parameters={"SharePointParameters": {"SharePointDomain": "contoso.sharepoint.com"}},
            key_arn=_KEY, thumbprint=_THUMBPRINT, owner_arn=_OWNER, tags=None,
        )
    assert exc.value.code == "InvalidParameterValueException"
    assert _KEY in str(exc.value)


def test_another_400_is_a_plain_aws_error(stubbed):
    quick, stub = stubbed
    stub.add_client_error("create_data_source", "InvalidParameterValueException",
                          "Data source validation failed.", http_status_code=400)
    with pytest.raises(AwsError) as exc:
        quick.create_data_source(
            ds_id="c-ds", name="c-ds", ds_type="SHAREPOINT",
            parameters={"SharePointParameters": {"SharePointDomain": "contoso.sharepoint.com"}},
            key_arn=_KEY, thumbprint=_THUMBPRINT, owner_arn=_OWNER, tags=None,
        )
    assert not isinstance(exc.value, KeyNotAuthorized)
    assert exc.value.code == "InvalidParameterValueException"


def _kb_summary(kb_id: str, ds_arn: str) -> dict:
    return {"KnowledgeBaseArn": f"{_KB_ARN}-{kb_id}", "KnowledgeBaseId": kb_id,
            "Name": kb_id, "Status": "ACTIVE", "DataSourceArn": ds_arn}


def test_knowledge_bases_for_data_source_pages_25_at_a_time(stubbed):
    quick, stub = stubbed
    other = f"{_DS_ARN}-other"
    stub.add_response(
        "list_knowledge_bases",
        {"KnowledgeBaseSummaries": [_kb_summary("a", _DS_ARN), _kb_summary("b", other)],
         "NextToken": "page2"},
        {"AwsAccountId": _ACCOUNT, "MaxResults": 25},
    )
    stub.add_response(
        "list_knowledge_bases",
        {"KnowledgeBaseSummaries": [_kb_summary("c", _DS_ARN)]},
        {"AwsAccountId": _ACCOUNT, "MaxResults": 25, "NextToken": "page2"},
    )
    found = quick.knowledge_bases_for_data_source(_DS_ARN)
    assert [kb["KnowledgeBaseId"] for kb in found] == ["a", "c"]


def test_data_sources_for_app_filters_by_client_id(stubbed):
    quick, stub = stubbed
    stub.add_response(
        "list_data_sources",
        {"DataSources": [
            {"DataSourceId": "sp", "Type": "SHAREPOINT", "DataSourceParameters": {
                "SharePointParameters": {"SharePointDomain": "contoso.sharepoint.com",
                                         "ClientId": _CLIENT}}},
            {"DataSourceId": "other", "Type": "ONE_DRIVE", "DataSourceParameters": {
                "OneDriveParameters": {"ClientId": "33333333-3333-3333-3333-333333333333"}}},
        ], "NextToken": "t"},
        {"AwsAccountId": _ACCOUNT},
    )
    stub.add_response(
        "list_data_sources",
        {"DataSources": [
            {"DataSourceId": "od", "Type": "ONE_DRIVE", "DataSourceParameters": {
                "OneDriveParameters": {"ClientId": _CLIENT}}},
            {"DataSourceId": "s3", "Type": "S3"},
        ]},
        {"AwsAccountId": _ACCOUNT, "NextToken": "t"},
    )
    found = quick.data_sources_for_app(_CLIENT)
    assert [ds["DataSourceId"] for ds in found] == ["sp", "od"]


def test_create_knowledge_base_request_matches_the_model(stubbed):
    quick, stub = stubbed
    template = templates.knowledge_base_template(_cfg("sharepoint"))
    stub.add_response(
        "create_knowledge_base",
        {"KnowledgeBaseArn": _KB_ARN, "KnowledgeBaseId": "c-kb", "CreationStatus": "CREATING"},
        {"AwsAccountId": _ACCOUNT, "KnowledgeBaseId": "c-kb", "Name": "kb-connector-c",
         "Description": "Managed by kb-connector for connector c.",
         "DataSourceArn": _DS_ARN,
         "KnowledgeBaseConfiguration": {"templateConfiguration": {"template": template}},
         "AccessControlConfiguration": {"isACLEnabled": True},
         "PrimaryOwnerArn": _OWNER},
    )
    arn = quick.create_knowledge_base(
        kb_id="c-kb", name="kb-connector-c",
        description="Managed by kb-connector for connector c.", ds_arn=_DS_ARN,
        template=template, acl=True, owner_arn=_OWNER, tags=None,
    )
    assert arn == _KB_ARN


def test_missing_resources_read_as_none_and_deletes_as_done(stubbed):
    quick, stub = stubbed
    for op in ("describe_data_source", "describe_knowledge_base",
               "delete_knowledge_base", "delete_data_source"):
        stub.add_client_error(op, "ResourceNotFoundException", "not found",
                              http_status_code=404)
    assert quick.describe_data_source("c-ds") is None
    assert quick.describe_knowledge_base("c-kb") is None
    quick.delete_knowledge_base("c-kb")
    quick.delete_data_source("c-ds")


def test_delete_knowledge_base_waits_until_it_is_gone(stubbed):
    quick, stub = stubbed
    stub.add_response("delete_knowledge_base",
                      {"KnowledgeBaseArn": _KB_ARN, "KnowledgeBaseId": "c-kb"},
                      {"AwsAccountId": _ACCOUNT, "KnowledgeBaseId": "c-kb"})
    stub.add_response("describe_knowledge_base", {"KnowledgeBase": {
        "KnowledgeBaseArn": _KB_ARN, "KnowledgeBaseId": "c-kb", "Name": "c",
        "Status": "DELETING", "DataSourceArn": _DS_ARN,
        "KnowledgeBaseConfiguration": {}}})
    stub.add_client_error("describe_knowledge_base", "ResourceNotFoundException",
                          "gone", http_status_code=404)
    quick.delete_knowledge_base("c-kb", wait=True, poll=0)


def _ds(status: str, **extra) -> dict:
    return {"DataSource": {"Arn": _DS_ARN, "DataSourceId": "c-ds", "Status": status, **extra}}


def _kb(status: str) -> dict:
    return {"KnowledgeBase": {
        "KnowledgeBaseArn": _KB_ARN, "KnowledgeBaseId": "c-kb", "Name": "c",
        "Status": status, "DataSourceArn": _DS_ARN, "KnowledgeBaseConfiguration": {}}}


@pytest.mark.parametrize("status", ["CREATION_SUCCESSFUL", "UPDATE_SUCCESSFUL"])
def test_wait_for_data_source_returns_on_a_usable_status(stubbed, status):
    quick, stub = stubbed
    stub.add_response("describe_data_source", _ds("CREATION_IN_PROGRESS"))
    stub.add_response("describe_data_source", _ds(status))
    assert quick.wait_for_data_source("c-ds", poll=0)["Status"] == status


@pytest.mark.parametrize("status, words", [
    ("CREATION_FAILED", "failed to create"),
    ("UPDATE_FAILED", "is in status UPDATE_FAILED"),
])
def test_wait_for_data_source_raises_with_the_error_info(stubbed, status, words):
    quick, stub = stubbed
    stub.add_response("describe_data_source", _ds(
        status, ErrorInfo={"Type": "ACCESS_DENIED", "Message": "Tenant refused the app."}))
    with pytest.raises(AwsError, match=f"{words} \\(ACCESS_DENIED\\): Tenant refused"):
        quick.wait_for_data_source("c-ds", poll=0)


@pytest.mark.parametrize("status, words", [
    ("FAILED", "failed to create"), ("DELETING", "is being deleted"),
])
def test_wait_until_kb_active_raises_on_a_status_that_cannot_become_active(
    stubbed, status, words
):
    quick, stub = stubbed
    stub.add_response("describe_knowledge_base", _kb(status))
    with pytest.raises(AwsError, match=words):
        quick.wait_until_kb_active("c-kb", poll=0)


def test_signer_role_quick_managed(stubbed):
    quick, stub = stubbed
    stub.add_response("describe_resource_permissions",
                      {"RoleType": "QUICKSIGHT_MANAGED"}, {"AwsAccountId": _ACCOUNT})
    assert quick.signer_role(partition="aws", account_id=_ACCOUNT) == SignerRole(
        "QUICKSIGHT_MANAGED",
        f"arn:aws:iam::{_ACCOUNT}:role/service-role/aws-quicksight-kms-role-v0",
        None,
    )


def test_signer_role_customer_managed(stubbed):
    quick, stub = stubbed
    role = f"arn:aws:iam::{_ACCOUNT}:role/quick-service"
    stub.add_response("describe_resource_permissions",
                      {"RoleType": "CUSTOMER_MANAGED", "CustomerManagedRoleArn": role},
                      {"AwsAccountId": _ACCOUNT})
    assert quick.signer_role(partition="aws", account_id=_ACCOUNT) == SignerRole(
        "CUSTOMER_MANAGED", role, None
    )


def test_signer_role_on_access_denied(stubbed):
    quick, stub = stubbed
    stub.add_client_error("describe_resource_permissions", "AccessDeniedException",
                          "denied", http_status_code=403)
    assert quick.signer_role(partition="aws", account_id=_ACCOUNT) == SignerRole(
        None, None, "AccessDeniedException"
    )


def test_user_arn(stubbed):
    quick, stub = stubbed
    stub.add_response("describe_user", {"User": {"Arn": _OWNER, "UserName": "Admin/tester"}},
                      {"AwsAccountId": _ACCOUNT, "Namespace": "default",
                       "UserName": "Admin/tester"})
    stub.add_client_error("describe_user", "ResourceNotFoundException", "no user",
                          http_status_code=404)
    assert quick.user_arn("Admin/tester") == _OWNER
    assert quick.user_arn("nobody") is None


def test_tags_report_readability(stubbed):
    quick, stub = stubbed
    tags = [{"Key": "ManagedBy", "Value": "kb-connector"}]
    stub.add_response("list_tags_for_resource", {"Tags": tags}, {"ResourceArn": _DS_ARN})
    stub.add_client_error("list_tags_for_resource", "AccessDeniedException", "denied",
                          http_status_code=403)
    assert quick.tags(_DS_ARN) == (tags, True)
    assert quick.tags(_DS_ARN) == ([], False)


@pytest.mark.parametrize("caller, expected", [
    (f"arn:aws:sts::{_ACCOUNT}:assumed-role/Admin/tester", "Admin/tester"),
    (f"arn:aws:iam::{_ACCOUNT}:user/alice", "alice"),
    (f"arn:aws:iam::{_ACCOUNT}:user/team/alice", "alice"),
    (f"arn:aws:iam::{_ACCOUNT}:root", None),
])
def test_quick_user_name(caller, expected):
    assert quick_client.quick_user_name(caller) == expected
