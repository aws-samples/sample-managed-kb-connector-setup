"""Amazon Quick (quicksight) calls for SharePoint and OneDrive knowledge bases.

A thin wrapper over the boto3 `quicksight` client. Every ClientError becomes an
AwsError carrying the service's error code. A missing resource is recognized
by its error code rather than through `client.exceptions`, and read calls
return None for it while deletes treat it as done.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from kb_connector.core.errors import AwsError, WaitTimeout, aws_error_from

# The role Quick signs with when the account uses the Quick-managed service
# role. Observed live: the console's first "Select keys" creates it. It is not
# documented.
QUICK_MANAGED_SIGNER_ROLE = "service-role/aws-quicksight-kms-role-v0"

# The data source permissions the owner gets.
DATA_SOURCE_ACTIONS = [
    "quicksight:DescribeDataSource",
    "quicksight:DescribeDataSourcePermissions",
    "quicksight:PassDataSource",
    "quicksight:UpdateDataSource",
    "quicksight:DeleteDataSource",
    "quicksight:UpdateDataSourcePermissions",
]

# ListKnowledgeBases page size. The service rejects MaxResults above 25,
# although the model allows 100.
KB_LIST_PAGE = 25

# Data source statuses: usable as is, or failed with ErrorInfo. Every other
# status is in progress.
DATA_SOURCE_READY = ("CREATION_SUCCESSFUL", "UPDATE_SUCCESSFUL")
_DATA_SOURCE_FAILED = ("CREATION_FAILED", "UPDATE_FAILED", "DELETED")

_NOT_FOUND = "ResourceNotFoundException"
_PARAMS_KEYS = ("SharePointParameters", "OneDriveParameters")


class KeyNotAuthorized(AwsError):
    """CreateDataSource failed because Quick cannot sign with the KMS key yet.

    The key is authorized for Quick in the Quick console (Manage account, AWS
    resources, "Select keys"). Until then Quick cannot build the Entra client
    assertion and the service answers with "Failed to generate JWT assertion".
    """


@dataclass(frozen=True)
class SignerRole:
    """The IAM role Quick uses to call KMS, from DescribeResourcePermissions.

    `role_type` is QUICKSIGHT_MANAGED or CUSTOMER_MANAGED. When the call
    fails, both are None and `detail` holds the error code.
    """

    role_type: str | None
    role_arn: str | None
    detail: str | None


def _code(exc: Exception) -> str | None:
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        code = response.get("Error", {}).get("Code")
        return str(code) if code else None
    return None


def _message(exc: Exception) -> str:
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        return str(response.get("Error", {}).get("Message") or "")
    return str(exc)


def _is_not_found(exc: Exception) -> bool:
    return _code(exc) == _NOT_FOUND


def _is_key_not_authorized(exc: Exception) -> bool:
    return (
        _code(exc) == "InvalidParameterValueException"
        and "JWT assertion" in _message(exc)
    )


def quick_user_name(caller_arn: str) -> str | None:
    """The Quick user name Quick gives an IAM caller, or None.

    `...:assumed-role/<role>/<session>` becomes `<role>/<session>` and
    `...:user/<name>` becomes `<name>` (the last path segment). The account
    root and anything else has no Quick user name.
    """
    parts = caller_arn.split(":", 5)
    if len(parts) < 6:
        return None
    resource = parts[5]
    if resource.startswith("assumed-role/"):
        pieces = resource.split("/")
        if len(pieces) >= 3 and pieces[1] and pieces[2]:
            return f"{pieces[1]}/{pieces[2]}"
        return None
    if resource.startswith("user/"):
        name = resource.rsplit("/", 1)[-1]
        return name or None
    return None


def caller_account(session: Any) -> str:
    """The account id of the session's identity, from STS."""
    try:
        return str(session.client("sts").get_caller_identity()["Account"])
    except (ClientError, BotoCoreError) as exc:
        raise aws_error_from(exc) from exc


class QuickClient:
    """Data source and knowledge base calls in one account and Region."""

    def __init__(self, *, session: Any, region: str | None, account_id: str) -> None:
        self._qs = session.client("quicksight", region_name=region)
        self.account_id = account_id

    # --- data sources -------------------------------------------------------

    def describe_data_source(self, ds_id: str) -> dict | None:
        try:
            resp = self._qs.describe_data_source(
                AwsAccountId=self.account_id, DataSourceId=ds_id
            )
        except (ClientError, BotoCoreError) as exc:
            if _is_not_found(exc):
                return None
            raise aws_error_from(exc) from exc
        data_source: dict = resp.get("DataSource") or {}
        return data_source

    def data_sources_for_app(self, client_id: str) -> list[dict]:
        """Every SharePoint or OneDrive data source whose ClientId is `client_id`."""
        found: list[dict] = []
        kwargs: dict[str, Any] = {"AwsAccountId": self.account_id}
        while True:
            try:
                resp = self._qs.list_data_sources(**kwargs)
            except (ClientError, BotoCoreError) as exc:
                raise aws_error_from(exc) from exc
            for ds in resp.get("DataSources") or []:
                params = ds.get("DataSourceParameters") or {}
                for key in _PARAMS_KEYS:
                    if (params.get(key) or {}).get("ClientId") == client_id:
                        found.append(ds)
                        break
            token = resp.get("NextToken")
            if not token:
                return found
            kwargs["NextToken"] = token

    def create_data_source(
        self,
        *,
        ds_id: str,
        name: str,
        ds_type: str,
        parameters: dict,
        key_arn: str,
        thumbprint: str,
        owner_arn: str,
        tags: list[dict[str, str]] | None,
    ) -> str:
        """CreateDataSource; returns the data source ARN.

        Raises KeyNotAuthorized when Quick cannot sign with `key_arn` yet.
        """
        arm = "SharePointClientCredentials" if ds_type == "SHAREPOINT" else (
            "OneDriveClientCredentials"
        )
        auth = {arm: {"KmsKeyArn": key_arn, "CertThumbprint": thumbprint}}
        kwargs: dict[str, Any] = {
            "AwsAccountId": self.account_id,
            "DataSourceId": ds_id,
            "Name": name,
            "Type": ds_type,
            "DataSourceParameters": parameters,
            "Credentials": auth,
            "Permissions": [{"Principal": owner_arn, "Actions": list(DATA_SOURCE_ACTIONS)}],
        }
        if tags is not None:
            kwargs["Tags"] = tags
        try:
            resp = self._qs.create_data_source(**kwargs)
        except (ClientError, BotoCoreError) as exc:
            if _is_key_not_authorized(exc):
                raise KeyNotAuthorized(
                    f"Amazon Quick cannot sign with KMS key {key_arn} yet: "
                    f"{_message(exc)}",
                    code=_code(exc),
                ) from exc
            raise aws_error_from(exc) from exc
        return str(resp["Arn"])

    def wait_for_data_source(
        self, ds_id: str, *, timeout: float = 120, poll: float = 3
    ) -> dict:
        deadline = time.monotonic() + timeout
        while True:
            ds = self.describe_data_source(ds_id)
            status = (ds or {}).get("Status")
            if ds is not None and status in DATA_SOURCE_READY:
                return ds
            if ds is not None and status in _DATA_SOURCE_FAILED:
                info = ds.get("ErrorInfo") or {}
                detail = info.get("Message") or "no error message"
                what = (
                    "failed to create" if status == "CREATION_FAILED"
                    else f"is in status {status}"
                )
                raise AwsError(
                    f"Quick data source {ds_id} {what} "
                    f"({info.get('Type', 'UNKNOWN')}): {detail}"
                )
            if time.monotonic() >= deadline:
                raise WaitTimeout(
                    f"Quick data source {ds_id} did not finish creating within "
                    f"{int(timeout)} s (last status {status!r})."
                )
            time.sleep(poll)

    def delete_data_source(self, ds_id: str) -> None:
        try:
            self._qs.delete_data_source(AwsAccountId=self.account_id, DataSourceId=ds_id)
        except (ClientError, BotoCoreError) as exc:
            if _is_not_found(exc):
                return
            raise aws_error_from(exc) from exc

    # --- knowledge bases ----------------------------------------------------

    def describe_knowledge_base(self, kb_id: str) -> dict | None:
        try:
            resp = self._qs.describe_knowledge_base(
                AwsAccountId=self.account_id, KnowledgeBaseId=kb_id
            )
        except (ClientError, BotoCoreError) as exc:
            if _is_not_found(exc):
                return None
            raise aws_error_from(exc) from exc
        kb: dict = resp.get("KnowledgeBase") or {}
        return kb

    def knowledge_bases_for_data_source(self, ds_arn: str) -> list[dict]:
        """Every knowledge base summary whose DataSourceArn is `ds_arn`."""
        found: list[dict] = []
        kwargs: dict[str, Any] = {"AwsAccountId": self.account_id, "MaxResults": KB_LIST_PAGE}
        while True:
            try:
                resp = self._qs.list_knowledge_bases(**kwargs)
            except (ClientError, BotoCoreError) as exc:
                raise aws_error_from(exc) from exc
            found.extend(
                kb for kb in resp.get("KnowledgeBaseSummaries") or []
                if kb.get("DataSourceArn") == ds_arn
            )
            token = resp.get("NextToken")
            if not token:
                return found
            kwargs["NextToken"] = token

    def create_knowledge_base(
        self,
        *,
        kb_id: str,
        name: str,
        description: str,
        ds_arn: str,
        template: dict,
        acl: bool,
        owner_arn: str,
        tags: list[dict[str, str]] | None,
    ) -> str:
        """CreateKnowledgeBase; returns the knowledge base ARN."""
        kwargs: dict[str, Any] = {
            "AwsAccountId": self.account_id,
            "KnowledgeBaseId": kb_id,
            "Name": name,
            "Description": description,
            "DataSourceArn": ds_arn,
            "KnowledgeBaseConfiguration": {"templateConfiguration": {"template": template}},
            "AccessControlConfiguration": {"isACLEnabled": acl},
            "PrimaryOwnerArn": owner_arn,
        }
        if tags is not None:
            kwargs["Tags"] = tags
        try:
            resp = self._qs.create_knowledge_base(**kwargs)
        except (ClientError, BotoCoreError) as exc:
            raise aws_error_from(exc) from exc
        return str(resp["KnowledgeBaseArn"])

    def wait_until_kb_active(
        self, kb_id: str, *, timeout: float = 600, poll: float = 10
    ) -> dict:
        deadline = time.monotonic() + timeout
        while True:
            kb = self.describe_knowledge_base(kb_id)
            status = (kb or {}).get("Status")
            if kb is not None and status == "ACTIVE":
                return kb
            if kb is not None and status == "FAILED":
                raise AwsError(f"Quick knowledge base {kb_id} failed to create.")
            if kb is not None and status == "DELETING":
                raise AwsError(f"Quick knowledge base {kb_id} is being deleted.")
            if time.monotonic() >= deadline:
                raise WaitTimeout(
                    f"Quick knowledge base {kb_id} did not become ACTIVE within "
                    f"{int(timeout)} s (last status {status!r})."
                )
            time.sleep(poll)

    def delete_knowledge_base(
        self, kb_id: str, *, wait: bool = True, timeout: float = 600, poll: float = 10
    ) -> None:
        """DeleteKnowledgeBase, then poll Describe until it is gone when `wait`."""
        try:
            self._qs.delete_knowledge_base(AwsAccountId=self.account_id, KnowledgeBaseId=kb_id)
        except (ClientError, BotoCoreError) as exc:
            if _is_not_found(exc):
                return
            raise aws_error_from(exc) from exc
        if not wait:
            return
        deadline = time.monotonic() + timeout
        while self.describe_knowledge_base(kb_id) is not None:
            if time.monotonic() >= deadline:
                raise WaitTimeout(
                    f"Quick knowledge base {kb_id} was still present {int(timeout)} s "
                    f"after DeleteKnowledgeBase."
                )
            time.sleep(poll)

    # --- account ------------------------------------------------------------

    def tags(self, arn: str) -> tuple[list, bool]:
        """A resource's tags, plus whether they could be read."""
        try:
            resp = self._qs.list_tags_for_resource(ResourceArn=arn)
        except (ClientError, BotoCoreError):
            return [], False
        return list(resp.get("Tags") or []), True

    def signer_role(self, *, partition: str, account_id: str) -> SignerRole:
        """The role Quick signs with, from DescribeResourcePermissions."""
        try:
            resp = self._qs.describe_resource_permissions(AwsAccountId=account_id)
        except (ClientError, BotoCoreError) as exc:
            return SignerRole(None, None, _code(exc) or type(exc).__name__)
        role_type = resp.get("RoleType")
        if role_type == "QUICKSIGHT_MANAGED":
            arn = f"arn:{partition}:iam::{account_id}:role/{QUICK_MANAGED_SIGNER_ROLE}"
            return SignerRole(role_type, arn, None)
        if role_type == "CUSTOMER_MANAGED":
            return SignerRole(role_type, resp.get("CustomerManagedRoleArn"), None)
        return SignerRole(role_type, None, None)

    def user_arn(self, user_name: str, namespace: str = "default") -> str | None:
        """The ARN of a Quick user, or None when there is no such user."""
        try:
            resp = self._qs.describe_user(
                AwsAccountId=self.account_id, Namespace=namespace, UserName=user_name
            )
        except (ClientError, BotoCoreError) as exc:
            if _is_not_found(exc):
                return None
            raise aws_error_from(exc) from exc
        arn = (resp.get("User") or {}).get("Arn")
        return str(arn) if arn else None
