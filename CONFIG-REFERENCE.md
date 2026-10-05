# Configuration reference

Generated from the connector specs by `scripts/gen_config_reference.py`. Do not edit by hand.

Keys go under `[connectors.<name>]`. A key the tool does not read, or a value of the wrong type, prints a warning naming the closest valid key. For request fields not listed here, see [Request overrides](README.md#request-overrides).

## Every connector

| Key | Type | Default | Description |
|---|---|---|---|
| `type` | str |  | **Required.** Connector type. One of: `sharepoint`, `onedrive`, `s3`, `web`, `confluence`, `googledrive`. |
| `target` | str | `"bmkb"` | Control plane that holds the knowledge base: bmkb or quick. |
| `region` | str |  | AWS Region for every resource the connector creates. |
| `profile` | str |  | AWS profile to use. |
| `resource_prefix` | str |  | Prefix for derived resource names, so connectors in one account cannot collide. |
| `kms_key_arn` | str |  | Customer-managed KMS key for the knowledge base, secret and certificate object. |
| `owner` | str |  | Free-form owner label. Not used by setup. |
| `tags` | dict |  | Extra tags applied to every resource the tool creates. |
| `validation` | dict |  | Inputs for `validate`: query, authorized_user, unauthorized_user. |
| `overrides` | dict |  | Request overrides for create_data_source and create_knowledge_base. |
| `connector_params_overrides` | dict |  | Deep-merged into connectorParameters. |

`[connectors.<name>.validation]` takes `query`, `authorized_user`, `unauthorized_user`.

## SharePoint and OneDrive

| Key | Type | Default | Description |
|---|---|---|---|
| `tenant_id` | str |  | **Required.** Microsoft Entra tenant id. Can be set once in [defaults.microsoft]. |
| `auth_method` | str | `"az"` | How setup gets a Microsoft Graph token. One of: `az`, `device_code`. |
| `cert_s3_bucket` | str |  | Bucket for the certificate. Defaults to `kb-connector-certs-<account>-<region>`. |
| `cert_s3_key_prefix` | str |  | Key prefix for the certificate object. |
| `cert_valid_days` | int | `365` | Certificate lifetime in days. |
| `signing_key_arn` | str |  | Quick target: existing KMS signing key to use. |
| `signing_key_alias` | str |  | Quick target: alias for the KMS signing key. |
| `sites_selected` | bool | `false` | Grant per-site access with Sites.Selected instead of tenant-wide read. SharePoint only. |

## `type = "sharepoint"`

| Key | Type | Default | Description |
|---|---|---|---|
| `credential` | str | `"cert"` | Credential mode. Only cert is automated. One of: `cert`, `client_secret`, `ropc`. |
| `acl` | bool | `false` | Document-level access control. Cannot be changed later. |
| `site_urls` | list |  | **Required.** Sites to crawl, as /sites/<name> URLs. |
| `sharepoint_host` | str |  | Tenant host, for example contoso.sharepoint.com. |
| `sharepoint_domain` | str |  | Quick target: tenant root URL the Quick console asks for. |
| `crawl_files` | bool | `true` | Crawl files. |
| `crawl_pages` | bool | `true` | Crawl pages. |
| `inclusion_item_paths` | list |  | Paths to crawl. Replaces the site_urls crawl rather than narrowing it. |
| `exclusion_item_paths` | list |  | Paths to skip. |
| `inclusion_file_name_patterns` | list |  | File name patterns to include (regex). |
| `exclusion_file_name_patterns` | list |  | File name patterns to skip (regex). |
| `inclusion_file_path` | list |  | File path patterns to include (regex). |
| `exclusion_file_path` | list |  | File path patterns to skip (regex). |
| `modified_date_after` | str |  | Only items modified after this ISO 8601 time. |
| `modified_date_before` | str |  | Only items modified before this ISO 8601 time. |

## `type = "onedrive"`

| Key | Type | Default | Description |
|---|---|---|---|
| `credential` | str | `"cert"` | Credential mode. One of: `cert`, `client_secret`, `oauth2_refresh`. |
| `acl` | bool | `false` | Document-level access control. Cannot be changed later. |
| `crawl_personal_drives` | bool | `true` | Crawl users' personal drives. |
| `crawl_shared_with_me` | bool | `false` | Crawl items shared with each user. |
| `inclusion_user_emails` | list |  | Only crawl these users' drives. |

## `type = "s3"`

| Key | Type | Default | Description |
|---|---|---|---|
| `bucket_name` | str |  | **Required.** Bucket to crawl. |
| `bucket_owner_account_id` | str |  | Account that owns the bucket. Defaults to the caller's account. |
| `acl` | bool | `false` | Document-level access control. Cannot be changed later. |
| `acl_s3_uri` | str |  | S3 URI of the global ACL file. Used when acl is true. |
| `inclusion_prefixes` | list |  | Only crawl these key prefixes. |
| `exclusion_prefixes` | list |  | Skip these key prefixes. |
| `inclusion_patterns` | list |  | Only crawl keys matching these patterns. |
| `exclusion_patterns` | list |  | Skip keys matching these patterns. |
| `max_file_size_mb` | int or str |  | Largest file to crawl, in MB. 1 to 500 without media extraction; up to 1500 with it. |
| `metadata_files_prefix` | str |  | Prefix of .metadata.json sidecar files. |

## `type = "web"`

| Key | Type | Default | Description |
|---|---|---|---|
| `seed_urls` | list |  | URLs to start crawling from. Set this or sitemap_urls. |
| `sitemap_urls` | list |  | Sitemap URLs to crawl. |
| `auth_mode` | str | `"no_auth"` | Authentication for the crawl target. One of: `no_auth`, `basic_auth`. |
| `username` | str |  | basic_auth user name. |
| `password` | str |  | basic_auth password. Prefer leaving this out and entering it when prompted. |
| `crawl_depth` | int |  | Maximum link depth from the seed URLs. |
| `max_links_per_url` | int |  | Maximum links followed per page. |
| `max_crawled_urls_per_minute` | int |  | Crawl rate limit. |
| `sync_scope` | str |  | How far the crawler follows links. One of: `ALL_DOMAINS`, `DOMAINS_ONLY`, `PATH_SPECIFIC`, `SUB_DOMAINS`. |
| `crawl_attachments` | bool | `false` | Crawl linked attachments. |
| `max_file_size_mb` | int or str |  | Largest file to crawl, in MB. 1 to 500 without media extraction; up to 1500 with it. |
| `inclusion_filters` | list |  | Only crawl URLs matching these patterns. |
| `exclusion_filters` | list |  | Skip URLs matching these patterns. |

## `type = "confluence"`

| Key | Type | Default | Description |
|---|---|---|---|
| `host_url` | str |  | **Required.** Confluence URL, for example https://company.atlassian.net. |
| `credential` | str | `"oauth2"` | Credential mode. ACL requires basic. One of: `oauth2`, `basic`, `basic_auth`. |
| `hosting_type` | str | `"SAAS"` | Hosting type. |
| `acl` | bool | `false` | Document-level access control. Cannot be changed later. |
| `space_keys` | list |  | Only crawl these spaces. |
| `exclusion_space_keys` | list |  | Skip these spaces. |
| `inclusion_mime_types` | list |  | Only crawl these MIME types. |
| `exclusion_mime_types` | list |  | Skip these MIME types. |
| `data_entities` | dict |  | Content types to crawl, for example { crawl_page = true, crawl_blog = false }. |

## `type = "googledrive"`

| Key | Type | Default | Description |
|---|---|---|---|
| `credential` | str | `"oauth2"` | Credential mode. ACL requires service_account. One of: `oauth2`, `service_account`. |
| `acl` | bool | `false` | Document-level access control. Cannot be changed later. |
| `shared_drives` | list |  | Only crawl these shared drive ids. |
| `shared_drive_ids` | list |  | Alias for shared_drives. |
| `exclusion_shared_drive_ids` | list |  | Skip these shared drive ids. |
| `inclusion_mime_types` | list |  | Only crawl these MIME types. |
| `exclusion_mime_types` | list |  | Skip these MIME types. |
| `inclusion_folder_ids` | list |  | Only crawl these folder ids. |
| `inclusion_file_ids` | list |  | Only crawl these file ids. |
| `data_entities` | dict |  | Drives to crawl, for example { crawl_my_drive = true, crawl_shared_drives = true }. |
