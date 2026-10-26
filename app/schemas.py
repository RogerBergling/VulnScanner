"""Pydantic request models for the API."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator

# Characters that are safe in both POSIX shell (``. ./.env``) and Windows
# ``cmd.exe`` (``set "KEY=VALUE"``) without quoting. Keeping the admin password
# inside this set lets the settings endpoint write it to ``.env`` safely.
_ADMIN_PASSWORD_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._~@+=:,/-"
)


def _non_blank(value: str, name: str) -> str:
    value = (value or "").strip()
    if not value:
        raise ValueError(f"{name} is required")
    return value


class CustomerCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    description: str = Field(default="", max_length=2000)

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        return _non_blank(value, "Customer name")


class CustomerUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    description: str | None = Field(default=None, max_length=2000)


class GroupCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    description: str = Field(default="", max_length=2000)

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        return _non_blank(value, "Group name")


class GroupUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    description: str | None = Field(default=None, max_length=2000)


AssetKind = Literal["host", "web", "repo", "github", "domain", "agent", "other"]


class AssetCreate(BaseModel):
    name: str = Field(min_length=1, max_length=160)
    kind: AssetKind = "host"
    identifier: str = Field(default="", max_length=2000)
    description: str = Field(default="", max_length=2000)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        return _non_blank(value, "Asset name")


class AssetUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=160)
    kind: AssetKind | None = None
    identifier: str | None = Field(default=None, max_length=2000)
    description: str | None = Field(default=None, max_length=2000)
    metadata: dict[str, Any] | None = None


ScanType = Literal["web", "network", "repo", "github", "ad"]
CredentialOS = Literal["linux", "windows"]
CredentialAuth = Literal["password", "key"]
CredentialAccount = Literal["local", "domain"]


class ScanCredentialInput(BaseModel):
    """Per-scan credential override. Secrets are stored encrypted."""

    username: str = Field(min_length=1, max_length=200)
    password: str | None = Field(default=None, max_length=40_000)
    private_key: str | None = Field(default=None, max_length=40_000)
    passphrase: str | None = Field(default=None, max_length=4_000)
    domain: str = Field(default="", max_length=200)
    account_type: CredentialAccount = "local"
    auth_type: CredentialAuth | None = None


class CredentialCreate(BaseModel):
    name: str = Field(default="", max_length=160)
    os: CredentialOS
    username: str = Field(min_length=1, max_length=200)
    password: str | None = Field(default=None, max_length=40_000)
    private_key: str | None = Field(default=None, max_length=40_000)
    passphrase: str | None = Field(default=None, max_length=4_000)
    auth_type: CredentialAuth = "password"
    domain: str = Field(default="", max_length=200)
    account_type: CredentialAccount = "local"
    customer_id: int | None = None
    asset_id: int | None = None
    is_default: bool = False


class CredentialUpdate(BaseModel):
    name: str | None = Field(default=None, max_length=160)
    os: CredentialOS | None = None
    username: str | None = Field(default=None, min_length=1, max_length=200)
    password: str | None = Field(default=None, max_length=40_000)
    private_key: str | None = Field(default=None, max_length=40_000)
    passphrase: str | None = Field(default=None, max_length=4_000)
    auth_type: CredentialAuth | None = None
    domain: str | None = Field(default=None, max_length=200)
    account_type: CredentialAccount | None = None
    is_default: bool | None = None


class AssetCredentialUpdate(BaseModel):
    linux: int | None = None
    windows: int | None = None


class ScanCreate(BaseModel):
    customer_id: int
    group_id: int | None = None
    asset_id: int | None = None
    scan_type: ScanType
    target: str = Field(default="", max_length=4000)
    options: dict[str, Any] = Field(default_factory=dict)
    # Per-scan credential overrides keyed by "linux"/"windows". The values are
    # encrypted into the per-scan credential table and never returned.
    credentials: dict[CredentialOS, ScanCredentialInput] | None = None
    github_token: str | None = Field(default=None, max_length=500)
    requested_by: str = Field(default="local", max_length=120)
    # Optional execution agent for network scans. When set, the job is queued
    # for that agent and runs from its network position.
    agent_id: str | None = Field(default=None, max_length=80)

    @model_validator(mode="after")
    def check_target(self) -> "ScanCreate":
        if self.scan_type in {"web", "network", "repo", "github", "ad"} and not self.target.strip():
            raise ValueError("This scan type requires a target")
        if self.credentials and self.scan_type != "network":
            raise ValueError("Credentials can only be supplied for network scans")
        return self


class FindingStatusUpdate(BaseModel):
    status: Literal["open", "acknowledged", "false_positive", "accepted", "fixed"]


class AgentTokenRequest(BaseModel):
    customer_id: int
    group_id: int
    agent_name: str = Field(default="", max_length=160)
    hours: int = Field(default=24, ge=1, le=168)
    months: int | None = Field(default=None, ge=0, le=12)
    years: int | None = Field(default=None, ge=0, le=10)


class AgentUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=160)
    customer_id: int | None = None
    group_id: int | None = None


class AgentEnrollRequest(BaseModel):
    enrollment_token: str = Field(min_length=10, max_length=300)
    name: str = Field(default="", max_length=160)
    platform: str = Field(default="", max_length=120)
    version: str = Field(default="", max_length=60)
    hostname: str = Field(default="", max_length=200)
    capabilities: list[str] = Field(default_factory=list)
    ip: str = Field(default="", max_length=100)


class AgentHeartbeatRequest(BaseModel):
    platform: str = Field(default="", max_length=120)
    version: str = Field(default="", max_length=60)
    hostname: str = Field(default="", max_length=200)
    capabilities: list[str] = Field(default_factory=list)
    ip: str = Field(default="", max_length=100)


class AgentJobResult(BaseModel):
    status: Literal["completed", "failed", "cancelled"] = "completed"
    results: dict[str, Any] = Field(default_factory=dict)
    error: str = Field(default="", max_length=4000)


class AgentScanRequest(BaseModel):
    modules: list[Literal["system", "packages", "ports", "secrets", "ad", "repo", "network"]] = Field(
        default_factory=lambda: ["system", "packages", "ports"]
    )
    paths: list[str] = Field(default_factory=list)
    target: str = Field(default="", max_length=4000)
    options: dict[str, Any] = Field(default_factory=dict)

    @field_validator("modules")
    @classmethod
    def unique_modules(cls, value: list[str]) -> list[str]:
        return list(dict.fromkeys(value))


class SettingsUpdate(BaseModel):
    allow_external_apis: bool | None = None
    nuclei_enabled: bool | None = None
    nmap_enabled: bool | None = None

    # SMTP notification settings.
    smtp_host: str | None = Field(default=None, max_length=253)
    smtp_port: str | None = Field(default=None, max_length=5)
    smtp_user: str | None = Field(default=None, max_length=320)
    smtp_password: str | None = Field(default=None, max_length=1024)
    smtp_from: str | None = Field(default=None, max_length=320)
    notify_email_default: str | None = Field(default=None, max_length=320)
    notify_webhook_default: str | None = Field(default=None, max_length=2048)

    # Scan guardrails.
    max_web_hosts: int | None = Field(default=None, ge=1, le=10_000)
    workers: int | None = Field(default=None, ge=1, le=32)
    max_repo_bytes: int | None = Field(default=None, ge=1_048_576, le=10_737_418_240)
    max_source_file_bytes: int | None = Field(default=None, ge=1024, le=104_857_600)
    max_scan_files: int | None = Field(default=None, ge=1, le=1_000_000)
    max_cidr_hosts: int | None = Field(default=None, ge=1, le=65_536)
    agent_job_timeout: int | None = Field(default=None, ge=60, le=86_400)

    @field_validator("smtp_port")
    @classmethod
    def validate_smtp_port(cls, value: str | None) -> str | None:
        if value is None or value == "":
            return value
        if not value.isdigit() or not 1 <= int(value) <= 65_535:
            raise ValueError("SMTP port must be a number between 1 and 65535")
        return value

    @field_validator("notify_webhook_default")
    @classmethod
    def validate_webhook(cls, value: str | None) -> str | None:
        if value is None or value == "":
            return value
        if not value.lower().startswith(("http://", "https://")):
            raise ValueError("Webhook URL must start with http:// or https://")
        return value


class AdminPasswordUpdate(BaseModel):
    # An empty string disables dashboard authentication. Non-empty passwords
    # must be long enough and avoid characters that would need shell quoting in
    # .env (newlines, spaces, $, %, quotes, etc.).
    password: str = Field(default="", max_length=128)

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        if value == "":
            return value
        if len(value) < 12:
            raise ValueError("Admin password must be at least 12 characters")
        invalid = sorted(set(value) - _ADMIN_PASSWORD_CHARS)
        if invalid:
            raise ValueError(
                "Admin password contains unsupported characters. Use letters, digits, "
                "and . _ ~ @ + = : , / -"
            )
        return value


class ADImportRequest(BaseModel):
    customer_id: int
    group_id: int | None = None
    asset_id: int | None = None
    report: dict[str, Any]
