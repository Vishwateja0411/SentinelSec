import ipaddress
import re
from datetime import datetime
from typing import List, Literal, Optional
from urllib.parse import urlsplit
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from backend.app.models.target import TargetType


class TargetBase(BaseModel):
    target: str = Field(..., description="Target IP address or HTTP/HTTPS URL")
    type: TargetType = Field(..., description="Target type: 'ip' or 'url'")
    authorization_attestation: bool = Field(
        ...,
        description="Explicit affirmative confirmation of ownership or written testing authorization",
    )


class TargetCreate(TargetBase):
    @field_validator("authorization_attestation")
    @classmethod
    def validate_attestation(cls, v: bool) -> bool:
        if v is not True:
            raise ValueError(
                "Explicit affirmative authorization attestation is strictly required. "
                "You must confirm you own this target or have documented written permission."
            )
        return v

    @field_validator("target")
    @classmethod
    def sanitize_target_string(cls, v: str) -> str:
        clean = v.strip()
        if not clean:
            raise ValueError("Target string cannot be empty or whitespace.")
        if any(c in clean for c in ["\r", "\n", "\x00"]):
            raise ValueError("Target contains illegal control characters.")
        return clean

    @model_validator(mode="after")
    def validate_target_format(self) -> "TargetCreate":
        raw_target = self.target
        target_type = self.type

        if target_type == TargetType.IP:
            try:
                # Validates standard IPv4 and IPv6 representations
                ipaddress.ip_address(raw_target)
            except ValueError:
                raise ValueError(
                    f"'{raw_target}' is not a valid IPv4 or IPv6 address. "
                    "Domain names and invalid address formats are not accepted for type 'ip'."
                )

        elif target_type == TargetType.URL:
            try:
                parsed = urlsplit(raw_target)
            except Exception:
                raise ValueError(f"'{raw_target}' is a malformed URL.")

            scheme = parsed.scheme.lower()
            if scheme not in ("http", "https"):
                raise ValueError(
                    f"URL scheme '{scheme}' is unsupported. Only 'http://' and 'https://' URLs are permitted."
                )

            if not parsed.netloc:
                raise ValueError("URL must include a valid host / network location.")

            # Reject embedded credentials (RFC 3986 userinfo, e.g. http://user:pass@example.com)
            if parsed.username or parsed.password or "@" in parsed.netloc:
                raise ValueError(
                    "Embedded credentials (userinfo) in target URLs are strictly forbidden."
                )

            # Check hostname validity
            hostname = parsed.hostname
            if not hostname:
                raise ValueError("URL has an invalid or missing hostname.")

            # Reject invalid characters or spaces in host
            if re.search(r"[\s\<\>\"\'\{\}\|\\\^~`]", hostname):
                raise ValueError("URL host contains invalid characters.")

        return self


class TargetResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    target: str
    type: TargetType
    authorization_attestation: bool
    attestation_timestamp: datetime
    created_at: datetime


class TargetListResponse(BaseModel):
    total: int = Field(..., description="Total number of registered targets matching query")
    skip: int = Field(..., description="Pagination offset")
    limit: int = Field(..., description="Pagination limit")
    items: List[TargetResponse] = Field(..., description="List of target records")
