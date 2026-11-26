"""Registration, login, and safe session schemas."""

import re
import uuid
from datetime import datetime

from pydantic import BaseModel, Field, field_validator, model_validator


EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


def validate_username_policy(value: str) -> str:
    if re.search(r"\s", value):
        raise ValueError("Username cannot contain spaces.")
    if len(value) < 6 or len(value) > 64:
        raise ValueError("Username must be between 6 and 64 characters.")
    if not re.match(r"^[A-Z]", value):
        raise ValueError("Username must start with an uppercase letter (A-Z).")
    if not re.search(r"[0-9]", value):
        raise ValueError("Username must contain at least one number (0-9).")
    if not re.search(r"[^A-Za-z0-9\s]", value):
        raise ValueError("Username must contain at least one special character.")
    return value


def normalize_username(value: str) -> str:
    return validate_username_policy(value)


def normalize_email(value: str) -> str:
    return value.strip().lower()


def validate_password_policy(value: str) -> str:
    if len(value) < 6 or len(value) > 20:
        raise ValueError("Password must be between 6 and 20 characters.")
    if not re.search(r"[A-Z]", value):
        raise ValueError("Password must contain at least one uppercase letter.")
    if not re.search(r"[a-z]", value):
        raise ValueError("Password must contain at least one lowercase letter.")
    if not re.search(r"[0-9]", value):
        raise ValueError("Password must contain at least one number.")
    if not re.search(r"[^A-Za-z0-9\s]", value):
        raise ValueError("Password must contain at least one special character.")
    return value


class UserResponse(BaseModel):
    id: uuid.UUID | None
    full_name: str
    username: str
    email: str
    role: str
    is_active: bool
    created_at: datetime | None = None
    credential_change_required: bool = False


class RegisterRequest(BaseModel):
    full_name: str = Field(min_length=2, max_length=255)
    username: str = Field(min_length=6, max_length=64)
    email: str = Field(min_length=5, max_length=320)
    password: str
    confirm_password: str

    @field_validator("full_name")
    @classmethod
    def clean_name(cls, value: str) -> str:
        cleaned = " ".join(value.strip().split())
        if len(cleaned) < 2:
            raise ValueError("Full name is required.")
        return cleaned

    @field_validator("username")
    @classmethod
    def clean_username(cls, value: str) -> str:
        return validate_username_policy(value)

    @field_validator("email")
    @classmethod
    def clean_email(cls, value: str) -> str:
        normalized = normalize_email(value)
        if not EMAIL_RE.fullmatch(normalized):
            raise ValueError("Enter a valid email address.")
        return normalized

    @field_validator("password")
    @classmethod
    def strong_password(cls, value: str) -> str:
        return validate_password_policy(value)

    @model_validator(mode="after")
    def passwords_match(self) -> "RegisterRequest":
        if self.password != self.confirm_password:
            raise ValueError("Password confirmation does not match.")
        return self


class LoginRequest(BaseModel):
    identifier: str = Field(min_length=3, max_length=320)
    password: str = Field(min_length=1, max_length=128)

    @field_validator("identifier")
    @classmethod
    def clean_identifier(cls, value: str) -> str:
        return value.strip()


class SessionResponse(BaseModel):
    authenticated: bool
    method: str
    expires_at: datetime | None = None
    user: UserResponse
