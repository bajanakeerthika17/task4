from typing import Optional, List, Any
from pydantic import BaseModel, Field, field_validator, model_validator
from app.security import (
    validate_email_format,
    validate_password_strength,
    sanitize_string
)

class UserRegisterRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=100, description="Full Name of the user")
    email: str = Field(..., max_length=254, description="User email address")
    password: str = Field(..., min_length=8, max_length=128, description="Account password")
    confirm_password: str = Field(..., min_length=8, max_length=128, description="Password confirmation")

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        clean = sanitize_string(v)
        if len(clean) < 2:
            raise ValueError("Full Name must be at least 2 characters long.")
        return clean

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        clean = v.strip().lower()
        if not validate_email_format(clean):
            raise ValueError("Please provide a valid email address.")
        return clean

    @field_validator("password")
    @classmethod
    def validate_pwd_strength(cls, v: str) -> str:
        is_valid, errors = validate_password_strength(v)
        if not is_valid:
            raise ValueError(" ".join(errors))
        return v

    @model_validator(mode="after")
    def verify_passwords_match(self) -> "UserRegisterRequest":
        if self.password != self.confirm_password:
            raise ValueError("Passwords do not match.")
        return self


class UserLoginRequest(BaseModel):
    email: str = Field(..., max_length=254)
    password: str = Field(..., min_length=1, max_length=128)
    remember_me: bool = False

    @field_validator("email")
    @classmethod
    def clean_email(cls, v: str) -> str:
        return v.strip().lower()


class Verify2FARequest(BaseModel):
    pre_auth_token: str = Field(..., min_length=10, max_length=256)
    code: str = Field(..., min_length=6, max_length=8)

    @field_validator("code")
    @classmethod
    def clean_code(cls, v: str) -> str:
        clean = v.strip().replace(" ", "").replace("-", "")
        if not clean.isdigit() or len(clean) != 6:
            raise ValueError("2FA code must be exactly 6 digits.")
        return clean


class Enable2FAConfirmRequest(BaseModel):
    code: str = Field(..., min_length=6, max_length=8)

    @field_validator("code")
    @classmethod
    def clean_code(cls, v: str) -> str:
        clean = v.strip().replace(" ", "").replace("-", "")
        if not clean.isdigit() or len(clean) != 6:
            raise ValueError("Verification code must be exactly 6 digits.")
        return clean


class Disable2FARequest(BaseModel):
    password: str = Field(..., min_length=1, max_length=128)


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(..., min_length=1, max_length=128)
    new_password: str = Field(..., min_length=8, max_length=128)
    confirm_new_password: str = Field(..., min_length=8, max_length=128)

    @field_validator("new_password")
    @classmethod
    def validate_new_pwd(cls, v: str) -> str:
        is_valid, errors = validate_password_strength(v)
        if not is_valid:
            raise ValueError(" ".join(errors))
        return v

    @model_validator(mode="after")
    def verify_new_passwords_match(self) -> "ChangePasswordRequest":
        if self.new_password != self.confirm_new_password:
            raise ValueError("New passwords do not match.")
        if self.current_password == self.new_password:
            raise ValueError("New password cannot be the same as current password.")
        return self


class APIResponse(BaseModel):
    success: bool
    message: str
    data: Optional[Any] = None
    errors: Optional[List[str]] = None
