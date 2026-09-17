from pydantic import BaseModel


# =========================
# USER SCHEMAS
# =========================

class UserCreate(BaseModel):
    name: str
    email: str
    password: str
    mobile: str | None = None
    address: str | None = None


class UserUpdate(BaseModel):
    name: str
    email: str
    password: str | None = None
    mobile: str | None = None
    address: str | None = None


class UserResponse(BaseModel):
    id: int
    name: str
    email: str
    mobile: str | None = None
    address: str | None = None

    class Config:
        from_attributes = True
class UserListResponse(BaseModel):
    id: int
    name: str
    email: str
    mobile: str | None = None
    address: str | None = None
    role: str

    class Config:
        from_attributes = True

# =========================
# ROLE SCHEMAS
# =========================

class RoleCreate(BaseModel):
    name: str


class RoleUpdate(BaseModel):
    name: str


# =========================
# USER ROLE SCHEMAS
# =========================

class UserRoleCreate(BaseModel):
    user_id: int
    role_id: int


class UserRoleUpdate(BaseModel):
    user_id: int
    role_id: int


# =========================
# AUTH SCHEMAS
# =========================

class RegisterRequest(BaseModel):
    name: str
    email: str
    password: str
    mobile: str | None = None
    address: str | None = None


class LoginRequest(BaseModel):
    email: str
    password: str


class RoleChangeRequest(BaseModel):
    role_id: int