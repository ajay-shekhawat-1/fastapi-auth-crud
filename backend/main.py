from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from fastapi.middleware.cors import CORSMiddleware
from security import (
    hash_password,
    verify_password,
    create_access_token,
    decode_access_token
)

from database import engine, Base, SessionLocal
import models

from schemas import (
    UserCreate,
    UserUpdate,
    RoleCreate,
    RoleUpdate,
    UserRoleCreate,
    UserListResponse,
    UserRoleUpdate,
    RegisterRequest,
    UserResponse,
    LoginRequest,
    RoleChangeRequest,
)


# ============================================================
# INITIALIZATION
# ============================================================

# OAuth2 scheme pointing to our login route
oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="login"
)

# Create database tables
Base.metadata.create_all(bind=engine)

# Create FastAPI application
app = FastAPI()


# ============================================================
# DATABASE DEPENDENCY
# ============================================================
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
def get_db():
    db = SessionLocal()

    try:
        yield db

    finally:
        db.close()


# ============================================================
# CURRENT USER DEPENDENCY
# ============================================================

def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
):
    # Decode JWT token
    payload = decode_access_token(token)

    # Token invalid or expired
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token"
        )

    # Get user ID from token
    user_id = payload.get("sub")

    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token"
        )

    # Find user in database
    user = db.query(models.User).filter(
        models.User.id == int(user_id)
    ).first()

    # User does not exist
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    return user


# ============================================================
# USER ROLE DEPENDENCY
# ============================================================

def get_current_user_role(
    current_user: models.User,
    db: Session
):
    user_role = db.query(models.UserRole).filter(
        models.UserRole.user_id == current_user.id
    ).first()

    if user_role is None:
        return "User"

    role = db.query(models.Role).filter(
        models.Role.id == user_role.role_id
    ).first()

    # Role does not exist
    if role is None:
        return "User"

    return role.name


# ============================================================
# ADMIN DEPENDENCY
# ============================================================

def require_admin(
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    role = get_current_user_role(current_user, db)

    if role not in ["Admin", "Super Admin"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )

    return current_user

def require_super_admin(
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    role = get_current_user_role(current_user, db)

    if role != "Super Admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Super Admin access required"
        )

    return current_user
# ============================================================
# HOME
# ============================================================

@app.get("/")
def home():
    return {
        "message": "FastAPI is working"
    }


# ============================================================
# AUTHENTICATION
# ============================================================


# ------------------------------------------------------------
# REGISTER USER
# ------------------------------------------------------------

@app.post("/register")
def register_user(
    register_data: RegisterRequest,
    db: Session = Depends(get_db)
):
    # Check if email already exists
    existing_user = db.query(models.User).filter(
        models.User.email == register_data.email
    ).first()

    if existing_user is not None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )

    # Create new user
    new_user = models.User(
        name=register_data.name,
        email=register_data.email,
        password=hash_password(register_data.password),
        mobile=register_data.mobile,
        address=register_data.address
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    # Find the normal User role
    user_role = db.query(models.Role).filter(
        models.Role.name == "User"
    ).first()

    if user_role is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="User role not found"
        )

    # Assign User role
    new_user_role = models.UserRole(
        user_id=new_user.id,
        role_id=user_role.id
    )

    db.add(new_user_role)
    db.commit()

    return {
        "message": "User registered successfully",
        "user_id": new_user.id,
        "user_name": new_user.name,
        "email": new_user.email,
        "role": "User"
    }


# ------------------------------------------------------------
# LOGIN USER
# ------------------------------------------------------------

@app.post("/login")
def login_user(
    login_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    # OAuth2 uses "username", but we use it as email
    user = db.query(models.User).filter(
        models.User.email == login_data.username
    ).first()

    # Check email
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password"
        )

    # Check password
    password_correct = verify_password(
        login_data.password,
        user.password
    )

    if not password_correct:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password"
        )

    # Get user's role
    user_role = db.query(models.UserRole).filter(
        models.UserRole.user_id == user.id
    ).first()

    # Default role
    role_name = "User"

    if user_role:
        role = db.query(models.Role).filter(
            models.Role.id == user_role.role_id
        ).first()

        if role:
            role_name = role.name

    # Create JWT access token
    access_token = create_access_token(
        data={
            "sub": str(user.id)
        }
    )

    return {
        "access_token": access_token,
        "token": access_token,
        "token_type": "bearer",
        "user_id": user.id,
        "user_name": user.name,
        "role": role_name
    }


# ------------------------------------------------------------
# GET CURRENT LOGGED-IN USER
# ------------------------------------------------------------

@app.get("/me")
def get_current_user_info(
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    role_name = get_current_user_role(current_user, db)

    return {
        "id": current_user.id,
        "name": current_user.name,
        "email": current_user.email,
        "role": role_name
    }


# USER CRUD
# ============================================================


# ------------------------------------------------------------
# CREATE USER - ADMIN ONLY
# ------------------------------------------------------------

@app.post(
    "/users",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED
)
def create_user(
    user: UserCreate,
    db: Session = Depends(get_db),
    admin_role=Depends(require_admin)
):
    # Check if email already exists
    existing_user = db.query(models.User).filter(
        models.User.email == user.email
    ).first()

    if existing_user is not None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )

    # Find default User role
    default_role = db.query(models.Role).filter(
        models.Role.name == "User"
    ).first()

    if default_role is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="User role not found"
        )

    # Create user
    new_user = models.User(
        name=user.name,
        email=user.email,
        password=hash_password(user.password),
        mobile=user.mobile,
        address=user.address
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    # Assign User role
    new_user_role = models.UserRole(
        user_id=new_user.id,
        role_id=default_role.id
    )

    db.add(new_user_role)
    db.commit()

    return new_user


# ------------------------------------------------------------
# GET ALL USERS
# ------------------------------------------------------------

@app.get("/users", response_model=list[UserListResponse])
def get_users(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    results = (
        db.query(models.User, models.Role.name)
        .outerjoin(
            models.UserRole,
            models.UserRole.user_id == models.User.id
        )
        .outerjoin(
            models.Role,
            models.Role.id == models.UserRole.role_id
        )
        .all()
    )

    return [
        {
            "id": user.id,
            "name": user.name,
            "email": user.email,
            "mobile": user.mobile,
            "address": user.address,
            "role": role_name or "User"
        }
        for user, role_name in results
    ]


# ------------------------------------------------------------
# GET USER BY ID
# ------------------------------------------------------------

@app.get(
    "/users/{user_id}",
    response_model=UserResponse
)
def get_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    user = db.query(models.User).filter(
        models.User.id == user_id
    ).first()

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    return user


# ------------------------------------------------------------
# UPDATE USER
# ------------------------------------------------------------

@app.put(
    "/users/{user_id}"
)
def update_user(
    user_id: int,
    user_data: UserUpdate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_admin)
):
    # Find user
    user = db.query(models.User).filter(
        models.User.id == user_id
    ).first()

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    # Check email conflict
    existing_user = db.query(models.User).filter(
        models.User.email == user_data.email,
        models.User.id != user_id
    ).first()

    if existing_user is not None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered by another user"
        )

    # Update user
    user.name = user_data.name
    user.email = user_data.email
    user.mobile = user_data.mobile
    user.address = user_data.address

    if user_data.password:
        user.password = hash_password(user_data.password)

    db.commit()
    db.refresh(user)

    return {
        "message": "User updated successfully",
        "user_id": user.id
    }


# ------------------------------------------------------------
# DELETE USER
# ------------------------------------------------------------

@app.delete("/users/{user_id}")
def delete_user(
    user_id: int,
    current_user: models.User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    # Find the user
    user = db.query(models.User).filter(
        models.User.id == user_id
    ).first()

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    # Do not allow an admin to delete themselves
    if user.id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You cannot delete your own account"
        )

    # Delete the user's role mapping first
    user_role = db.query(models.UserRole).filter(
        models.UserRole.user_id == user_id
    ).first()

    if user_role is not None:
        db.delete(user_role)
        db.flush()

    # Delete the user
    db.delete(user)
    db.commit()

    return {
        "message": "User deleted successfully",
        "user_id": user_id
    }

@app.put("/users/{user_id}/role")
def change_user_role(
    user_id: int,
    role_data: RoleChangeRequest,
    current_user: models.User = Depends(require_super_admin),
    db: Session = Depends(get_db)
):
    # Find target user
    target_user = db.query(models.User).filter(
        models.User.id == user_id
    ).first()

    if target_user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    # Find requested role
    new_role = db.query(models.Role).filter(
        models.Role.id == role_data.role_id
    ).first()

    if new_role is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Role not found"
        )

    # Find existing role mapping
    user_role = db.query(models.UserRole).filter(
        models.UserRole.user_id == user_id
    ).first()

    if user_role is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User role mapping not found"
        )

    # Update role
    user_role.role_id = new_role.id

    db.commit()
    db.refresh(user_role)

    return {
        "message": "User role updated successfully",
        "user_id": target_user.id,
        "user_name": target_user.name,
        "role": new_role.name
    }
# ============================================================
# ROLE CRUD
# ============================================================


# ------------------------------------------------------------
# CREATE ROLE
# ------------------------------------------------------------

@app.post(
    "/roles",
    status_code=status.HTTP_201_CREATED
)
def create_role(
    role: RoleCreate,
    db: Session = Depends(get_db),
    admin_role = Depends(require_admin)
):
    new_role = models.Role(
        name=role.name
    )

    db.add(new_role)
    db.commit()
    db.refresh(new_role)

    return new_role


# ------------------------------------------------------------
# GET ALL ROLES
# ------------------------------------------------------------

@app.get("/roles")
def get_roles(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    roles = db.query(models.Role).all()

    return roles


# ------------------------------------------------------------
# GET ROLE BY ID
# ------------------------------------------------------------

@app.get("/roles/{role_id}")
def get_role(
    role_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    role = db.query(models.Role).filter(
        models.Role.id == role_id
    ).first()

    if role is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Role not found"
        )

    return role


# ------------------------------------------------------------
# UPDATE ROLE
# ------------------------------------------------------------

@app.put("/roles/{role_id}")
def update_role(
    role_id: int,
    role_data: RoleUpdate,
    db: Session = Depends(get_db),
    admin_role = Depends(require_admin)
):
    role = db.query(models.Role).filter(
        models.Role.id == role_id
    ).first()

    if role is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Role not found"
        )

    role.name = role_data.name

    db.commit()
    db.refresh(role)

    return role


# ------------------------------------------------------------
# DELETE ROLE
# ------------------------------------------------------------

@app.delete("/roles/{role_id}")
def delete_role(
    role_id: int,
    db: Session = Depends(get_db),
    admin_role = Depends(require_admin)
):
    role = db.query(models.Role).filter(
        models.Role.id == role_id
    ).first()

    if role is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Role not found"
        )

    db.delete(role)
    db.commit()

    return {
        "message": "Role deleted successfully"
    }


# ============================================================
# USER ROLE CRUD
# ============================================================


# ------------------------------------------------------------
# CREATE USER ROLE
# ------------------------------------------------------------

@app.post(
    "/user-roles",
    status_code=status.HTTP_201_CREATED
)
def create_user_role(
    user_role: UserRoleCreate,
    db: Session = Depends(get_db),
    admin_role = Depends(require_admin)
):
    # Check user
    user = db.query(models.User).filter(
        models.User.id == user_role.user_id
    ).first()

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    # Check role
    role = db.query(models.Role).filter(
        models.Role.id == user_role.role_id
    ).first()

    if role is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Role not found"
        )

    # Create user-role relationship
    new_user_role = models.UserRole(
        user_id=user_role.user_id,
        role_id=user_role.role_id
    )

    db.add(new_user_role)
    db.commit()
    db.refresh(new_user_role)

    return new_user_role


# ------------------------------------------------------------
# GET ALL USER ROLES
# ------------------------------------------------------------

@app.get("/user-roles")
def get_user_roles(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    user_roles = db.query(models.UserRole).all()

    return user_roles


# ------------------------------------------------------------
# GET USER ROLE BY ID
# ------------------------------------------------------------

@app.get("/user-roles/{user_role_id}")
def get_user_role(
    user_role_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    user_role = db.query(models.UserRole).filter(
        models.UserRole.id == user_role_id
    ).first()

    if user_role is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="UserRole not found"
        )

    return user_role


# ------------------------------------------------------------
# UPDATE USER ROLE
# ------------------------------------------------------------

@app.put("/user-roles/{user_role_id}")
def update_user_role(
    user_role_id: int,
    user_role_data: UserRoleUpdate,
    db: Session = Depends(get_db),
    admin_role = Depends(require_admin)
):
    # Find user-role relationship
    user_role = db.query(models.UserRole).filter(
        models.UserRole.id == user_role_id
    ).first()

    if user_role is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="UserRole not found"
        )

    # Check user
    user = db.query(models.User).filter(
        models.User.id == user_role_data.user_id
    ).first()

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    # Check role
    role = db.query(models.Role).filter(
        models.Role.id == user_role_data.role_id
    ).first()

    if role is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Role not found"
        )

    # Update relationship
    user_role.user_id = user_role_data.user_id
    user_role.role_id = user_role_data.role_id

    db.commit()
    db.refresh(user_role)

    return user_role


# ------------------------------------------------------------
# DELETE USER ROLE
# ------------------------------------------------------------

@app.delete("/user-roles/{user_role_id}")
def delete_user_role(
    user_role_id: int,
    db: Session = Depends(get_db),
    admin_role = Depends(require_admin)
):
    # Find user-role relationship
    user_role = db.query(models.UserRole).filter(
        models.UserRole.id == user_role_id
    ).first()

    if user_role is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="UserRole not found"
        )

    db.delete(user_role)
    db.commit()

    return {
        "message": "UserRole deleted successfully"
    }

