"""
permissions.py – Role-Based Access Control helpers.

Roles (in ascending privilege order):
  readonly  -> can only retrieve secrets (no create/delete)
  user      -> full CRUD on own secrets
  admin     -> full access including /api/admin/* endpoints
"""
from enum import IntEnum
from fastapi import Depends, HTTPException, status
from app.core.security import get_current_user

class Role(IntEnum):
    READONLY = 0
    USER     = 1
    ADMIN    = 2
    @classmethod
    def from_str(cls, role: str) -> "Role":
        try:
            return cls[role.upper()]
        except KeyError:
            raise ValueError(f"Unknown role: {role!r}")

def _require_role(minimum_role: Role):
    '''Factory: returns a FastAPI dependency that enforces a minimum role'''
    async def dependency(current_user: dict = Depends(get_current_user)) -> dict:
        if not current_user.get("is_active", True):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Account is deactivated",
            )
        try:
            user_level = Role.from_str(current_user["role"])
        except ValueError:
            # Unknown role stored in DB
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Invalid role assigned to account",
            )
        if user_level.value < minimum_role.value:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires '{minimum_role.name.lower()}' role or higher",
            )
        return current_user
    return dependency


# Convenient pre-built dependencies
# How you’d use them: 
# Only logged-in users -> Depends(require_user)
# Admin-only -> Depends(require_admin)
# Read-only -> Depends(require_readonly)
require_user  = _require_role(Role.USER)
require_admin = _require_role(Role.ADMIN)
require_readonly = _require_role(Role.READONLY)


def require_owns_secret(secret_owner_id: str | None, current_user: dict) -> None:
    # Raises 403 if current_user is not admin and doesn't own the secret.
    # Call this inside route handlers after fetching the secret.
    try:
        role: Role = Role.from_str(current_user["role"])
    except ValueError:
        role = Role.READONLY
    if role.value >= Role.ADMIN.value:
        return
    if secret_owner_id is None:
        # Anonymous secret - no owner recorded, nobody can claim ownership.
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This secret was created anonymously and cannot be managed",
        ) 
    if str(secret_owner_id) != str(current_user["id"]):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have permission to access this secret",
        )