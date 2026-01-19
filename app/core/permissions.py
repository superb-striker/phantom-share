"""
permissions.py – Role-Based Access Control helpers.

Roles (in ascending privilege order):
  readonly  → can only retrieve secrets (no create/delete)
  user      → full CRUD on own secrets
  admin     → full access including /api/admin/* endpoints
"""
from fastapi import Depends, HTTPException, status
from app.core.security import get_current_user

ROLE_HIERARCHY = {"readonly": 0, "user": 1, "admin": 2}

def _require_role(minimum_role: str):
    # Factory: returns a FastAPI dependency that enforces a minimum role
    async def dependency(current_user: dict = Depends(get_current_user)) -> dict:
        # user must already be authenticated then role is checked
        # convert roles to numbers and check if allowed to access
        user_level = ROLE_HIERARCHY.get(current_user["role"], -1)
        required_level = ROLE_HIERARCHY.get(minimum_role, 99)
        if user_level < required_level:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires '{minimum_role}' role or higher",
            )
        return current_user
    return dependency


# Convenient pre-built dependencies
# How you’d use them: 
# Only logged-in users -> Depends(require_user)
# Admin-only -> Depends(require_admin)
require_user  = _require_role("user")
require_admin = _require_role("admin")


def require_owns_secret(secret_owner_id: str | None, current_user: dict) -> None:
    # Raises 403 if current_user is not admin and doesn't own the secret.
    # Call this inside route handlers after fetching the secret.
    if current_user["role"] == "admin":
        return
    if secret_owner_id and str(secret_owner_id) != current_user["id"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have permission to access this secret",
        )