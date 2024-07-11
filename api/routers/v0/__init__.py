"router initial"
from fastapi import APIRouter
from .jwtAccess import router as jwt_router
router = APIRouter(prefix="/v0")
router.include_router(jwt_router)
