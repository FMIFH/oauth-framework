from fastapi import APIRouter, Depends

from src.core.database import get_db
from src.services.key_manager import jwks

router = APIRouter(prefix="/oauth", tags=["oauth"])

@router.get("/authorize")
def authorize():
    return {"message": "Authorization endpoint"}

@router.post("/token")
def token():
    return {"message": "Token endpoint"}

@router.get("/jwks")
async def jwks_endpoints(session=Depends(get_db)):
    return await jwks(session=session)
