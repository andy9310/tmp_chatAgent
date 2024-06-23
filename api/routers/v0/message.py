"post question"
from fastapi.security import OAuth2PasswordBearer
from pydantic.typing import Annotated
from pydantic import BaseModel, Field
from fastapi import APIRouter, Body, HTTPException, Depends
from datetime import datetime
from ...logger import logger
import httpx
import jwt


_CORE_SERVICE_URL = "http://core-service:8080"
router = APIRouter(prefix="/message")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

class QuestionResponse(BaseModel):
    answer: str = Field(examples=["我不是機器人"])
    
async def forward(message):
    post_url = f"{_CORE_SERVICE_URL}/api/v0/question"
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                post_url,
                headers={
                    "X-Customer-ID": "1",
                    "X-API-Key": "4X0YYzC2pnsw7N5jUrNorxJQHNeu-Tmd-hHJ7QTasXg"
                },
                json={"question": message},
                follow_redirects=True,
                timeout=100
            )
            response.raise_for_status()  # 檢查 HTTP 狀態碼，非 2xx 將引發 HTTPStatusError
            return response.json()
    except httpx.HTTPStatusError as e:
        logger.error("HTTP error occurred: %s - %s",
                     e.response.status_code, e.response.text)
        raise HTTPException(status_code=e.response.status_code,
                            detail=e.response.text) from e
    except httpx.RequestError as e:
        logger.error("Request error occurred: %s", str(e))
        raise HTTPException(status_code=500,
                            detail="Unable to connect to the service") from e
    except Exception as e:
        logger.error("Unexpected error occurred: %s", str(e))
        raise HTTPException(status_code=500,
                            detail="An unexpected error occurred") from e
# Dependency to get the current user from the token
def get_current_user(token: str = Depends(oauth2_scheme)):
    payload = verify_token(token)
    return payload

def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )



@router.post("/", status_code=200)
async def question(message: Annotated[str, Body(media_type="application/json")]):
    """The API to Ask questions."""
    try:
        send_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        logger.info("[INFO][WEB-SERVICE][PostQuestion]receive question: %s, %s",
                    message, send_timestamp)
        if verify_token(message):
            response = await forward(message)
        else:
            response = 
        response_timestamp =datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        logger.info("[INFO][WEB-SERVICE][PostQuestion] receive answer: %s, %s",
                    response["answer"], response_timestamp)

        return QuestionResponse(answer=response["answer"])
    except HTTPException as e:
        error_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        logger.error("[INFO][WEB-SERVICE][PostQuestion]receive ans err: %s, %s",
                     str(e), error_timestamp)
        raise HTTPException(status_code=500,
                            detail="receive ans error occurred") from e
    