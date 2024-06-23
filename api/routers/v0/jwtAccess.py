"post question"
from pydantic.typing import Annotated
from pydantic import BaseModel, Field
from fastapi import APIRouter, Body, HTTPException
from datetime import datetime
from ...logger import logger
from dotenv import load_dotenv
from datetime import datetime, timezone
import hashlib
import httpx
import jwt
import os
import json

# _CORE_SERVICE_URL = "http://core-service:8080"

router = APIRouter(prefix="/jwtAccess")

class JWTResponse(BaseModel):
    message: bool = Field(examples=[True]),
    jwt_token: str = Field(examples=["jwt_token"])

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
## randomly generate jwt token
def generate_jwt(secret_key, algorithm="HS256", expiry_minutes=30):
    # Add the expiration time to the payload
    payload = {"user_id": 0,"username": "IEEE"}
    payload['exp'] = datetime.now(timezone.utc) + datetime.timedelta(minutes=expiry_minutes)
    token = jwt.encode(payload, secret_key, algorithm=algorithm) 
    return token

def load_secret_file(file_path):
    secret_vars = {}
    with open(file_path, 'r') as file:
        for line in file:
            if line.strip() and not line.startswith('#'):
                key, value = line.strip().split('=', 1)
                secret_vars[key] = value
    return secret_vars

def write_secret_file(env_vars):
    with open('./secret.txt', 'w') as file:
        for key, value in env_vars.items():
            file.write(f"{key}={value}\n")

def verify( jwt_token:str ):
    hashed_jwt_bytes = bytes.fromhex( load_secret_file('./secret.txt') )
    salt = hashed_jwt_bytes[:16]
    stored_hash = hashed_jwt_bytes[16:]
    hash_object = hashlib.sha256(salt + jwt_token.encode())
    new_hash = hash_object.digest()
    if new_hash == stored_hash:
        return True
    else:
        return False


@router.post("/", status_code=200)
async def jwtGenerator(request: Annotated[str, Body(media_type="application/json")]):
    """The API to Ask questions."""
    try:
        send_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        logger.info("[INFO][Chat-Agent][PostJWT]receive request: %s, %s",
                    json.dumps(request), send_timestamp)
        ## jwt verify and create next new jwt for client side
        ##
        print(request['token'])
        ## 
        response = {}
        if verify(request['token']):
            token = os.getenv("SECRET_KEY")
            new_token = generate_jwt(token)
            write_secret_file({"hashed_jwt":new_token})
            response['message'] = True
            response['jwt_token'] = new_token
        else:
            response['message'] = False
            response['jwt_token'] = 'unauthorization'
        return JWTResponse(message=response["message"], jwt_token=response['jwt_token'])
    
    except HTTPException as e:
        error_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        logger.error("[INFO][Chat-Agent][PostJWT] err: %s, %s",
                     str(e), error_timestamp)
        raise HTTPException(status_code=500,
                            detail="error occurred") from e
    