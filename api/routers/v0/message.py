"post question"
from fastapi.security import OAuth2PasswordBearer
from pydantic.typing import Annotated
from pydantic import BaseModel, Field
from fastapi import APIRouter, Body, HTTPException, Depends
from datetime import datetime
from ...logger import logger
from cryptography.fernet import Fernet
import httpx
import jwt
import json


_CORE_SERVICE_URL = "http://core-service:8080"
router = APIRouter(prefix="/message")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

class QuestionResponse(BaseModel):
    answer: str = Field(examples=["我不是機器人"])

class BotRequest(BaseModel):
    token: str = Field(examples=["jwt_token"]),
    message: str = Field(examples=["請問IEEE是甚麼"])

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
#### token verify
def decrypt_file(encrypted_file_name):
    with open("secret.key", "rb") as key_file:
        key = key_file.read()

    cipher_suite = Fernet(key)

    with open(encrypted_file_name, "rb") as encrypted_file:
        encrypted_data = encrypted_file.read()

    decrypted_data = cipher_suite.decrypt(encrypted_data)

    decrypted_file_name = "decrypted_" + encrypted_file_name
    with open(decrypted_file_name, "wb") as decrypted_file:
        decrypted_file.write(decrypted_data)

def load_secret_file(file_path):
    secret_vars = {}
    with open(file_path, 'r') as file:
        for line in file:
            if line.strip() and not line.startswith('#'):
                key, value = line.strip().split('=', 1)
                secret_vars[key] = value
    return secret_vars['hashed_jwt']

def verify_token(jwt_token:str):
    decrypted_file_name = decrypt_file("encrypted_secret.txt")
    secrets = load_secret_file(decrypted_file_name)
    print(secrets)
    stored_hash = secrets[:].encode()  # Adjust based on how the salt and stored hash are stored
    print(f"new: {jwt_token.encode()}")
    print(f"stored: {stored_hash}")
    if jwt_token.encode() == stored_hash:
        return True
    else:
        return False

@router.post("/", status_code=200)
async def question(request: Annotated[BotRequest, Body(media_type="application/json")]):
    """The API to Ask questions."""
    try:
        send_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        logger.info("[INFO][WEB-SERVICE][PostQuestion]receive question: %s, %s",
                    json.dumps(request.dict()), send_timestamp)
        if verify_token(request.dict()['token']):
            print(f"post message success")
            response = await forward(request.dict()['message'])
        else:
            print(f"invalid post message")
            response = {'answer': 'wrong authentication'}
            
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
    