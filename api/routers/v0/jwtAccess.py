"post question"
from pydantic.typing import Annotated
from pydantic import BaseModel, Field
from fastapi import APIRouter, Body, HTTPException
from datetime import datetime
from ...logger import logger
# from dotenv import load_dotenv
from datetime import datetime, timezone, timedelta
from cryptography.fernet import Fernet
import hashlib
import httpx
import jwt
import os
import json

# _CORE_SERVICE_URL = "http://core-service:8080"

router = APIRouter(prefix="/jwt")

class JWTResponse(BaseModel):
    message: bool = Field(examples=[True]),
    jwt_token: str = Field(examples=["jwt_token"])

class JWTrequest(BaseModel):
    token: str = Field(examples=["jwt_token"])
# async def forward(message):
#     post_url = f"{_CORE_SERVICE_URL}/api/v0/question"
#     try:
#         async with httpx.AsyncClient() as client:
#             response = await client.post(
#                 post_url,
#                 headers={
#                     "X-Customer-ID": "1",
#                     "X-API-Key": "4X0YYzC2pnsw7N5jUrNorxJQHNeu-Tmd-hHJ7QTasXg"
#                 },
#                 json={"question": message},
#                 follow_redirects=True,
#                 timeout=100
#             )
#             response.raise_for_status()  # 檢查 HTTP 狀態碼，非 2xx 將引發 HTTPStatusError
#             return response.json()
#     except httpx.HTTPStatusError as e:
#         logger.error("HTTP error occurred: %s - %s",
#                      e.response.status_code, e.response.text)
#         raise HTTPException(status_code=e.response.status_code,
#                             detail=e.response.text) from e
#     except httpx.RequestError as e:
#         logger.error("Request error occurred: %s", str(e))
#         raise HTTPException(status_code=500,
#                             detail="Unable to connect to the service") from e
#     except Exception as e:
#         logger.error("Unexpected error occurred: %s", str(e))
#         raise HTTPException(status_code=500,
#                             detail="An unexpected error occurred") from e
## randomly generate jwt token
def generate_jwt(secret_key, algorithm="HS256", expiry_minutes=30):
    # Add the expiration time to the payload
    payload = {"user_id": 0,"username": "IEEE"}
    payload['exp'] = datetime.now(timezone.utc) + timedelta(minutes=expiry_minutes)
    token = jwt.encode(payload, secret_key, algorithm=algorithm) 
    return token


###########################################
def generate_and_save_key(): ## key to encrypt the hashed jwttoken file
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(key)

def encrypt_file(file_name):
    with open("secret.key", "rb") as key_file:
        key = key_file.read()

    cipher_suite = Fernet(key)

    with open(file_name, "rb") as file:
        file_data = file.read()

    encrypted_data = cipher_suite.encrypt(file_data)

    with open("encrypted_" + file_name, "wb") as encrypted_file:
        encrypted_file.write(encrypted_data)



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

    return decrypted_file_name

def load_secret_file(file_path):
    secret_vars = {}
    with open(file_path, 'r') as file:
        for line in file:
            if line.strip() and not line.startswith('#'):
                key, value = line.strip().split('=', 1)
                secret_vars[key] = value
    return secret_vars['hashed_jwt']

def write_secret_file(env_vars):
    generate_and_save_key()
    with open('./secret.txt', 'w') as file:
        for key, value in env_vars.items():
            file.write(f"{key}={value}\n")
    encrypt_file("secret.txt")
def string_to_hex(s):
    hex_string = ''.join(format(ord(c), '02x') for c in s)
    return hex_string
def verify( jwt_token:str ):
    decrypted_file_name = decrypt_file("encrypted_secret.txt")
    secrets = load_secret_file(decrypted_file_name)
    print(secrets)
    salt = secrets[:16].encode()  # Adjust based on how the salt and stored hash are stored
    stored_hash = secrets[:].encode()  # Adjust based on how the salt and stored hash are stored

    # Create a new hash with the salt and jwt_token
    hash_object = hashlib.sha256( jwt_token.encode())
    new_hash = hash_object.digest()
    # hashed_jwt_bytes = bytes.fromhex( secrets )
    # salt = hashed_jwt_bytes[:16]
    # stored_hash = hashed_jwt_bytes[16:]
    # hash_object = hashlib.sha256(salt + jwt_token.encode())
    # new_hash = hash_object.digest()
    print(f"new: {jwt_token.encode()}")
    print(f"stored: {stored_hash}")
    if jwt_token.encode() == stored_hash:
        return True
    else:
        return False
    
def encrypt_secret_file(file):
    key = Fernet.generate_key()
    with open("magic_word.txt", "wb") as key_file:
        key_file.write(key)
    cipher_suite = Fernet(key)
    encrypted_data = cipher_suite.encrypt(file)
    with open("secrets.txt", "wb") as encrypted_file:
        encrypted_file.write(encrypted_data)

def decrypt_secret_file():
    with open("magic_word.txt", "rb") as key_file:
        key = key_file.read()
    cipher_suite = Fernet(key)
    with open("secrets.txt", "rb") as encrypted_file:
        encrypted_data = encrypted_file.read()
    decrypted_data = cipher_suite.decrypt(encrypted_data) # real hashed jwttoken
    return decrypted_data

@router.get("/", status_code=200)
async def jwtGenerator():
    """The API to generate jwt token initially."""
    # token = os.getenv("SECRET_KEY")
    token = "seed_key_for_chat_agent_of_intelligentQA"
    # print(f"token: {token}")
    new_token = generate_jwt(token)
    print(f"token: {new_token}")
    write_secret_file({"hashed_jwt":new_token})
    return {"status": "success"}

@router.post("/", status_code=200)
async def jwtGenerator(request: Annotated[JWTrequest, Body(media_type="application/json")]):
    """The API to Ask questions."""
    try:
        send_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        
        logger.info("[INFO][Chat-Agent][PostJWT]receive request: %s, %s",
                    json.dumps(request.dict()), send_timestamp)
        ## jwt verify and create next new jwt for client side
        ##
        #print(request.dict()['token'])
        ## 
        response = {}
        if verify(request.dict()['token']):
            token = "seed_key_for_chat_agent_of_intelligentQA"
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
    