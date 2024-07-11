"main api entry"
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .routers import router

api = FastAPI(
    title="Chat Agent",
    version="0.1.0",
    summary="store api and keeping jwt token access control"
) ## server on port80


origins = [ 
    "http://127.0.0.1:5500",
    "http://localhost",
    "https://pc211.ee.ntu.edu.tw",
    "https://pc201.ee.ntu.edu.tw",
    "http://127.0.0.1:5500/",
] ## tmp website 
api.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

api.include_router(router)

@api.get("/heartbeat")
async def heartbeat():
    return {"status": "running"}

