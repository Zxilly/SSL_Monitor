from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import json

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/sslcheck/")
async def sslcheck():
    with open("cert.json",mode="r+") as cert:
        json_content = cert.read()
    content = json.loads(json_content)
    return content