from fastapi import FastAPI
import json

app = FastAPI()


@app.get("/sslcheck/")
async def sslcheck():
    with open("cert.json",mode="r+") as cert:
        json_content = cert.read()
    content = json.loads(json_content)
    return content