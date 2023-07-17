from typing import Annotated
from fastapi import FastAPI, Depends
from fastapi_nextauth_jwt import NextAuthJWT

app = FastAPI()

JWT = NextAuthJWT(
    secret="y0uR_SuP3r_s3cr37_$3cr3t",
)


@app.get("/")
async def return_jwt(jwt: Annotated[dict, Depends(JWT)]):
    return {"message": f"Hi {jwt['name']}. Greetings from fastapi!"}

# For CSRF protection testing
@app.post("/")
async def return_jwt(jwt: Annotated[dict, Depends(JWT)]):
    return {"message": f"Hi {jwt['name']}. Greetings from fastapi!"}