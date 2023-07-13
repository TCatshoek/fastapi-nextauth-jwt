from typing import Annotated

from fastapi import FastAPI, Depends
from fastapi_nextauth_jwt import NextAuthJWT

app = FastAPI()

JWT = NextAuthJWT(
    secret="6dDnFiDpUlKlbJciCusuFKNYmcf4WpIigldzX/Wb/FA=",
    csrf_prevention_enabled=False
)

JWTwCSRF = NextAuthJWT(
    secret="6dDnFiDpUlKlbJciCusuFKNYmcf4WpIigldzX/Wb/FA=",
    csrf_prevention_enabled=True
)


@app.get("/")
async def read_main(jwt: Annotated[dict, Depends(JWT)]):
    return jwt


@app.post("/csrf")
async def read_main(jwt: Annotated[dict, Depends(JWTwCSRF)]):
    return jwt


@app.get("/csrf")
async def read_main(jwt: Annotated[dict, Depends(JWTwCSRF)]):
    return jwt
