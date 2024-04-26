"""
A fastapi dependency used to decode jwt tokens generated by nextauth,
for use in nextjs/nextauth and fastapi mixed projects
"""

__version__ = "2.0.0"

from fastapi_nextauth_jwt.fastapi_nextauth_jwt import NextAuthJWT, NextAuthJWTv4
