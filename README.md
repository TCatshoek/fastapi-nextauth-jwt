# fastapi-nextauth-jwt

[![PyPI version](https://badge.fury.io/py/fastapi-nextauth-jwt.svg)](https://badge.fury.io/py/fastapi-nextauth-jwt)
[![PyPI Downloads](https://img.shields.io/pypi/dm/fastapi-nextauth-jwt)](https://pypi.org/project/fastapi-nextauth-jwt/)
[![License](https://img.shields.io/pypi/l/fastapi-nextauth-jwt)](https://github.com/yourusername/fastapi-nextauth-jwt/blob/main/LICENSE)
[![Contributors](https://img.shields.io/github/contributors/TCatshoek/fastapi-nextauth-jwt)](https://github.com/TCatshoek/fastapi-nextauth-jwt/graphs/contributors)

This project provides a FastAPI dependency for decrypting and validating JWTs generated by Auth.js. It is designed to facilitate the integration of a FastAPI backend with Next.js and NextAuth/Auth.js on the frontend.

> [!NOTE]
> Using Auth.js with frameworks other than Next.js may work but has not been tested

## Features

- **JWT Decryption & Validation**: Seamlessly decrypt and validate JWTs generated by Auth.js
- **CSRF Protection**: Built-in Auth.js-compatible CSRF protection with configurable HTTP methods
- **Flexible Configuration**: Extensive customization options for encryption algorithms, cookie names, and security settings
- **NextAuth.js v4 Compatibility**: Includes a compatibility layer for NextAuth.js v4 through `NextAuthJWTv4`

## Installation

```shell
pip install fastapi-nextauth-jwt
```

## Basic Usage

```python
from typing import Annotated
from fastapi import FastAPI, Depends
from fastapi_nextauth_jwt import NextAuthJWT

app = FastAPI()

JWT = NextAuthJWT(
    secret="y0uR_SuP3r_s3cr37_$3cr3t", # Leave this out to automatically read the NEXTAUTH_SECRET env var
)

@app.get("/")
async def return_jwt(jwt: Annotated[dict, Depends(JWT)]):
    return jwt
```

## Configuration Options

### Essential Settings

- **secret** (str): The secret key used for JWT operations. Should match `NEXTAUTH_SECRET` in your Next.js app. Leave this out to automatically read the `NEXTAUTH_SECRET` environment variable.
  ```python
  JWT = NextAuthJWT(secret=os.getenv("YOUR_SECRET_ENV_VAR_NAME")))
  ```

### Security Options

- **csrf_prevention_enabled** (bool): Enable CSRF protection
  - Defaults to `False` in development (`ENV=dev`), `True` otherwise

- **csrf_methods** (Set[str]): HTTP methods requiring CSRF protection
  - Default: `{'POST', 'PUT', 'PATCH', 'DELETE'}`

### Cookie Configuration

- **secure_cookie** (bool): Enable secure cookie attributes
  - Default: `True` (when `NEXTAUTH_URL` starts with https)

- **cookie_name** (str): Session token cookie name
  - Default: `"__Secure-authjs.session-token"` (when secure_cookie is True)
  - Default: `"authjs.session-token"` (when secure_cookie is False)

- **csrf_cookie_name** (str): CSRF token cookie name
  - Default: `"__Host-authjs.csrf-token"` (when secure_cookie is True)
  - Default: `"authjs.csrf-token"` (when secure_cookie is False)

> [!TIP]
> If you're using the latest version of Auth.js, here's the recommended configuration:
> ```python
> JWT = NextAuthJWT(
>     secret=os.environ["AUTHJS_SECRET"],
> )
> ```

### Advanced Options

- **encryption_algorithm** (str): JWT encryption algorithm
  - Supported: `"A256CBC-HS512"` (default), `"A256GCM"`

- **check_expiry** (bool): Enable JWT expiration validation
  - Default: `True`

## NextAuth.js v4 Compatibility

For NextAuth.js v4 applications, use the `NextAuthJWTv4` class:

```python
from fastapi_nextauth_jwt import NextAuthJWTv4

JWT = NextAuthJWTv4(
    secret=os.getenv("NEXTAUTH_SECRET")
)
```

This provides compatibility with the v4 token format and default settings

## Security Best Practices

1. **Environment Variables**: Always use environment variables for sensitive values:
   ```python
   JWT = NextAuthJWT(
       secret=os.getenv("NEXTAUTH_SECRET"),
   )
   ```

2. **HTTPS in Production**: Ensure `NEXTAUTH_URL` starts with `https://` in production to enable secure cookies

3. **CSRF Protection**: Keep CSRF protection enabled in production environments

## Examples

A [simple example](https://github.com/TCatshoek/fastapi-nextauth-jwt/tree/main/examples/simple) is available in the examples folder. It demonstrates:
- Using Next.js URL rewrites to route requests to FastAPI
- Basic JWT validation setup
- CSRF protection configuration

You can also place both the backend and frontend behind a reverse proxy like nginx, as long as the auth.js cookies reach FastAPI.

## Environment Variables

- `NEXTAUTH_SECRET`: The secret key used for JWT operations (required)
- `NEXTAUTH_URL`: The URL of your application (affects secure cookie settings)
- `ENV`: Set to `"dev"` to disable CSRF protection in development
