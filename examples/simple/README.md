# Simple Example

This example shows off a very basic setup using Next.js, NextAuth, 
and a FastAPI backend.

It uses [Next.js url rewriting](https://nextjs.org/docs/pages/api-reference/next-config-js/rewrites)
to direct requests starting with `/fastapi` to the FastAPI backend.

## Setup

### With docker compose:
```shell
docker-compose up
```

### Without docker:

#### FastAPI
```shell
cd fastapi
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload
```

#### Next.js
```shell
cd nextjs
npm install
npm run dev
```

## Usage
Open the Next.js page in your browser. It should prompt you to log in.
It is set up in such a way that it accepts any credentials, so no need
to create an account first.

Then, click the blue button and see the response from FastAPI!