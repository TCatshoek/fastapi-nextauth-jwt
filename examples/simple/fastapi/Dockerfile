FROM python:3.11
WORKDIR /code
COPY examples/simple/fastapi/requirements.txt /code/requirements.txt
RUN pip install --no-cache-dir --upgrade -r /code/requirements.txt
COPY . /fastapi-nextauth-jwt
RUN pip install --no-cache-dir /fastapi-nextauth-jwt
COPY . /code

CMD ["uvicorn", "main:app", "--reload"]
