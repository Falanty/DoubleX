FROM python:3.9-bookworm

WORKDIR /app

RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y python3 nodejs npm vim nano curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY . .

RUN cd /app/src \
    && npm install esprima \
    && npm install escodegen \
    && npm install -g js-beautify

RUN pip install -r requirements.txt

ENTRYPOINT ["tail", "-f", "/dev/null"]