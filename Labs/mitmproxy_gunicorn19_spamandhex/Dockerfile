FROM ubuntu:18.04

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl python3-pip python3-wheel python3-dev libffi-dev libssl-dev \
    && pip3 install -U pip setuptools \
    && pip install flask gunicorn[gevent]==20.0.4 requests

RUN pip3 install --upgrade pip && \
	pip3 --no-cache-dir install mitmproxy flask_autoindex && \
    mkdir /app/

COPY filter.py run.sh flag /app/
WORKDIR app
RUN chmod +x run.sh
