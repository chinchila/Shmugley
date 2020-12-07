#!/usr/bin/env python3
import argparse
import os
import sys
import time
import traceback
import uuid

import requests

SECRET = b"Hi friend, did you steal the cookie?"
SLEEP_TIME = float(os.getenv("SLEEP_TIME", 2))
URL = "http://127.0.0.1:8080/files/"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--daemon", action="store_true")
    arguments = parser.parse_args()
    run_loop()


def put_file():
    response = requests.post(
        URL,
        data=SECRET,
        headers={
            "Content-Type": "text/plain",
            "User-Agent": "client",
            "Cookie":"stolen=true",
            "X-guid": str(uuid.uuid4()),
        },
        timeout=1,
    )
    if response.status_code == 201:
        sys.stdout.write(".")
        sys.stdout.flush()
    else:
        print()
        print(response)


def run_loop():
    while True:
        try:
            put_file()
        except Exception:
            traceback.print_exc()
        time.sleep(SLEEP_TIME)


if __name__ == "__main__":
    sys.exit(main())
