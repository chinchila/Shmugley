"""Provides two instances of a filestore.

There is not intended to be any vulnerability contained within this code. This file is provided to
make it easier to test locally without needing access to an S3 bucket.

-OOO

"""
import os

import boto3
import botocore


class NotFound(Exception):
    pass


class LocalStore:
    def __init__(self):
        import tempfile
        self.upload_directory = tempfile.mkdtemp()

    def read(self, key):
        filepath = os.path.join(self.upload_directory, key)

        try:
            with open(filepath, "rb") as fp:
                return fp.read()
        except FileNotFoundError:
            raise NotFound

    def save(self, key, data):
        with open(os.path.join(self.upload_directory, key), "wb") as fp:
            fp.write(data)

