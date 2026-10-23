import ssl

import httpx
import requests


def call_partner(url: str):
    return requests.get(url, verify=False)  # ruleid: python-tls-verify-disabled


def make_client():
    return httpx.Client(verify=False)  # ruleid: python-tls-verify-disabled


def context():
    return ssl._create_unverified_context()  # ruleid: python-tls-verify-disabled
