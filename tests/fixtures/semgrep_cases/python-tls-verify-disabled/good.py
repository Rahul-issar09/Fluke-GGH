import ssl

import httpx
import requests


def call_partner(url: str):
    return requests.get(url, timeout=5)


def make_client():
    return httpx.Client(verify="/etc/ssl/certs/ca.pem")


def context():
    return ssl.create_default_context()
