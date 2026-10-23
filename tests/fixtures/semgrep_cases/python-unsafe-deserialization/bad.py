import pickle

import yaml


def load_session(blob: bytes):
    return pickle.loads(blob)  # ruleid: python-unsafe-deserialization


def load_config(text: str):
    return yaml.load(text, Loader=yaml.Loader)  # ruleid: python-unsafe-deserialization
