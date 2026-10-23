import json

import yaml


def load_session(blob: bytes):
    return json.loads(blob)


def load_config(text: str):
    return yaml.load(text, Loader=yaml.SafeLoader)


def load_config_short(text: str):
    return yaml.safe_load(text)
