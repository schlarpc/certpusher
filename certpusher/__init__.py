import argparse
import importlib
import json
import pathlib
import pkgutil

from . import modules

from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("config", type=pathlib.Path)
    parser.add_argument("cacerts", type=pathlib.Path)
    parser.add_argument("cert", type=pathlib.Path)
    parser.add_argument("key", type=pathlib.Path)
    return parser.parse_args()


def main():
    args = get_args()
    with args.config.open("r") as f:
        configs = json.load(f)
    with args.key.open("rb") as f:
        key = load_pem_private_key(f.read(), password=None)
    if not isinstance(key, RSAPrivateKey):
        raise Exception("Key must be RSA")  # esxi and unifi_cloudkey require this
    with args.cert.open("rb") as f:
        cert = load_pem_x509_certificate(f.read())
    with args.cacerts.open("rb") as f:
        cacerts = [load_pem_x509_certificate(cert) for cert in f.read().split(b"\n\n")]

    for config in configs:
        print("Running", config['module'])
        module = importlib.import_module(
            f".modules.{config['module']}", package=__package__
        )
        module.main(config=config, cacerts=cacerts, cert=cert, key=key)
