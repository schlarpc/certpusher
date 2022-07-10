import requests
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    NoEncryption,
)


def main(config, cacerts, cert, key):
    session = requests.Session()
    response = session.post(
        f"https://{config['host']}/api/session",
        {"username": config['username'], "password": config['password']},
        verify=False,
    )
    session.headers["X-CSRFTOKEN"] = response.json()["CSRFToken"]
    response = session.post(
        f"https://{config['host']}/api/settings/ssl/certificate",
        files={
            "new_certificate": (
                "certificate.pem",
                cert.public_bytes(encoding=Encoding.PEM),
            ),
            "new_private_key": (
                "key.pem",
                key.private_bytes(
                    encoding=Encoding.PEM,
                    format=PrivateFormat.PKCS8,
                    encryption_algorithm=NoEncryption(),
                ),
            ),
            "new_ca_certificate": (
                "cacert.pem",
                b"".join(
                    cacert.public_bytes(encoding=Encoding.PEM) for cacert in cacerts
                ),
            ),
        },
        verify=False,
    )
    print(response.text)


if __name__ == "__main__":
    main()
