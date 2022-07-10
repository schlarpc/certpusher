import json
import time
import requests
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    NoEncryption,
)


def main(config, cacerts, cert, key):
    session = requests.Session()
    session.hooks = {"response": lambda r, *args, **kwargs: r.raise_for_status()}
    session.headers.update(
        {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {config['apiKey']}",
        }
    )

    response = session.post(
        f"https://{config['host']}/api/v2.0/certificate",
        json={
            "create_type": "CERTIFICATE_CREATE_IMPORTED",
            "name": f"{config['certificatePrefix']}-{cert.serial_number}",
            "certificate": b"\n".join(
                [cert.public_bytes(encoding=Encoding.PEM)]
                + [cacert.public_bytes(encoding=Encoding.PEM) for cacert in cacerts]
            ).decode("utf-8"),
            "privatekey": key.private_bytes(
                encoding=Encoding.PEM,
                format=PrivateFormat.PKCS8,
                encryption_algorithm=NoEncryption(),
            ).decode("utf-8"),
        },
        verify=False,
    )
    time.sleep(5)

    response = session.get(
        f"https://{config['host']}/api/v2.0/certificate",
        params={"limit": 0},
        verify=False,
    )
    all_certificates = response.json()
    for stored_certificate in all_certificates:
        if stored_certificate["name"] == f"{config['certificatePrefix']}-{cert.serial_number}":
            break
    else:
        raise Exception("Certificate not found")

    session.put(
        f"https://{config['host']}/api/v2.0/system/general",
        json={"ui_certificate": stored_certificate["id"]},
        verify=False,
    )

    for check_certificate in all_certificates:
        if (
            check_certificate["name"].startswith(f"{config['certificatePrefix']}-")
            and check_certificate["id"] != stored_certificate["id"]
        ):
            session.delete(
                f"https://{config['host']}/api/v2.0/certificate/id/{check_certificate['id']}",
                verify=False,
            )

    session.post(
        f"https://{config['host']}/api/v2.0/system/general/ui_restart",
        verify=False,
    )
