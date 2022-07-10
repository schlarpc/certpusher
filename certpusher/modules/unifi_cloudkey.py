import paramiko
import tarfile
import pathlib
from cryptography.hazmat.primitives.serialization.pkcs12 import (
    serialize_key_and_certificates,
)
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption,
    Encoding,
    PrivateFormat,
    NoEncryption,
)
from ..common import temporary_path, ssh_exec


def main(config, cacerts, cert, key):
    with temporary_path() as temp_path:
        with (temp_path / "unifi.keystore.jks").open("wb") as f:
            f.write(
                serialize_key_and_certificates(
                    name=b"unifi",
                    key=key,
                    cert=cert,
                    cas=cacerts,
                    encryption_algorithm=BestAvailableEncryption(
                        password=b"aircontrolenterprise",
                    ),
                )
            )

        with (temp_path / "cloudkey.key").open("wb") as f:
            f.write(
                key.private_bytes(
                    encoding=Encoding.PEM,
                    format=PrivateFormat.PKCS8,
                    encryption_algorithm=NoEncryption(),
                )
            )

        with (temp_path / "cloudkey.crt").open("wb") as f:
            f.write(cert.public_bytes(encoding=Encoding.PEM))
            for cacert in cacerts:
                f.write(cacert.public_bytes(encoding=Encoding.PEM))

        tar_contents = list(temp_path.iterdir())
        with (temp_path / "cert.tar").open("wb") as f:
            with tarfile.open(fileobj=f, mode="w") as tf:
                for tar_content in tar_contents:
                    tarinfo = tarfile.TarInfo(name=tar_content.name)
                    tarinfo.size = tar_content.stat().st_size
                    tarinfo.uname = tarinfo.gname = "0"
                    with tar_content.open("rb") as tcf:
                        tf.addfile(tarinfo, fileobj=tcf)

        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(
            config["host"],
            username=config["username"],
            password=config["password"],
        )
        sftp = ssh.open_sftp()

        destination_path = pathlib.PurePosixPath("/etc/ssl/private")
        for source in temp_path.iterdir():
            sftp.put(source, str(destination_path / (source.name + ".new")))
        ssh_exec(
            ssh,
            [
                "chown",
                "unifi:ssl-cert",
                str(destination_path / "unifi.keystore.jks.new"),
            ],
        )
        for source in temp_path.iterdir():
            sftp.posix_rename(
                str(destination_path / (source.name + ".new")),
                str(destination_path / source.name),
            )
        ssh_exec(ssh, ["/etc/init.d/nginx", "restart"])
        ssh_exec(ssh, ["/etc/init.d/unifi", "restart"])


if __name__ == "__main__":
    main()
