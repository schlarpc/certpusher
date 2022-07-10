import paramiko
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    NoEncryption,
)
from ..common import temporary_path, add_host_key, ssh_exec


def main(config, cacerts, cert, key):
    with temporary_path() as temp_path:
        with (temp_path / "rui.key").open("wb") as f:
            f.write(
                key.private_bytes(
                    encoding=Encoding.PEM,
                    format=PrivateFormat.PKCS8,
                    encryption_algorithm=NoEncryption(),
                )
            )
        with (temp_path / "rui.crt").open("wb") as f:
            f.write(cert.public_bytes(encoding=Encoding.PEM))
        # TODO this required some manual fuckery with an XML config
        with (temp_path / "castore.pem").open("wb") as f:
            for cacert in cacerts:
                f.write(cacert.public_bytes(encoding=Encoding.PEM))

        ssh = paramiko.SSHClient()
        add_host_key(
            ssh,
            f"{config['host']} {config['hostKey']}",
        )
        ssh.connect(
            config['host'], username=config['username'], password=config['password']
        )
        sftp = ssh.open_sftp()

        sftp.put(temp_path / "rui.key", "/etc/vmware/ssl/rui.key")
        sftp.put(temp_path / "rui.crt", "/etc/vmware/ssl/rui.crt")
        sftp.put(temp_path / "castore.pem", "/etc/vmware/ssl/castore.pem")
        sftp.chmod("/etc/vmware/ssl/rui.key", 0o400)
        ssh_exec(ssh, ["/etc/init.d/hostd", "restart"])
        ssh_exec(ssh, ["/etc/init.d/rhttpproxy", "restart"])


if __name__ == "__main__":
    main()
