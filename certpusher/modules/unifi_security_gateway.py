import paramiko
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    NoEncryption,
)
from ..common import temporary_path, add_host_key, ssh_exec


def main(config, cacerts, cert, key):
    with temporary_path() as temp_path:
        with (temp_path / "server.pem").open("wb") as f:
            f.write(
                key.private_bytes(
                    encoding=Encoding.PEM,
                    format=PrivateFormat.PKCS8,
                    encryption_algorithm=NoEncryption(),
                )
            )
            f.write(cert.public_bytes(encoding=Encoding.PEM))
            # TODO fix this somehow, lighttpd needs a separate ssl.ca-file path
            # for cacert in cacerts:
            # f.write(
            # cacert.public_bytes(encoding=Encoding.PEM)
            # )

        ssh = paramiko.SSHClient()
        add_host_key(ssh, f"{config['host']} {config['hostKey']}")
        ssh.connect(
            config["host"], username=config["username"], password=config["password"],
        )
        sftp = ssh.open_sftp()

        sftp.put(temp_path / "server.pem", "/tmp/server.pem.new")
        ssh_exec(
            ssh, ["sudo", "mv", "/tmp/server.pem.new", "/etc/lighttpd/server.pem.new"]
        )
        ssh_exec(ssh, ["sudo", "chown", "root:root", "/etc/lighttpd/server.pem.new"])
        ssh_exec(ssh, ["sudo", "chmod", "400", "/etc/lighttpd/server.pem.new"])
        ssh_exec(
            ssh,
            ["sudo", "mv", "/etc/lighttpd/server.pem.new", "/etc/lighttpd/server.pem"],
        )
        ssh_exec(
            ssh,
            [
                "sudo",
                "start-stop-daemon",
                "--stop",
                "--oknodo",
                "--pidfile",
                "/var/run/lighttpd.pid",
                "--exec",
                "/usr/sbin/lighttpd",
            ],
        )
        ssh_exec(ssh, ["sudo", "lighttpd", "-f", "/etc/lighttpd/lighttpd.conf"])


if __name__ == "__main__":
    main()
