import tempfile
import pathlib
import shlex
import paramiko
import contextlib


def ssh_exec(connection, args, check=True):
    stdin, stdout, stderr = connection.exec_command(shlex.join(args))
    stdout.channel.set_combine_stderr(True)
    output = stdout.readlines()
    return_code = stdout.channel.recv_exit_status()
    if check and return_code != 0:
        raise ValueError(f"Return code == {return_code}")
    return return_code, output


@contextlib.contextmanager
def temporary_path(*args, **kwargs):
    with tempfile.TemporaryDirectory() as tempdir:
        yield pathlib.Path(tempdir)


def add_host_key(ssh, line):
    host_keys = ssh.get_host_keys()
    # TODO make temp file and use host_keys.load(filename)
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
