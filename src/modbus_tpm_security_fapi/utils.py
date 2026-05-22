import subprocess

def get_host_ip():
    out = subprocess.check_output("ip -4 addr", shell=True).decode()
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("inet ") and not line.startswith("inet 127."):
            return line.split()[1].split("/")[0]