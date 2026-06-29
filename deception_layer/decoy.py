"""
deception_layer/decoy.py

Generates a convincing decoy evidence store.

The decoy is placed in an obvious location that an attacker
would expect to find the real forensic record. It is
structurally identical to real preserved evidence but
contains only plausible non-sensitive content.

The goal is to misdirect the attacker into destroying
the decoy while the real evidence remains hidden in
the stego-image.
"""

import logging
import os
import random
from datetime import datetime, timedelta

logger = logging.getLogger("eps.deception.decoy")


class DecoyGenerator:
    """
    Generates a fake evidence store that mimics the structure
    of real preserved evidence.

    Parameters
    ----------
    decoy_dir : str
        Root directory where the decoy store is deployed.
    """

    def __init__(self, decoy_dir: str):
        self.decoy_dir = decoy_dir

    def generate(self, session_id: str) -> str:
        """
        Generate and deploy a complete decoy evidence store.

        Creates:
        - Fake process list
        - Fake network connections
        - Fake user list
        - Fake bash history
        - Fake log files
        - Fake .enc and .hash files to look like real evidence

        Returns path to the deployed decoy directory.
        """
        decoy_session_dir = os.path.join(self.decoy_dir, f"evidence_backup_{session_id}")
        os.makedirs(decoy_session_dir, exist_ok=True)

        self._generate_fake_processes(decoy_session_dir)
        self._generate_fake_network(decoy_session_dir)
        self._generate_fake_users(decoy_session_dir)
        self._generate_fake_bash_history(decoy_session_dir)
        self._generate_fake_logs(decoy_session_dir)
        self._generate_fake_encrypted_archive(decoy_session_dir, session_id)

        logger.info("Decoy evidence store deployed → %s", decoy_session_dir)
        return decoy_session_dir

    # ── Fake artifact generators ─────────────────────────────────────────

    def _generate_fake_processes(self, decoy_dir: str) -> None:
        """Generate a realistic-looking but fake process list."""
        path = os.path.join(decoy_dir, "processes.txt")
        fake_processes = [
            "root           1  0.0  0.0 168928 11456 ?    Ss   08:01   0:03 /sbin/init",
            "root           2  0.0  0.0      0     0 ?    S    08:01   0:00 [kthreadd]",
            "root         445  0.0  0.1  47512  8204 ?    Ss   08:01   0:00 /usr/sbin/sshd",
            "root         512  0.0  0.0  14856  1832 ?    Ss   08:01   0:00 /usr/sbin/cron",
            "syslog       521  0.0  0.1 224748  4312 ?    Ssl  08:01   0:00 /usr/sbin/rsyslogd",
            "root         891  0.0  0.0  72296  3204 ?    Ss   08:01   0:00 /usr/lib/openssh/sftp-server",
        ]
        with open(path, "w") as f:
            f.write(f"PROCESS SNAPSHOT\nCaptured: {datetime.now()}\n")
            f.write("=" * 60 + "\n")
            f.write("USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n")
            for proc in fake_processes:
                f.write(proc + "\n")

    def _generate_fake_network(self, decoy_dir: str) -> None:
        """Generate a realistic-looking but fake network connection list."""
        path = os.path.join(decoy_dir, "network.txt")
        with open(path, "w") as f:
            f.write(f"NETWORK CONNECTIONS\nCaptured: {datetime.now()}\n")
            f.write("=" * 60 + "\n")
            f.write("Netid  State   Recv-Q  Send-Q  Local Address:Port  Peer Address:Port\n")
            f.write("tcp    LISTEN  0       128     0.0.0.0:22           0.0.0.0:*\n")
            f.write("tcp    LISTEN  0       128     127.0.0.1:631        0.0.0.0:*\n")

    def _generate_fake_users(self, decoy_dir: str) -> None:
        """Generate a fake logged-in users file."""
        path = os.path.join(decoy_dir, "users.txt")
        with open(path, "w") as f:
            f.write(f"LOGGED IN USERS\nCaptured: {datetime.now()}\n")
            f.write("=" * 60 + "\n")
            f.write(f"root     pts/0        {datetime.now().strftime('%Y-%m-%d %H:%M')} (192.168.56.1)\n")

    def _generate_fake_bash_history(self, decoy_dir: str) -> None:
        """Generate a fake bash history."""
        path = os.path.join(decoy_dir, "bash_history.txt")
        fake_commands = [
            "ls -la /var/log",
            "cat /var/log/syslog",
            "ps aux",
            "netstat -tulnp",
            "who",
            "last",
            "df -h",
            "free -m",
            "uname -a",
            "id",
        ]
        with open(path, "w") as f:
            for cmd in fake_commands:
                f.write(cmd + "\n")

    def _generate_fake_logs(self, decoy_dir: str) -> None:
        """Generate fake log files that look like real syslog entries."""
        log_dir = os.path.join(decoy_dir, "var_log")
        os.makedirs(log_dir, exist_ok=True)

        # Fake syslog
        syslog_path = os.path.join(log_dir, "syslog")
        base_time = datetime.now() - timedelta(hours=2)
        with open(syslog_path, "w") as f:
            for i in range(20):
                entry_time = base_time + timedelta(minutes=i * 5)
                f.write(
                    f"{entry_time.strftime('%b %d %H:%M:%S')} ubuntu systemd[1]: "
                    f"Started Session {random.randint(1, 99)} of user root.\n"
                )

        # Fake auth.log
        auth_path = os.path.join(log_dir, "auth.log")
        with open(auth_path, "w") as f:
            for i in range(10):
                entry_time = base_time + timedelta(minutes=i * 10)
                f.write(
                    f"{entry_time.strftime('%b %d %H:%M:%S')} ubuntu sshd[{random.randint(1000,9999)}]: "
                    f"Accepted publickey for root from 192.168.56.1 port {random.randint(40000,60000)}\n"
                )

    def _generate_fake_encrypted_archive(self, decoy_dir: str, session_id: str) -> None:
        """
        Generate a fake .enc and .hash file that looks like
        real preserved evidence. Contains random bytes.
        """
        import os
        # Fake encrypted archive - random bytes
        fake_enc_path = os.path.join(decoy_dir, f"session_{session_id}.enc")
        with open(fake_enc_path, "wb") as f:
            f.write(os.urandom(4096))

        # Fake hash file
        import hashlib
        fake_hash = hashlib.sha256(os.urandom(32)).hexdigest()
        fake_hash_path = os.path.join(decoy_dir, f"session_{session_id}.hash")
        with open(fake_hash_path, "w") as f:
            f.write(f"{fake_hash}  session_{session_id}.enc\n")

        logger.info("Fake encrypted archive and hash deployed")