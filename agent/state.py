"""Crash-safe state files and one writer across CGI and supervisor processes."""
import contextlib
import fcntl
import json
import os
from pathlib import Path
import tempfile
from .client import AgentError


class Store:
    def __init__(self, root):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.root, 0o700)

    def read(self, name, default=None):
        try:
            return json.loads((self.root / name).read_text())
        except FileNotFoundError:
            return default
        except (ValueError, OSError):
            raise AgentError('Persistent state is unreadable: ' + name) from None

    def write(self, name, value):
        fd, tmp = tempfile.mkstemp(prefix='.write-', dir=self.root)
        try:
            with os.fdopen(fd, 'w') as out:
                json.dump(value, out, ensure_ascii=False)
                out.flush(); os.fsync(out.fileno())
            os.replace(tmp, self.root / name)
            directory = os.open(self.root, os.O_RDONLY)
            try: os.fsync(directory)
            finally: os.close(directory)
        finally:
            if os.path.exists(tmp): os.unlink(tmp)

    @contextlib.contextmanager
    def lock(self):
        with (self.root / 'writer.lock').open('a') as lock:
            os.chmod(self.root / 'writer.lock', 0o600)
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise AgentError('Another operation is running') from None
            try: yield
            finally: fcntl.flock(lock, fcntl.LOCK_UN)
