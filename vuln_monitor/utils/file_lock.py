import fcntl
import os
from pathlib import Path
from contextlib import contextmanager

from loguru import logger


@contextmanager
def file_lock(lock_path: str = None, timeout: float = 30.0):
    if lock_path is None:
        lock_path = str(Path(__file__).parent.parent.parent / "data" / ".vulnmonitor.lock")

    lock_dir = os.path.dirname(lock_path)
    if lock_dir:
        os.makedirs(lock_dir, exist_ok=True)

    lock_fd = open(lock_path, "w")
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        logger.debug(f"Acquired file lock: {lock_path}")
        yield
    except (IOError, OSError):
        logger.warning(f"Could not acquire file lock: {lock_path}, another instance may be running")
        raise
    finally:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
            lock_fd.close()
        except Exception:
            pass
