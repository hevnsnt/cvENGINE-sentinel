"""The result spool: finished results a Sentinel holds on disk until cvENGINE can take them.

A task that ends while cvENGINE is unreachable (an update, a restart, a network fault) must not lose its work. The result is written here
first (one file per task, 0600, synced and renamed into place so a crash leaves the old state or the new one, never half a file) and the
daemon delivers the entries oldest first with a capped backoff, deleting each once the server has answered. Nothing here is ever logged but
counts and task ids: a result body can hold anything a scan found.

Bounds: an entry older than the window (``CVENGINE_SENTINEL_SPOOL_HOURS``, default 6) is no longer offered to the server (its lease is long
gone) but stays on disk under ``expired/`` for an operator, and the whole directory is held under ``CVENGINE_SENTINEL_SPOOL_MAX_MB``
(default 256): when a new result does not fit, the oldest expired entries go first, and a result that still does not fit is refused (the
caller releases the task, the old behaviour) instead of filling the disk.
"""
import json
import logging
import os
import re
import tempfile
import time

from . import config

logger = logging.getLogger('sentinel.spool')

DEFAULT_WINDOW_HOURS = 6.0
DEFAULT_MAX_MB = 256
EXPIRED_DIR = 'expired'
_SAFE_ID = re.compile(r'[A-Za-z0-9_-]{1,64}')


def window_seconds():
    """How long a held result is offered to the server, in seconds (``CVENGINE_SENTINEL_SPOOL_HOURS``). 0 turns the spool off."""
    raw = os.environ.get('CVENGINE_SENTINEL_SPOOL_HOURS')
    try:
        hours = float(raw) if raw not in (None, '') else DEFAULT_WINDOW_HOURS
    except ValueError:
        hours = DEFAULT_WINDOW_HOURS
    if hours != hours or hours < 0:  # NaN or negative
        hours = DEFAULT_WINDOW_HOURS
    return min(hours, 24 * 30) * 3600.0


def max_bytes():
    raw = os.environ.get('CVENGINE_SENTINEL_SPOOL_MAX_MB')
    try:
        mb = float(raw) if raw not in (None, '') else DEFAULT_MAX_MB
    except ValueError:
        mb = DEFAULT_MAX_MB
    if mb != mb or mb <= 0:
        mb = DEFAULT_MAX_MB
    return int(mb * 1024 * 1024)


def default_dir():
    """``CVENGINE_SENTINEL_SPOOL_DIR``, else ``spool`` next to the token file (the state volume, which survives a container restart)."""
    explicit = os.environ.get('CVENGINE_SENTINEL_SPOOL_DIR')
    if explicit:
        return explicit
    return os.path.join(os.path.dirname(config.token_path()) or '.', 'spool')


def _fsync_dir(directory):
    try:
        fd = os.open(directory, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


class Spool:
    def __init__(self, directory=None):
        self._directory = directory

    @property
    def directory(self):
        return self._directory or default_dir()

    @staticmethod
    def _name(task_id):
        task_id = str(task_id)
        if not _SAFE_ID.fullmatch(task_id):
            raise ValueError('not a task id')
        return f'{task_id}.json'

    def enabled(self):
        return window_seconds() > 0

    # --- reading ------------------------------------------------------------------------------------------------

    def _live_files(self):
        """(mtime_ns, name, size) of every held entry, oldest first."""
        out = []
        try:
            with os.scandir(self.directory) as it:
                for entry in it:
                    if entry.is_file(follow_symlinks=False) and entry.name.endswith('.json') and _SAFE_ID.fullmatch(entry.name[:-5]):
                        st = entry.stat(follow_symlinks=False)
                        out.append((st.st_mtime_ns, entry.name, st.st_size))
        except FileNotFoundError:
            return []
        except OSError as exc:
            logger.warning('the spool directory could not be read: %s', exc)
            return []
        return sorted(out)

    def count(self):
        return len(self._live_files())

    def task_ids(self):
        return [name[:-5] for _m, name, _s in self._live_files()]

    def oldest_age(self, now=None):
        files = self._live_files()
        if not files:
            return None
        return max(0.0, (now if now is not None else time.time()) - files[0][0] / 1e9)

    def entries(self):
        """``(task_id, age_seconds)`` of every held entry, oldest first."""
        now = time.time()
        return [(name[:-5], max(0.0, now - mtime / 1e9)) for mtime, name, _s in self._live_files()]

    def load(self, task_id):
        """The result held for ``task_id``, or ``None`` when it is gone or unreadable (an unreadable file is moved aside, never retried forever)."""
        path = os.path.join(self.directory, self._name(task_id))
        try:
            with open(path, encoding='utf-8') as handle:
                data = json.load(handle)
        except FileNotFoundError:
            return None
        except (OSError, ValueError):
            logger.error('the spooled result for task %s could not be read; moving it aside', task_id)
            self._move_expired(task_id)
            return None
        result = data.get('result') if isinstance(data, dict) else None
        if not isinstance(result, dict):
            self._move_expired(task_id)
            return None
        return result

    # --- writing ------------------------------------------------------------------------------------------------

    def add(self, task_id, result):
        """Hold ``result`` for ``task_id``. Returns True when it is safely on disk, False when it could not be kept (spool off, over its size
        bound, or the disk refused): the caller then falls back to releasing the task. A second add for the same task keeps the first."""
        if not self.enabled():
            return False
        try:
            name = self._name(task_id)
            payload = json.dumps({'v': 1, 'task_id': str(task_id), 'spooled_at': time.time(), 'result': result}, separators=(',', ':')).encode('utf-8')
        except (TypeError, ValueError):
            return False
        directory = self.directory
        try:
            os.makedirs(directory, mode=0o700, exist_ok=True)
            if os.path.exists(os.path.join(directory, name)):
                return True
            if not self._make_room(len(payload)):
                logger.error('the spool is full (limit %s MB): the result for task %s cannot be held', max_bytes() // (1024 * 1024), task_id)
                return False
            fd, tmp = tempfile.mkstemp(prefix='.spool-', suffix='.tmp', dir=directory)  # mkstemp creates it 0600
            try:
                with os.fdopen(fd, 'wb') as handle:
                    handle.write(payload)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(tmp, os.path.join(directory, name))
            except BaseException:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
                raise
            _fsync_dir(directory)
            return True
        except OSError as exc:
            logger.error('the result for task %s could not be written to the spool: %s', task_id, exc)
            return False

    def remove(self, task_id):
        try:
            os.unlink(os.path.join(self.directory, self._name(task_id)))
        except (FileNotFoundError, ValueError):
            return
        except OSError as exc:
            logger.warning('could not delete the spool entry for task %s: %s', task_id, exc)
            return
        _fsync_dir(self.directory)

    def expire_old(self, window=None):
        """Move every entry older than the window to ``expired/``. Returns the task ids moved."""
        window = window_seconds() if window is None else window
        moved = []
        for age_task, age in self.entries():
            if age > window:
                if self._move_expired(age_task):
                    moved.append(age_task)
        return moved

    def _move_expired(self, task_id):
        try:
            name = self._name(task_id)
            dest = os.path.join(self.directory, EXPIRED_DIR)
            os.makedirs(dest, mode=0o700, exist_ok=True)
            os.replace(os.path.join(self.directory, name), os.path.join(dest, name))
            return True
        except (OSError, ValueError):
            return False

    # --- bounds -------------------------------------------------------------------------------------------------

    def _expired_files(self):
        out = []
        try:
            with os.scandir(os.path.join(self.directory, EXPIRED_DIR)) as it:
                for entry in it:
                    if entry.is_file(follow_symlinks=False):
                        st = entry.stat(follow_symlinks=False)
                        out.append((st.st_mtime_ns, entry.path, st.st_size))
        except OSError:
            return []
        return sorted(out)

    def total_bytes(self):
        return sum(s for _m, _n, s in self._live_files()) + sum(s for _m, _p, s in self._expired_files())

    def _make_room(self, needed):
        limit = max_bytes()
        if needed > limit:
            return False
        total = self.total_bytes()
        if total + needed <= limit:
            return True
        for _mtime, path, size in self._expired_files():  # only expired entries are ever dropped for room, oldest first
            try:
                os.unlink(path)
            except OSError:
                continue
            logger.warning('the spool is over its size limit: dropped the oldest expired entry (%s)', os.path.basename(path)[:-5])
            total -= size
            if total + needed <= limit:
                return True
        return total + needed <= limit
