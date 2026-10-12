"""Owner cleanup for this directory's offline Prometheus protocol fixtures only."""
from contextlib import contextmanager
from pathlib import Path
import stat
import subprocess
import sys
import tempfile

from observability import LOCK


_PROFILES = {
    'sandbox-metrics-check-': ('wal', 'wal-samples'),
    'sandbox-prometheus-pipeline-': ('receiver', 'agent-a', 'agent-b'),
}


@contextmanager
def fixture_directory(prefix, stores):
    """Keep test failures intact while the data owner removes its own stores.

    Callers stop their fixture containers before leaving this context. The
    helper mounts only newly-created direct children of its own random root;
    it cannot accept a deployment path, shared volume, or arbitrary directory.
    """
    stores = tuple(stores)
    if _PROFILES.get(prefix) != stores:
        raise ValueError('FIXTURE_CLEANUP_PROFILE')
    temporary = tempfile.TemporaryDirectory(prefix=prefix)
    path = Path(temporary.name)
    primary = None
    try:
        yield path
    except BaseException as error:
        primary = error
        raise
    finally:
        errors = []
        for name in stores:
            store = path / name
            try:
                metadata = store.lstat()
            except FileNotFoundError:
                # A setup failure may precede creation of this store.
                continue
            except OSError as error:
                errors.append(f'{type(error).__name__}: {error}')
                continue
            try:
                if not stat.S_ISDIR(metadata.st_mode) or store.resolve().parent != path.resolve() or ',' in str(store):
                    raise ValueError('FIXTURE_STORE_IDENTITY')
                # Prometheus owns wal/chunks_head on Linux. The host test user
                # cannot recursively remove those directories. Preserve their
                # modes, and let the same fixed image's default non-root owner
                # remove only these offline fixture children after assertions.
                command = ['docker', 'run', '--rm', '--pull=never', '--network=none',
                           '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges',
                           '--mount', f'type=bind,src={store},dst=/prometheus',
                           '--entrypoint=/bin/rm', LOCK['prometheus_image'],
                           '-rf', '/prometheus/wal', '/prometheus/chunks_head']
                completed = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                           timeout=30, check=False)
                if completed.returncode:
                    detail = (completed.stdout + completed.stderr)[:4096].decode(errors='replace')
                    raise ValueError(f'FIXTURE_STORE_CLEANUP_FAILED {name}: {detail}')
            except (ValueError, OSError, subprocess.SubprocessError) as error:
                errors.append(f'{type(error).__name__}: {error}')
        try:
            # The host removes its own parent/configuration files only after
            # the data owner's children have gone. Never ignore this failure.
            temporary.cleanup()
        except OSError as error:
            errors.append(f'FIXTURE_HOST_CLEANUP_FAILED: {type(error).__name__}: {error}')
        if errors:
            detail = '\n'.join(errors)[:8192]
            print(f'FIXTURE_CLEANUP_FAILED: {detail}', file=sys.stderr)
            if primary is None:
                raise ValueError('FIXTURE_CLEANUP_FAILED')
