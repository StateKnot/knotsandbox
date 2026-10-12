"""Bounded, canonical inventory of one quiesced Restic repository.

Full encrypted object hashes are computed in the trusted SEAL job. The control
plane subsequently verifies signed inventory and metadata, not 16 TiB of data.
"""
import hashlib
import json
from pathlib import Path
import re
import sqlite3

MAX_OBJECTS = 2_000_000
MAX_INVENTORY_BYTES = 512 * 1024 * 1024
MAX_SHARD_BYTES = 1024 * 1024
MAX_OBJECT_BYTES = 128 * 1024 * 1024
MAX_REPOSITORY_BYTES = 32 * 1024**4
MAX_SHARDS = 1024


def require(condition, code):
    if not condition:
        raise ValueError(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def object_key(key, snapshot):
    if key == 'config':
        return True
    if re.fullmatch(r'(keys|index)/[0-9a-f]{64}', key):
        return True
    if key == 'snapshots/' + snapshot:
        return True
    return re.fullmatch(r'data/[0-9a-f]{2}/[0-9a-f]{64}', key) is not None and key[5:7] == key[8:10]


def build(c, snapshot, remote, directory, deadline, env, run, rclone='/usr/local/bin/rclone'):
    """Stream list/hash operations, bound a disk-backed index, emit sorted shards.

    Caller uploads all shards before manifest/signature. Existing sealed objects
    must be quiesced and immutable; this function grants no write authorization.
    """
    require(re.fullmatch('[0-9a-f]{64}', snapshot), 'INVENTORY_SNAPSHOT')
    directory = Path(directory)
    directory.mkdir(mode=0o700, parents=False, exist_ok=False)
    db = sqlite3.connect(directory / 'index.sqlite')
    pending = bytearray()
    count = total = 0
    try:
        db.execute('PRAGMA page_size=4096')
        db.execute('PRAGMA journal_mode=OFF')
        db.execute('PRAGMA synchronous=OFF')  # Scratch only; never a completion receipt.
        db.execute('PRAGMA cache_size=-4096')
        db.execute('PRAGMA max_page_count=131072')  # Default 4096-byte pages: 512 MiB.
        db.execute('CREATE TABLE objects(key TEXT PRIMARY KEY, size INTEGER NOT NULL, sha TEXT, checked INTEGER NOT NULL DEFAULT 0) WITHOUT ROWID')
        def listing(block):
            nonlocal count, total, pending
            lines = (pending + block).split(b'\n')
            pending = bytearray(lines.pop())
            for line in lines:
                require(len(line) <= 256 and b'\r' not in line, 'INVENTORY_LIST_FRAME')
                fields = line.decode('ascii').split('\t')
                require(len(fields) == 2 and fields[0].isdigit(), 'INVENTORY_LIST_FIELDS')
                size, key = int(fields[0]), fields[1]
                require(0 < size <= MAX_OBJECT_BYTES and object_key(key, snapshot), 'INVENTORY_OBJECT')
                if key == 'config' or key.startswith('snapshots/'):
                    require(size <= MAX_SHARD_BYTES, 'INVENTORY_METADATA_LIMIT')
                count += 1
                total += size
                require(count <= MAX_OBJECTS and total <= MAX_REPOSITORY_BYTES, 'INVENTORY_LIMIT')
                db.execute('INSERT INTO objects(key,size) VALUES (?, ?)', (key, size))
            require(len(pending) <= 256, 'INVENTORY_LIST_FRAME')
        run([rclone, 'lsf', '--recursive', '--files-only', '--format', 'sp', '--separator', '\t', remote], deadline, env, sink=listing)
        require(not pending, 'INVENTORY_INCOMPLETE_LIST')
        db.commit()
        # One mature streaming process keeps workers/STS reuse bounded. Starting
        # rclone once per object would be prohibitive at the two-million limit.
        def hashed(block):
            nonlocal pending
            lines = (pending + block).split(b'\n')
            pending = bytearray(lines.pop())
            for line in lines:
                require(len(line) <= 256 and b'\r' not in line, 'INVENTORY_HASH_FRAME')
                text = line.decode('ascii')
                require(len(text) >= 67 and text[64:66] == '  ', 'INVENTORY_HASH_FIELDS')
                checksum, key = text[:64], text[66:]
                require(re.fullmatch('[0-9a-f]{64}', checksum) and object_key(key, snapshot), 'INVENTORY_HASH_OBJECT')
                require(key == 'config' or checksum == key.rsplit('/', 1)[1], 'INVENTORY_CONTENT_ADDRESS')
                changed = db.execute('UPDATE objects SET sha=? WHERE key=? AND sha IS NULL', (checksum, key)).rowcount
                require(changed == 1, 'INVENTORY_HASH_SET_CHANGED')
            require(len(pending) <= 256, 'INVENTORY_HASH_FRAME')
        run([rclone, 'hashsum', 'SHA256', '--download', '--checkers', '2', '--max-size', '128Mi', remote], deadline, env, sink=hashed)
        require(not pending and db.execute('SELECT count(*) FROM objects WHERE sha IS NULL').fetchone()[0] == 0, 'INVENTORY_HASH_INCOMPLETE')
        def relisted(block):
            nonlocal pending
            lines = (pending + block).split(b'\n')
            pending = bytearray(lines.pop())
            for line in lines:
                require(len(line) <= 256, 'INVENTORY_LIST_FRAME')
                fields = line.decode('ascii').split('\t')
                require(len(fields) == 2 and fields[0].isdigit(), 'INVENTORY_LIST_FIELDS')
                changed = db.execute('UPDATE objects SET checked=1 WHERE key=? AND size=? AND checked=0', (fields[1], int(fields[0]))).rowcount
                require(changed == 1, 'INVENTORY_LIST_CHANGED')
            require(len(pending) <= 256, 'INVENTORY_LIST_FRAME')
        run([rclone, 'lsf', '--recursive', '--files-only', '--format', 'sp', '--separator', '\t', remote], deadline, env, sink=relisted)
        require(not pending and db.execute('SELECT count(*) FROM objects WHERE checked=0').fetchone()[0] == 0, 'INVENTORY_LIST_INCOMPLETE')
        db.commit()
        base = {'protocol': 1, 'tenant_id': c['tenant_id'], 'backup_id': c['backup_id'],
                'seal_attempt_id': c['seal_attempt_id'], 'cluster_epoch': c['cluster_epoch']}
        descriptors, objects = [], []
        encoded_bytes = len(canonical({**base, 'objects': []}))
        inventory_bytes = 0
        groups = set()
        def flush():
            nonlocal inventory_bytes, objects, encoded_bytes
            require(objects, 'INVENTORY_EMPTY_SHARD')
            body = canonical({**base, 'objects': objects})
            require(len(body) <= MAX_SHARD_BYTES and len(descriptors) < MAX_SHARDS, 'INVENTORY_SHARD_LIMIT')
            key = f'inventory/{len(descriptors):06d}.json'
            (directory / Path(key).name).write_bytes(body)
            descriptors.append({'key': key, 'size_bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest(), 'object_count': len(objects)})
            inventory_bytes += len(body)
            require(inventory_bytes <= MAX_INVENTORY_BYTES, 'INVENTORY_TOTAL_LIMIT')
            objects = []
            encoded_bytes = len(canonical({**base, 'objects': []}))
        for key, size, checksum in db.execute('SELECT key,size,sha FROM objects ORDER BY key COLLATE BINARY'):
            entry = {'key': key, 'size_bytes': size, 'sha256': checksum}
            entry_size = len(canonical(entry)) + (1 if objects else 0)
            if encoded_bytes + entry_size > MAX_SHARD_BYTES:
                flush()
                entry_size = len(canonical(entry))
            objects.append(entry)
            encoded_bytes += entry_size
            groups.add(key.split('/')[0])
        require(groups == {'config', 'data', 'index', 'keys', 'snapshots'}, 'INVENTORY_REPOSITORY_INCOMPLETE')
        flush()
        return {'format': 'restic-object-inventory-v1', 'object_count': count, 'total_bytes': total, 'shards': descriptors}
    finally:
        db.close()
        (directory / 'index.sqlite').unlink(missing_ok=True)


def validate(value):
    require(isinstance(value, dict) and set(value) == {'format', 'object_count', 'total_bytes', 'shards'}, 'INVENTORY_FIELDS')
    require(value['format'] == 'restic-object-inventory-v1' and type(value['object_count']) is int and 5 <= value['object_count'] <= MAX_OBJECTS, 'INVENTORY_COUNT')
    require(type(value['total_bytes']) is int and 0 < value['total_bytes'] <= MAX_REPOSITORY_BYTES, 'INVENTORY_BYTES')
    shards = value['shards']
    require(isinstance(shards, list) and 1 <= len(shards) <= MAX_SHARDS, 'INVENTORY_SHARDS')
    count = size = 0
    for index, shard in enumerate(shards):
        require(set(shard) == {'key', 'size_bytes', 'sha256', 'object_count'} and shard['key'] == f'inventory/{index:06d}.json', 'INVENTORY_SHARD_KEY')
        require(type(shard['size_bytes']) is int and 0 < shard['size_bytes'] <= MAX_SHARD_BYTES and re.fullmatch('[0-9a-f]{64}', shard['sha256']), 'INVENTORY_SHARD_HASH')
        require(type(shard['object_count']) is int and 0 < shard['object_count'] <= MAX_OBJECTS, 'INVENTORY_SHARD_COUNT')
        count += shard['object_count']; size += shard['size_bytes']
    require(count == value['object_count'] and size <= MAX_INVENTORY_BYTES, 'INVENTORY_TOTAL')
