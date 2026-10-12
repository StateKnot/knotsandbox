"""Bounded ELF64/amd64 linkage verification, without executing candidate code."""
import struct
from pathlib import Path
from common import require

GNU = 'gnu-dynamic-v1'
STATIC = 'musl-static-v1'
GNU_INTERPRETER = '/lib64/ld-linux-x86-64.so.2'
GNU_ALLOWED = {'libgcc_s.so.1', 'libm.so.6', 'libc.so.6', 'ld-linux-x86-64.so.2'}
MAX_BINARY = 512 * 1024 * 1024


def inspect(data):
    require(isinstance(data, bytes) and 64 <= len(data) <= MAX_BINARY, 'ELF_SIZE')
    require(data[:7] == b'\x7fELF\x02\x01\x01', 'BINARY_PLATFORM')
    fields = struct.unpack_from('<HHIQQQIHHHHHH', data, 16)
    kind, machine, version, entry, offset, _, _, header_size, entry_size, count, _, _, _ = fields
    require(kind in (2, 3) and machine == 62 and version == 1 and header_size == 64, 'BINARY_PLATFORM')
    require(entry_size == 56 and 1 <= count <= 1024 and offset >= 64 and offset + count * 56 <= len(data), 'ELF_PROGRAM_HEADERS')
    segments = [struct.unpack_from('<IIQQQQQQ', data, offset + index * 56) for index in range(count)]
    for _, _, file_offset, _, _, file_size, memory_size, alignment in segments:
        require(file_offset <= len(data) and file_size <= len(data) - file_offset and file_size <= memory_size, 'ELF_SEGMENT_BOUNDS')
        require(alignment == 0 or alignment & (alignment - 1) == 0, 'ELF_SEGMENT_ALIGNMENT')
    loads = [s for s in segments if s[0] == 1]
    require(loads and any(s[1] & 1 and s[3] <= entry < s[3] + s[6] for s in loads), 'ELF_ENTRY_POINT')
    interpreters = [s for s in segments if s[0] == 3]
    require(len(interpreters) <= 1, 'ELF_INTERPRETER_DUPLICATE')
    interpreter = None
    if interpreters:
        s = interpreters[0]
        raw = data[s[2]:s[2] + s[5]]
        require(2 <= len(raw) <= 256 and raw[-1:] == b'\0' and b'\0' not in raw[:-1], 'ELF_INTERPRETER')
        try: interpreter = raw[:-1].decode('ascii')
        except UnicodeError as error: raise ValueError('ELF_INTERPRETER') from error
    dynamics = [s for s in segments if s[0] == 2]
    require(len(dynamics) <= 1, 'ELF_DYNAMIC_DUPLICATE')
    needed, strings, string_size = [], None, None
    if dynamics:
        s = dynamics[0]
        require(s[5] <= 1024 * 1024 and s[5] % 16 == 0, 'ELF_DYNAMIC_BOUNDS')
        terminated = False
        for at in range(s[2], s[2] + s[5], 16):
            tag, value = struct.unpack_from('<qQ', data, at)
            if tag == 0: terminated = True; break
            if tag == 1: needed.append(value)
            elif tag == 5:
                require(strings is None, 'ELF_STRTAB_DUPLICATE'); strings = value
            elif tag == 10:
                require(string_size is None, 'ELF_STRSZ_DUPLICATE'); string_size = value
            elif tag in (15, 29): raise ValueError('ELF_RPATH_FORBIDDEN')
        require(terminated and len(needed) <= 64, 'ELF_DYNAMIC_TERMINATION')
    names = []
    if needed:
        require(strings is not None and string_size is not None and 0 < string_size <= 1024 * 1024, 'ELF_STRTAB_REQUIRED')
        candidates = [s for s in loads if s[3] <= strings and strings - s[3] <= s[5] and string_size <= s[5] - (strings - s[3])]
        require(len(candidates) == 1, 'ELF_STRTAB_MAPPING')
        s = candidates[0]; start = s[2] + strings - s[3]
        table = data[start:start + string_size]
        for index in needed:
            require(index < len(table), 'ELF_NEEDED_BOUNDS')
            end = table.find(b'\0', index, min(len(table), index + 256))
            require(end > index, 'ELF_NEEDED_NAME')
            try: name = table[index:end].decode('ascii')
            except UnicodeError as error: raise ValueError('ELF_NEEDED_NAME') from error
            require('/' not in name and all(c.isalnum() or c in '_.+-' for c in name), 'ELF_NEEDED_NAME')
            names.append(name)
        require(len(names) == len(set(names)), 'ELF_NEEDED_DUPLICATE')
    return {'kind': 'EXEC' if kind == 2 else 'PIE', 'interpreter': interpreter, 'needed': sorted(names)}


def validate(data, profile):
    value = inspect(data)
    if profile == GNU:
        require(value['interpreter'] == GNU_INTERPRETER, 'ELF_GNU_INTERPRETER')
        require('libc.so.6' in value['needed'] and set(value['needed']) <= GNU_ALLOWED, 'ELF_GNU_NEEDED')
    elif profile == STATIC:
        require(value['interpreter'] is None and not value['needed'], 'ELF_STATIC_DEPENDENCY')
    else: raise ValueError('ELF_PROFILE_UNKNOWN')
    return value


def validate_file(path, profile):
    path = Path(path)
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= MAX_BINARY, 'ELF_FILE')
    return validate(path.read_bytes(), profile)
