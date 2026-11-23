#!/usr/bin/env python3
"""Strict pure output/input validators, shared with runner and replayable fixtures."""
import hashlib,json,pathlib,stat
STATUS_KEYS={'schema','compile_exit','elapsed_seconds','scope','daemon_executed','installed','input_manifest_sha256','diagnostic_counts','raw_log_retained','binary'}
def validate_output(d):
    d=pathlib.Path(d);assert not d.is_symlink()
    s=json.loads((d/'status.json').read_text());assert set(s)<=STATUS_KEYS
    assert set(s)>={'schema','compile_exit','elapsed_seconds','scope','daemon_executed','installed','input_manifest_sha256','diagnostic_counts','raw_log_retained'}
    assert s['schema']==1 and s['scope']=='target-userland-compile-only'
    assert s['daemon_executed']is False and s['installed']is False and s['raw_log_retained']is False
    assert type(s['compile_exit'])is int and -255<=s['compile_exit']<=255
    assert type(s['elapsed_seconds'])in (int,float) and 0<=s['elapsed_seconds']<=2800
    assert set(s['diagnostic_counts'])=={'error_lines','warning_lines','compile_lines'}
    assert all(type(x)is int and 0<=x<=1000000 for x in s['diagnostic_counts'].values())
    import re
    assert re.fullmatch('[0-9a-f]{64}',s['input_manifest_sha256'])
    names={'status.json','greetd','elf.txt'}if s['compile_exit']==0 else {'status.json'}
    assert {p.name for p in d.iterdir()}==names
    assert all(not p.is_symlink()and stat.S_ISREG(p.stat().st_mode)and p.stat().st_size<64*1024*1024 for p in d.iterdir())
    if s['compile_exit']==0:
        b=(d/'greetd').read_bytes();assert b[:4]==b'\x7fELF'
        assert s['binary']=={'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}
        for p in d.iterdir():
            data=p.read_bytes()
            assert all(z not in data for z in (b'/mnt/',b'/home/runner',b'ghp_',b'github_pat_',b'BEGIN PRIVATE KEY',b'NAV-development-001'))
    else:assert 'binary'not in s
    return s
