#!/usr/bin/env python3
"""Read-only checks against an explicitly reviewed, commit-pinned build manifest."""
import argparse
import hashlib
import json
import os
from pathlib import Path


def digest_stream(stream):
    digest = hashlib.sha256()
    for block in iter(lambda: stream.read(1024 * 1024), b''):
        digest.update(block)
    return digest.hexdigest()


def load_manifest(path, expected_sha256):
    raw = Path(path).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == expected_sha256, 'manifest hash mismatch'
    manifest = json.loads(raw)
    assert manifest['schema_version'] == 1
    return manifest


def verify_inventory(manifest, observed, new_cache=None):
    rows = observed['actions_caches']
    assert observed['total_count'] == len(rows), 'cache inventory incomplete'
    actual = {str(row['id']): {'key': row['key'], 'bytes': row['size_in_bytes']} for row in rows}
    assert len(actual) == len(rows), 'duplicate cache ID'
    expected = dict(manifest['protected_caches'])
    if new_cache is not None:
        assert new_cache['id'] not in expected, 'new cache ID already protected'
        assert all(v['key'] != new_cache['key'] for v in expected.values()), 'new cache key already protected'
        expected[new_cache['id']] = {'key': new_cache['key'], 'bytes': new_cache['bytes']}
    assert actual == expected, 'protected cache identity/key/bytes changed'
    total = sum(v['bytes'] for v in actual.values())
    headroom = manifest['limits']['capacity_bytes'] - total
    assert headroom >= manifest['limits']['reserve_bytes'], 'cache reserve violated'
    return {'count': len(actual), 'bytes': total, 'headroom': headroom}


def verify_archive(manifest, package, archive):
    expected = manifest['accepted_archives'][package]
    path = Path(archive)
    assert path.stat().st_size == expected['bytes'], 'archive size mismatch'
    with path.open('rb') as stream:
        assert digest_stream(stream) == expected['sha256'], 'archive hash mismatch'
    return {'bytes': expected['bytes'], 'sha256': expected['sha256']}


def payload(root):
    root = Path(root)
    result = {}
    for path in root.rglob('*'):
        relative = str(path.relative_to(root))
        if path.is_symlink():
            result[relative] = {'symlink': os.readlink(path)}
        elif path.is_file():
            with path.open('rb') as stream:
                result[relative] = {'bytes': path.stat().st_size, 'sha256': digest_stream(stream)}
    return result


def verify_payload(manifest, package, directory):
    expected = manifest['accepted_archives'][package]['original_stage_paths']
    actual = payload(directory)
    assert actual == expected, 'original stage path or content mismatch'
    return {'paths': len(actual)}


def verify_mapped_root(manifest, package, directory):
    expected = manifest['accepted_archives'][package]
    root = Path(directory)
    checked = {}
    for source, record in expected['original_stage_paths'].items():
        target = expected['packaging_mapping'][source]
        assert not target.startswith('/') and '..' not in Path(target).parts
        path = root / target
        actual = {'symlink': os.readlink(path)} if path.is_symlink() else {'bytes': path.stat().st_size, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
        assert actual == record, 'mapped target content mismatch: ' + target
        checked[target] = actual
    for source, record in expected['canonical_paths_unchanged'].items():
        path = root / source
        assert not path.is_symlink()
        assert {'bytes': path.stat().st_size, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()} == record, 'canonical content changed: ' + source
    return {'mapped_paths': len(checked), 'canonical_paths_unchanged': len(expected['canonical_paths_unchanged'])}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', required=True)
    parser.add_argument('--manifest-sha256', required=True)
    sub = parser.add_subparsers(dest='action', required=True)
    inv = sub.add_parser('inventory')
    inv.add_argument('--observed', required=True)
    inv.add_argument('--approved-new-cache', help='Explicit ID/key/bytes JSON record; never inferred from observed state.')
    for action, flag in [('archive', 'file'), ('payload', 'directory'), ('mapped-root', 'directory')]:
        item = sub.add_parser(action)
        item.add_argument('--package', required=True)
        item.add_argument('--' + flag, required=True)
    args = parser.parse_args()
    manifest = load_manifest(args.manifest, args.manifest_sha256)
    if args.action == 'inventory':
        new = json.loads(Path(args.approved_new_cache).read_text()) if args.approved_new_cache else None
        result = verify_inventory(manifest, json.loads(Path(args.observed).read_text()), new)
    elif args.action == 'archive':
        result = verify_archive(manifest, args.package, args.file)
    elif args.action == 'payload':
        result = verify_payload(manifest, args.package, args.directory)
    else:
        result = verify_mapped_root(manifest, args.package, args.directory)
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
