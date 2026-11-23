#!/usr/bin/env python3
"""Extract exact frozen selected native bytes. No dynamic discovery, no fallback."""
import pathlib,json,os,hashlib,subprocess,shutil,stat
D=pathlib.Path('/mnt/nav-greetd');R=D/'root';B=D/'extract-batch';ISO=pathlib.Path('/tmp/NAV-development-001.iso')
def validate_tree(base,members):
    actual={str(p.relative_to(base))for p in base.rglob('*')if p.is_file()or p.is_symlink()}
    assert actual==set(members)
    for name,v in members.items():
        p=base/name
        assert not name.startswith('/')and '..'not in name.split('/')
        if 'link'in v:assert p.is_symlink()and os.readlink(p)==v['link']
        else:
            assert not p.is_symlink()and stat.S_ISREG(p.stat().st_mode)and p.stat().st_size==v['bytes']
            assert hashlib.sha256(p.read_bytes()).hexdigest()==v['sha256']
def main():
    members=json.loads((D/'sysroot-members.json').read_text());assert len(members)==286
    assert not R.exists()and not R.is_symlink()and not B.exists()and not B.is_symlink()
    assert not(D/'extract-failed.json').exists()
    assert all(not p.startswith('/')and '..'not in p.split('/')and not any(c in p for c in '*?[]')for p in members)
    total=sum(v['bytes']for v in members.values()if 'link'not in v);assert total<1536*1024**2
    assert shutil.disk_usage(D).free>=2*total+3*1024**3
    h=hashlib.sha256()
    with ISO.open('rb')as f:
        for b in iter(lambda:f.read(1048576),b''):h.update(b)
    assert ISO.stat().st_size==1734334464and h.hexdigest()=='09cf7f18940f8f84b9301050d98ee004a401a212a18c1abbadb18a547db83467'
    try:
        with (D/'extract.raw').open('wb')as f:
            subprocess.run(['unsquashfs','-processors','2','-no-progress','-no-wildcards','-strict-errors','-o','43124736','-d',str(B),str(ISO)]+sorted(members),check=True,stdout=f,stderr=subprocess.STDOUT,timeout=180)
        validate_tree(B,members);B.rename(R)
        (D/'sysroot-verified.json').write_text(json.dumps({'members':286,'bytes':total,'manifest_sha256':hashlib.sha256((D/'sysroot-members.json').read_bytes()).hexdigest(),'target_executed':False})+'\n')
    except BaseException:
        (D/'extract-failed.json').write_text('{"partial_preserved":true,"no_retry":true}\n');raise
if __name__=='__main__':main()
