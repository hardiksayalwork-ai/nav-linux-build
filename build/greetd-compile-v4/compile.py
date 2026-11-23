#!/usr/bin/env python3
"""Compile-only runner body. Review candidate. No daemon execution or installation."""
import hashlib,json,os,pathlib,resource,subprocess,time
D=pathlib.Path('/mnt/nav-greetd');ROOT=D/'root';SRC=D/'input/source';VENDOR=D/'input/vendor';OUT=D/'output';WORK=D/'work'
def run(args,**kw):return subprocess.run(args,check=True,timeout=kw.pop('timeout',120),**kw)
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    assert os.geteuid()==0
    assert json.loads((D/'capability.json').read_text())['namespace'] is True
    from extract import validate_tree
    members=json.loads((D/'sysroot-members.json').read_text())
    validate_tree(ROOT,members)
    assert not OUT.exists() and not WORK.exists()
    OUT.mkdir(mode=0o700);WORK.mkdir(mode=0o700)
    manifest=json.loads((D/'inputs.json').read_text())
    expected=manifest['files'];actual={}
    for base in (SRC,VENDOR):
        assert base.is_dir() and not base.is_symlink()
        for p in base.rglob('*'):
            assert not p.is_symlink()
            if p.is_file():actual[str(p.relative_to(D/'input'))]=sha(p)
    assert actual==expected
    assert sha(SRC/'Cargo.lock')=='7327b498112b27b1e4ae545e2e8cee12a3964a020a3953e847e822e169381b33'
    assert os.statvfs(D).f_bavail*os.statvfs(D).f_frsize>=3*1024**3
    for p in ('usr/bin/gcc','opt/rustc-1.97.1/bin/cargo','opt/rustc-1.97.1/bin/rustc','usr/lib/libpam.so','usr/lib/libpam_misc.so'):
        assert (ROOT/p).exists()
    for x in ('home','tmp','target','cargo-home'): (WORK/x).mkdir()
    (WORK/'cargo-home/config.toml').write_text('[source.crates-io]\nreplace-with="vendor"\n[source.vendor]\ndirectory="/vendor"\n')
    # No real host /etc or target /etc is mounted. Only public toolchain/sysroot trees.
    # Only exact hash-verified selected tree is visible, never broad baseline /usr or /opt.
    q=['bwrap','--die-with-parent','--new-session','--unshare-all','--cap-drop','ALL',
       '--dir','/usr','--dir','/opt','--dir','/lib64',
       '--symlink','usr/bin','/bin','--symlink','usr/sbin','/sbin','--symlink','usr/lib','/lib']
    for name in ('usr','opt','lib64'):
        q+=['--ro-bind',str(ROOT/name),'/'+name]
    q+=['--proc','/proc','--dev','/dev','--dir','/etc',
       '--ro-bind',str(SRC),'/source','--ro-bind',str(VENDOR),'/vendor',
       '--bind',str(WORK),'/build','--chdir','/source','--clearenv']
    env={'PATH':'/opt/rustc-1.97.1/bin:/usr/bin:/bin','HOME':'/build/home','TMPDIR':'/build/tmp',
         'LC_ALL':'C','RUSTC':'/opt/rustc-1.97.1/bin/rustc','RUSTDOC':'/opt/rustc-1.97.1/bin/rustdoc',
         'CARGO_HOME':'/build/cargo-home','CARGO_TARGET_DIR':'/build/target','CARGO_NET_OFFLINE':'true',
         'CARGO_INCREMENTAL':'0','CARGO_PROFILE_DEV_DEBUG':'0','CARGO_BUILD_JOBS':'1',
         'RUSTFLAGS':'-C linker=/usr/bin/gcc --remap-path-prefix=/source=/greetd --remap-path-prefix=/vendor=/vendor',
         'CC':'/usr/bin/gcc','AR':'/usr/bin/ar'}
    for k,v in env.items():q+=['--setenv',k,v]
    q+=['/opt/rustc-1.97.1/bin/cargo','build','--frozen','--offline','--jobs','1','--package','greetd','--bin','greetd']
    # prlimit and timeout operate outside the namespace; no target timeout dependency.
    cmd=['systemd-run','--unit=nav-greetd-compile','--wait','--pipe','--collect','-p','MemoryMax=8589934592','-p','TasksMax=256','-p','RuntimeMaxSec=2720','timeout','--kill-after=10s','2700s','prlimit','--as=6442450944','--fsize=1073741824','--nproc=256','--']+q
    start=time.monotonic()
    with (WORK/'compile.raw').open('wb')as f:
        result=subprocess.run(cmd,stdout=f,stderr=subprocess.STDOUT,timeout=2720,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin'})
    status={'schema':1,'compile_exit':result.returncode,'elapsed_seconds':round(time.monotonic()-start,3),'scope':'target-userland-compile-only','daemon_executed':False,'installed':False,'input_manifest_sha256':sha(D/'inputs.json')}
    # Strict diagnostic projection, not a best-effort redaction of arbitrary private output.
    raw=(WORK/'compile.raw').read_bytes();assert len(raw)<=64*1024*1024
    import re
    counts={k:len(re.findall(rb'(?m)^'+v,raw))for k,v in {'error_lines':b'error','warning_lines':b'warning','compile_lines':b' *Compiling '}.items()}
    status['diagnostic_counts']=counts;status['raw_log_retained']=False
    if result.returncode==0:
        binary=WORK/'target/debug/greetd';assert binary.is_file() and not binary.is_symlink()
        b=binary.read_bytes();assert b[:4]==b'\x7fELF' and 0<len(b)<64*1024*1024
        # Inspect without executing: reject concrete private host/input paths and credentials.
        for needle in (b'/mnt/',b'/home/runner',b'ghp_',b'github_pat_',b'BEGIN PRIVATE KEY',b'NAV-development-001'):
            assert needle not in b
        (OUT/'greetd').write_bytes(b);(OUT/'greetd').chmod(0o600)
        status['binary']={'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}
        elf=run(['readelf','-h','-d','-V',str(binary)],stdout=subprocess.PIPE).stdout
        # Readelf output is public-input-derived, but paths removed using fixed filename.
        (OUT/'elf.txt').write_bytes(elf.replace(str(binary).encode(),b'greetd'))
    (OUT/'status.json').write_text(json.dumps(status,sort_keys=True,indent=2)+'\n')
    assert {p.name for p in OUT.iterdir()}==({'status.json','greetd','elf.txt'}if result.returncode==0 else {'status.json'})
    print('NAV_COMPILE_STATUS_RECORDED')
    raise SystemExit(0 if result.returncode==0 else 1)
if __name__=='__main__':main()
