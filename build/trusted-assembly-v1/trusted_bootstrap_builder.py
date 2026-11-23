"""Generate PID1 bootstrap with literal reviewed bundle/runtime digests.

Trust anchor is host-verified exact initramfs, not root-readable JSON. No build
or target execution occurred here. Future receipt supplies actual bundle hash.
"""
import json,hashlib,re

def bootstrap(bundle_sha,runtime_sha,pinset_sha):
 for h in (bundle_sha,runtime_sha,pinset_sha):
  if not re.fullmatch('[0-9a-f]{64}',h):raise ValueError('literal digest')
 return ('''#!/usr/bin/python3 -IBS
import os,hashlib,tarfile,io,json,stat,sys
# Literal values embedded in exact host-verified initramfs bootstrap source.
BUNDLE_SHA=REPLACE_BUNDLE
RUNTIME_SHA=REPLACE_RUNTIME
PINSET_SHA=REPLACE_PINSET
def fail():
 os.write(2,b'NAV TRUSTED BOOTSTRAP FAILED; STOPPING\\n')
 os._exit(78)
try:
 if os.getpid()!=1 or os.getresuid()!=(0,0,0):fail()
 raw=open('/run/nav-private-input.tar.gz','rb').read(16777217)
 if len(raw)>16777216 or hashlib.sha256(raw).hexdigest()!=BUNDLE_SHA:fail()
 # Exact immutable bundle digest authenticates contents before parsing.
 files={}
 with tarfile.open(fileobj=io.BytesIO(raw),mode='r:gz')as t:
  for m in t:
   if m.name.startswith('/')or '..'in m.name.split('/')or m.name in files or not m.isfile()or m.size>4194304:fail()
   files[m.name]=(t.extractfile(m).read(),m.mode)
 r=files['usr/libexec/nav-test/runtime-input-binding.json'][0]
 p=files['usr/libexec/nav-test/injection-pinset.json'][0]
 if hashlib.sha256(r).hexdigest()!=RUNTIME_SHA or hashlib.sha256(p).hexdigest()!=PINSET_SHA:fail()
 pins=json.loads(p)
 if set(files)!=set(x.lstrip('/')for x in pins['files'])|{'usr/libexec/nav-test/injection-pinset.json'}:fail()
 # Import verified input gate from authenticated bundle bytes, before install.
 code=files['usr/libexec/nav-test/input_gate.py'][0];ns={};exec(compile(code,'<verified-input-gate>','exec'),ns)
 ns['runtime_inputs'](json.loads(r))
 gate={};exec(compile(files['usr/libexec/nav-test/guest_gate.py'][0],'<verified-mount-parser>','exec'),gate)
 sys.modules['guest_gate']=type(sys)('guest_gate');sys.modules['guest_gate'].__dict__.update(gate)
 overlay={};exec(compile(files['usr/libexec/nav-test/overlay_binding.py'][0],'<verified-overlay-gate>','exec'),overlay)
 overlay['observe_live'](pre_systemd=True)
 # PID1 before systemd: no provisioner, greeter, user session or competing task.
 for name,(data,mode)in files.items():
  if name!='usr/libexec/nav-test/injection-pinset.json':
   row=pins['files']['/'+name]
   if len(data)!=row['bytes']or hashlib.sha256(data).hexdigest()!=row['sha256']or mode!=row['mode']:fail()
  parts=name.split('/');fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
  try:
   for part in parts[:-1]:
    try:os.mkdir(part,0o755,dir_fd=fd)
    except FileExistsError:pass
    n=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);os.close(fd);fd=n
    st=os.fstat(fd)
    if st.st_uid!=0 or st.st_mode&0o022:fail()
   # No overwrite of an existing system input, all names dedicated except
   # dedicated PAM/config names, which must also be absent.
   out=os.open(parts[-1],os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode,dir_fd=fd)
   try:
    with os.fdopen(out,'wb')as f:f.write(data);f.flush();os.fsync(f.fileno())
   except BaseException:fail()
  finally:os.close(fd)
 unit=b'[Unit]\\nDescription=NAV one positive disposable case\\nAfter=systemd-logind.service\\nRequires=systemd-logind.service\\n[Service]\\nType=oneshot\\nExecStart=/usr/bin/python3 -IBS /usr/libexec/nav-test/trusted_entry.py\\nTimeoutStartSec=70\\nStandardInput=null\\nStandardOutput=journal\\nStandardError=journal\\n'
 os.makedirs('/run/systemd/system/multi-user.target.wants',exist_ok=True)
 f=os.open('/run/systemd/system/nav-disposable-test.service',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 with os.fdopen(f,'wb')as out:out.write(unit)
 os.symlink('../nav-disposable-test.service','/run/systemd/system/multi-user.target.wants/nav-disposable-test.service')
 # Root-readable records never supply authority. This PID1 was selected by the
 # direct host-pinned initrd, authenticated bundle, and verified every input.
 os.execve('/sbin/init',['/sbin/init'],{'PATH':'/usr/bin:/usr/sbin','LANG':'C.UTF-8'})
except BaseException:fail()
'''.replace('REPLACE_BUNDLE',repr(bundle_sha)).replace('REPLACE_RUNTIME',repr(runtime_sha)).replace('REPLACE_PINSET',repr(pinset_sha))).encode()
