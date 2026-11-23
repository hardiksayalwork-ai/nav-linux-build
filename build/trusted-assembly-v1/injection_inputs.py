"""Exact proposed injection assembly from verified hosted bytes, never run here."""
import io,gzip,tarfile,hashlib,json,pathlib,stat
ASSEMBLY_SHA='432053fc9ec3240b2a7ad670aca97817abd6cb2a0e1e4a332df2a9e0b142d493'
DAEMON_SHA='980455303b71eaf77b0920974b7deb02b1ebd5db717397e5b6f672d35740d302'
DAEMON_BYTES=3269688
FILES={'nav-login-terminal.py':('/usr/libexec/nav-login-terminal',0o755),
 'nav-user-session.py':('/usr/libexec/nav-user-session',0o755),
 'prompt_literals.py':('/usr/libexec/nav-login/prompt_literals.py',0o644),
 'policies/nav-test-user':('/etc/pam.d/nav-test-user',0o600),
 'policies/nav-test-greeter':('/etc/pam.d/nav-test-greeter',0o600),
 'config/nav-test.conf':('/etc/greetd/nav-test.conf',0o600)}
class AssemblyBlocked(Exception):pass

def observed_daemon(raw):
 if len(raw)!=911432 or hashlib.sha256(raw).hexdigest()!=ASSEMBLY_SHA:raise AssemblyBlocked('exact hosted assembly required')
 expected={'usr/sbin/nav-test-greetd','usr/libexec/nav-login-terminal','usr/libexec/nav-login/prompt_literals.py','evidence/daemon-member-receipt.json'};members={}
 with tarfile.open(fileobj=io.BytesIO(raw),mode='r:gz')as t:
  for x in t:
   if x.name not in expected or x.name in members or not x.isfile()or x.size>4*1024*1024:raise AssemblyBlocked('assembly shape')
   members[x.name]=t.extractfile(x).read()
 if set(members)!=expected:raise AssemblyBlocked('assembly set')
 b=members['usr/sbin/nav-test-greetd']
 if len(b)!=DAEMON_BYTES or hashlib.sha256(b).hexdigest()!=DAEMON_SHA:raise AssemblyBlocked('daemon member')
 return b

def prepare_inputs(raw,source_dir,reviewed_pins):
 # raw must arrive through the separately approved hosted authenticated route.
 # Final source hashes are supplied only by the pinned package manifest, not
 # trusted as an authorization grant. No installation/controller invocation.
 root=pathlib.Path(source_dir);result={'usr/sbin/nav-test-greetd':(observed_daemon(raw),0o755)}
 for name,(dest,mode)in FILES.items():
  data=(root/name).read_bytes()
  if hashlib.sha256(data).hexdigest()!=reviewed_pins[name]:raise AssemblyBlocked('source pin')
  result[dest.lstrip('/')]=(data,mode)
 return result

def private_tar(inputs):
 out=io.BytesIO()
 with tarfile.open(fileobj=out,mode='w:')as t:
  for name,(data,mode)in sorted(inputs.items()):
   if name.startswith('/')or '..'in name.split('/'):raise AssemblyBlocked('destination')
   h=tarfile.TarInfo(name);h.mode=mode;h.uid=h.gid=h.mtime=0;h.size=len(data);t.addfile(h,io.BytesIO(data))
 return gzip.compress(out.getvalue(),mtime=0)
