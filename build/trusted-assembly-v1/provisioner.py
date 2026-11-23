"""Disposable provisioning implementation source. NEVER invoked in this work.

No public CLI. The unfinished integration must establish guest identity,
exclusive ownership and RAM-overlay provenance before this function can be
wired. Top-level controller backend remains unconditionally disabled.
"""
import os,pwd,grp,subprocess,secrets,hashlib,stat
from pathlib import Path
USER='navtestuser';GREETER='navtestgreeter';USER_ID=1201;GREETER_ID=1202
BINARIES={
 '/usr/sbin/chpasswd':'ed01a0f8253ec4b4b94c37f944094c4647562a6af5c39d8c10f2207c03da90c8',
 '/usr/sbin/useradd':'7fde31beb9dc6f88e9ebe21e504c97d7988d40f199d49f0a32e99cb7ce2d1d10',
}
class ProvisionBlocked(Exception):pass

def binary(path,expected):
 p=Path(path)
 for part in [p]+list(p.parents):
  if str(part)=='/':break
  s=part.lstat()
  if stat.S_ISLNK(s.st_mode) or s.st_uid!=0 or s.st_mode&0o022:raise ProvisionBlocked('untrusted binary path')
 if hashlib.sha256(p.read_bytes()).hexdigest()!=expected:raise ProvisionBlocked('binary digest mismatch')

def collision_check():
 # Select no password field for output; exceptions never print NSS records.
 for name,uid in ((USER,USER_ID),(GREETER,GREETER_ID)):
  for lookup,arg in ((pwd.getpwnam,name),(pwd.getpwuid,uid),(grp.getgrnam,name),(grp.getgrgid,uid)):
   try:lookup(arg)
   except KeyError:continue
   raise ProvisionBlocked('test account/group collision')

def fixed_command(argv,stdin=None):
 # No raw stderr or input is retained: shadow may mention a rejected record.
 # Native command deadline/failure is a hard stop; no fallback or retry.
 p=subprocess.run(argv,input=stdin,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
  timeout=10,close_fds=True,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C','HOME':'/nonexistent'})
 if p.returncode:raise ProvisionBlocked('fixed native provisioning command failed')

def provision_on_verified_ram_overlay():
 # Intentional hard stop until trusted mount/namespace and exact full tool set
 # checks are implemented in the single native controller. No caller boolean,
 # path marker or callback can bypass this source revision.
 raise ProvisionBlocked('RAM overlay/namespace controller binding not implemented')

def _provision_body_NOT_WIRED():
 """Reviewable fixed mutation sequence, unreachable from integration entry.

 Must not be called in isolation: only the future verified native controller
 may wire it after full gate review. Not a host/setup convenience function.
 """
 if os.getresuid()!=(0,0,0):raise ProvisionBlocked('disposable guest controller root required')
 collision_check()
 for path,h in BINARIES.items():binary(path,h)
 # -U gives each identity a distinct matching private group. -K disables log
 # allocation path; -M creates no uncontrolled skeleton/home copy. Exact tool
 # semantics and option support need native source/build review first.
 for name,uid in ((USER,USER_ID),(GREETER,GREETER_ID)):
  fixed_command(['/usr/sbin/useradd','-M','-U','-u',str(uid),'-d','/home/'+name,
   '-s','/bin/sh','-K','CREATE_MAIL_SPOOL=no','-K','LOG_INIT_ENAB=no',name])
  r=pwd.getpwnam(name)
  if (r.pw_uid,r.pw_gid,r.pw_dir)!=(uid,uid,'/home/'+name):raise ProvisionBlocked('post-provision NSS mismatch')
  os.mkdir('/home/'+name,0o700);os.chown('/home/'+name,uid,uid)
 # Random one-run fixture secret exists only after all identity checks pass.
 # Python/pipe/kernel copies cannot be guaranteed erased by bytearray clearing.
 secret=bytearray(secrets.token_urlsafe(32).encode('ascii'))
 payload=bytearray(USER.encode()+b':')+secret+b'\n'
 try:fixed_command(['/usr/sbin/chpasswd','-c','SHA512'],payload)
 except BaseException:
  for i in range(len(secret)):secret[i]=0
  raise
 finally:
  for i in range(len(payload)):payload[i]=0
 # No secret exported or printed; controller must consume in RAM then clear.
 return secret
