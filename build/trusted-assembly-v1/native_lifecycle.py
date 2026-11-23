"""Single-generation positive lifecycle body, public entry remains blocked.

No body invoked in source preparation. Each acceptance matrix case needs its
own separately approved disposable VM. No daemon restarts or auth retries.
"""
import os,time,hashlib,stat,json
from pathlib import Path
from overlay_binding import observe_live
from provisioner import _provision_body_NOT_WIRED,collision_check
from daemon_owner import DaemonOwner
from terminal_driver import drive
from session_discovery import discover
from session_cleanup import terminate_once,await_cleanup
from quiesce import freeze_owned_daemon,destroy_frozen_creator
from manager_authority import sessions,AuthorityBlocked
from input_gate import runtime_inputs,regular_bytes

class LifecycleBlocked(Exception):pass

def make_private_runtime():
 os.mkdir('/run/nav-test',0o700)
 for name,user in (('user-allow','navtestuser'),('greeter-allow','navtestgreeter')):
  fd=os.open('/run/nav-test/'+name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  try:os.write(fd,(user+'\n').encode());os.fsync(fd)
  finally:os.close(fd)

def check_no_test_sessions():
 if any(x[1]in (1201,1202)or x[2]in ('navtestuser','navtestgreeter')for x in sessions()):raise LifecycleBlocked('preexisting test session')

def _positive_body_after_exact_launch_and_input_gate():
 # This is the concrete workflow order, NOT callable as a root setup helper.
 # Public main refuses until the launch/input gate below is fully implemented.
 if os.getresuid()!=(0,)*3 or len(os.listdir('/proc/self/task'))!=1:raise LifecycleBlocked('single root controller required')
 observe_live()
 with open('/usr/libexec/nav-test/runtime-input-binding.json')as f:runtime_inputs(json.load(f))
 with open('/usr/libexec/nav-test/injection-pinset.json')as f:pins=json.load(f)
 for path,row in pins['files'].items():regular_bytes(path,row['sha256'],row['bytes'])
 collision_check();check_no_test_sessions();make_private_runtime()
 secret=None;owner=DaemonOwner();owned=None;procfd=cgfd=None;frozen=False
 try:
  secret=_provision_body_NOT_WIRED()
  procfd=os.open('/proc',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
  cgfd=os.open('/sys/fs/cgroup',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
  # Runtime module is main-thread only and assumes no competing owner/writer.
  owner.acquire_NOT_WIRED()
  result=drive(owner.master,owner.slave,b'navtestuser',secret,time.monotonic()+12,True)
  if result['terminal_result']!='scheduled-only':raise LifecycleBlocked('positive scheduling failed')
  # Scheduling ack is not PAM/login proof. Independently bind actual unique
  # login1 session, root worker leader and child wrapper, pidfds and scope FD.
  until=time.monotonic()+3
  while True:
   try:owned=discover(owner,procfd,cgfd);break
   except (AuthorityBlocked,OSError):
    if time.monotonic()>=until:raise LifecycleBlocked('unique session discovery deadline')from None
    time.sleep(.02)
  freeze_owned_daemon(owner,procfd);frozen=True
  terminate_once(owned,owner,procfd)
  clean=await_cleanup(owned,owner,procfd,cgfd)
  destroy_frozen_creator(owner)
  # No following fresh login or reuse. The outer harness disposes the VM.
  return {'scope':'single-positive-disposable-case','scheduled':True,'session_identity_bound':True,'cleanup':clean,'vm_disposal_required':True,'native_acceptance':False}
 finally:
  if secret is not None:
   for i in range(len(secret)):secret[i]=0
  if owned:
   for fd in (owned.scope_fd,owned.leader_pidfd,owned.child_pidfd):os.close(fd)
  for fd in (procfd,cgfd):
   if fd is not None:os.close(fd)
  # On uncertainty never certify cleanup. Only terminate our stable creator;
  # scope/worker cleanup remains outer VM disposal, not a success result.
  owner.stop_owned()

def main():
 raise LifecycleBlocked('launch provenance and complete root-owned injection/runtime verifier not implemented; no native effects')
if __name__=='__main__':
 try:main()
 except LifecycleBlocked:raise SystemExit(78)
