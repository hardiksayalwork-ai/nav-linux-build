"""Exclusive daemon/PTY owner implementation source, never invoked here.

No callable integration launch path enables this module in current candidate.
This is not a general process supervisor. The only child command is the fixed
native test daemon/config, with private PTY and a single owner/reaper.
"""
import os,fcntl,stat,subprocess,pty,time,signal,termios
from pathlib import Path
class OwnershipBlocked(Exception):pass
def _single_thread_child_tty():
 # Only reviewed single-threaded controller may fork this preexec path.
 # Popen has connected fd0 to the inherited slave; setsid then TIOCSCTTY
 # explicitly makes it controlling. Inheriting an open slave is insufficient.
 os.setsid()
 fcntl.ioctl(0,termios.TIOCSCTTY,0)
 import array
 # Exact older09cf usr/include/asm-generic/ioctls.h defines TIOCGSID=0x5429.
 sid=array.array('i',[0]);fcntl.ioctl(0,0x5429,sid,True)
 if sid[0]!=os.getsid(0):raise OwnershipBlocked('controlling PTY not acquired')

class DaemonOwner:
 def __init__(self):self.child=None;self.master=None;self.slave=None;self.pidfd=None;self.lock=None
 def acquire_NOT_WIRED(self):
  if self.child is not None or os.getresuid()!=(0,0,0):raise OwnershipBlocked('single disposable root owner required')
  d=Path('/run/nav-test');s=d.lstat()
  if not stat.S_ISDIR(s.st_mode)or s.st_uid!=0 or s.st_mode&0o7777!=0o700:raise OwnershipBlocked('root private runtime required')
  self.lock=os.open('/run/nav-test/controller.lock',os.O_CREAT|os.O_EXCL|os.O_RDWR|os.O_CLOEXEC|os.O_NOFOLLOW,0o600)
  fcntl.flock(self.lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
  if len(os.listdir('/proc/self/task'))!=1:raise OwnershipBlocked('single-threaded owner required')
  self.master,self.slave=pty.openpty()
  # This PTY belongs only to this controller. No untrusted writer, network or
  # inherited app environment. Daemon's worker needs the slave as controlling
  # terminal when using vt=none; native PAM tty behavior remains unverified.
  self.child=subprocess.Popen(['/usr/sbin/nav-test-greetd','--config','/etc/greetd/nav-test.conf'],
   stdin=self.slave,stdout=self.slave,stderr=self.slave,close_fds=True,preexec_fn=_single_thread_child_tty,
   env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','HOME':'/nonexistent','LANG':'C.UTF-8','TERM':'linux'})
  self.pidfd=os.pidfd_open(self.child.pid)
 def stop_owned(self):
  # Direct daemon cleanup only, NEVER a whole-session-clean verdict.
  if self.child is None:return {'daemon_reaped':True,'session_clean':False}
  if self.pidfd is None:raise OwnershipBlocked('stable daemon reference missing')
  if self.child.poll() is None:signal.pidfd_send_signal(self.pidfd,signal.SIGKILL if getattr(self,'creator_frozen',False)else signal.SIGTERM)
  try:self.child.wait(timeout=3)
  except subprocess.TimeoutExpired:
   signal.pidfd_send_signal(self.pidfd,signal.SIGKILL);self.child.wait(timeout=3)
  for fd in (self.pidfd,self.master,self.slave,self.lock):
   if fd is not None:os.close(fd)
  # Do not delete the exclusive lock and allow another generation implicitly.
  return {'daemon_reaped':True,'session_clean':False,'automatic_restart':False}
 def __enter__(self):
  raise OwnershipBlocked('not integrated with byte/namespace/provision/teardown gates')
 def __exit__(self,*args):self.stop_owned()
