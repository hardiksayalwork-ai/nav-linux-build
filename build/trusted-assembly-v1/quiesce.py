"""One-shot creator quiescence using owned pidfd. No call made in this work."""
import os,signal,time
from collector import proc_identity,read_file,O_DIR
from daemon_owner import OwnershipBlocked

def freeze_owned_daemon(owner,proc_fd):
 # Called after observing the unique fixed wrapper session, BEFORE requesting
 # its termination. SIGSTOP is uncatchable; prevents greetd check_children from
 # creating another greeter after the user-session worker exits. Never resume.
 if owner.child is None or owner.pidfd is None or owner.child.poll()is not None:raise OwnershipBlocked('owned creator missing')
 pid=owner.child.pid;first=proc_identity(proc_fd,pid)
 if first['uids']!=(0,0,0,0):raise OwnershipBlocked('creator identity')
 signal.pidfd_send_signal(owner.pidfd,signal.SIGSTOP)
 deadline=time.monotonic()+2
 while time.monotonic()<deadline:
  row=proc_identity(proc_fd,pid)
  if row['starttime']!=first['starttime']or row['uids']!=first['uids']:raise OwnershipBlocked('creator replaced')
  fd=os.open(str(pid),O_DIR,dir_fd=proc_fd)
  try:text=read_file(fd,'status',16384)
  finally:os.close(fd)
  state=[line.split()[1]for line in text.splitlines()if line.startswith('State:')]
  if state==['T']:
   owner.creator_frozen=True
   return {'creator_pid':pid,'starttime':first['starttime'],'creator_stopped':True,'resume_allowed':False,'session_clean':False}
  time.sleep(.01)
 raise OwnershipBlocked('creator stop unverified')

def destroy_frozen_creator(owner):
 # A stopped process cannot service TERM; destroy only our stable pidfd owner.
 if not getattr(owner,'creator_frozen',False):raise OwnershipBlocked('creator not quiesced')
 signal.pidfd_send_signal(owner.pidfd,signal.SIGKILL);owner.child.wait(timeout=3)
 return {'creator_reaped':True,'session_clean':False}
