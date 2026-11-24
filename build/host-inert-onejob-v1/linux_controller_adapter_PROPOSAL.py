"""Linux controller adapter source. Not constructed or invoked on live PIDs.

Uses controller-owned proc dir,pidfd,cgroup handle and one-way token writer.
Deployment factory refuses until ownership/delegation and guard ABI reviewed.
"""
import os,signal,stat,select
from placement_observation import parse_stat,verify_stopped_membership,verify_empty
from release_transaction import ReleaseTransaction,ReleaseBlocked
from pidfd_identity import verify_pidfd_info
from filesystem_identity import require_type,PROC_MAGIC
class ControllerBlocked(Exception):pass

def read_relative(dirfd,name,limit=65536):
 if name not in ('stat','cgroup','children','fdinfo'):raise ControllerBlocked('unexpected proc member')
 fd=os.open(name,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW,dir_fd=dirfd)
 try:
  b=os.read(fd,limit+1)
  if len(b)>limit:raise ControllerBlocked('oversize proc record')
  return b.decode('ascii')
 finally:os.close(fd)

def read_pidfd_info(pidfd):
 # pidfd itself is owned/retained;fdinfo comes from pinned current procfs in
 # eventual controller. Current path-based helper still needs procfs binding.
 fd=os.open('/proc/self/fdinfo/'+str(pidfd),os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW)
 try:
  b=os.read(fd,65537)
  if len(b)>65536:raise ControllerBlocked('oversize pidfd info')
  return b.decode('ascii')
 finally:os.close(fd)

class OwnedStoppedController:
 @classmethod
 def acquire(cls,*args,**kwargs):raise ControllerBlocked('guard ABI/noescape/delegation/runtime bindings not accepted')
 def __init__(self,procfd,pidfd,token_write,cgroup,expected):
  # Source-only constructor. Actual future acquire must pin procfs mount plus
  # bind child creation identity before pidfd_open and membership move.
  require_type(procfd,PROC_MAGIC)
  self.procfd=os.dup(procfd);self.pidfd=os.dup(pidfd);self.token=os.dup(token_write);self.cg=cgroup;self.expected=dict(expected);self.release=ReleaseTransaction(expected);self.closed=False
 def observe(self):
  before=read_relative(self.procfd,'stat');membership=read_relative(self.procfd,'cgroup');members=self.cg.read('cgroup.procs');after=read_relative(self.procfd,'stat')
  # pidfd lifetime poll detects termination. Does not by itself bind numeric
  # PID/starttime:acquire must verify /proc/self/fdinfo Pid/NSpid identity.
  if 'ns_pids'not in self.expected:raise ControllerBlocked('expected namespace PID lineage required')
  info=read_pidfd_info(self.pidfd)
  verify_pidfd_info(info,self.expected['pid'],self.expected['ns_pids'])
  poll=select.poll();poll.register(self.pidfd,select.POLLIN|select.POLLHUP|select.POLLERR)
  alive=not bool(poll.poll(0))
  return before,after,membership,members,alive
 def release_stopped(self):
  if self.closed:raise ControllerBlocked('controller closed')
  obs=self.observe();self.release.observed(*obs)
  def token(b):return os.write(self.token,b)
  def cont():signal.pidfd_send_signal(self.pidfd,signal.SIGCONT,None,0)
  try:self.release.release(token,cont,self.observe)
  except BaseException:
   # Token-write without successfulCONT still leaves a stopped task. Always
   # request whole-subtree kill,never try alternate PID signaling or resume.
   self.cg._write('cgroup.kill',b'1');raise
 def terminate_empty(self,deadline_ns):
  self.cg.kill_and_verify_empty(deadline_ns)
  self.release.killed(self.cg.read('cgroup.events'),self.cg.read('cgroup.procs'))
 def finish(self,reap_guard,dispose_namespace,postflight):
  return self.release.finish(reap_guard,dispose_namespace,postflight)
 def close(self):
  if not self.closed:
   self.closed=True
   for fd in (self.token,self.pidfd,self.procfd):os.close(fd)
