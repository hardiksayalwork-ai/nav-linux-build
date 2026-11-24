"""Controller-owned cgroup-FD operations source. NOT used on live cgroups.

Caller must obtain a delegated dedicated cgroup with no escape path and bind
its filesystem identity. A directory FD does not authenticate delegation or
prevent a privileged adversary. construct() always refuses pending integration.
"""
import os,stat,re,time
from placement_observation import verify_empty,PlacementBlocked
from fd_group_admission import verify_group_fd
class CgroupBlocked(Exception):pass
class DedicatedCgroup:
 @classmethod
 def construct(cls,*args,**kwargs):raise CgroupBlocked('cgroup ownership/no-escape/proc pidfd binding not proved')
 def __init__(self,dirfd,expected_dev,expected_ino):
  verify_group_fd(dirfd) # Mandatory admission;directinitcannotbypassfactory.
  st=os.fstat(dirfd)
  if not stat.S_ISDIR(st.st_mode)or(st.st_dev,st.st_ino)!=(expected_dev,expected_ino):raise CgroupBlocked('cgroup identity mismatch')
  self.fd=os.dup(dirfd);self.identity=(expected_dev,expected_ino)
 def close(self):
  if self.fd is not None:os.close(self.fd);self.fd=None
 def _open(self,name,flags):
  if name not in ('cgroup.procs','cgroup.events','cgroup.kill','memory.max','memory.swap.max','pids.max'):raise CgroupBlocked('unexpected controller file')
  if self.fd is None:raise CgroupBlocked('closed controller')
  st=os.fstat(self.fd)
  if(st.st_dev,st.st_ino)!=self.identity:raise CgroupBlocked('controller replaced')
  return os.open(name,flags|os.O_CLOEXEC|os.O_NOFOLLOW,dir_fd=self.fd)
 def read(self,name):
  fd=self._open(name,os.O_RDONLY)
  try:
   b=os.read(fd,65537)
   if len(b)>65536:raise CgroupBlocked('oversize controller read')
   return b.decode('ascii')
  finally:os.close(fd)
 def _write(self,name,data):
  fd=self._open(name,os.O_WRONLY)
  try:
   if os.write(fd,data)!=len(data):raise CgroupBlocked('short controller write')
  finally:os.close(fd)
 def set_limits(self,memory_bytes,pids):
  if type(memory_bytes)is not int or memory_bytes<1 or type(pids)is not int or pids<1:raise CgroupBlocked('finite limits required')
  if self.read('cgroup.procs').strip():raise CgroupBlocked('limits must precede child placement')
  self._write('memory.max',str(memory_bytes).encode());self._write('memory.swap.max',b'0');self._write('pids.max',str(pids).encode())
  for name,expected in [('memory.max',str(memory_bytes)),('memory.swap.max','0'),('pids.max',str(pids))]:
   # read() permits same allowlist.
   if self.read(name).strip()!=expected:raise CgroupBlocked('limit readback mismatch')
 def place_stopped_child(self,pid):
  # A PID number alone is insufficient. Disabled until pidfd lifetime plus
  # controller-owned stopped observation and exec barrier are integrated.
  raise CgroupBlocked('stopped pidfd placement release not implemented')
 def kill_and_verify_empty(self,deadline_ns,clock=time.monotonic_ns,sleep=time.sleep):
  self._write('cgroup.kill',b'1')
  while True:
   events=self.read('cgroup.events');procs=self.read('cgroup.procs')
   try:verify_empty(events,procs);return True
   except PlacementBlocked:pass
   if clock()>=deadline_ns:raise CgroupBlocked('cgroup not empty by cleanup deadline')
   sleep(.01)
