"""First fixed HOSTONLYfixture scope delegation admission,read-only source.

Not general untrustedpayload proof. Requiresrootcontroller,childnobody,noother
untrustedrootprocess. Runtime factscannotbeestablishedbysourcefixtures.
"""
import os,stat
from pathlib import Path
from fd_group_admission import open_directory_chain
from filesystem_identity import require_type,CGROUP_MAGIC
class DelegationBlocked(Exception):pass

def inspect_parent(path):
 if os.geteuid()!=0:raise DelegationBlocked('firstfixturecontrollerrequiresroot')
 p=Path(path)
 if not p.is_absolute()or '..'in p.parts:raise DelegationBlocked('absolutecanonicalparent')
 # Fullcontrollerrootvisibilityandcgroupfsidentitymustbeverifiedseparately.
 fd=open_directory_chain(str(p))
 try:
  require_type(fd,CGROUP_MAGIC)
  st=os.fstat(fd)
  if st.st_uid!=0 or st.st_mode&0o022:raise DelegationBlocked('rootexclusiveparentrequired')
  for name in ('cgroup.procs','cgroup.subtree_control'):
   x=os.stat(name,dir_fd=fd,follow_symlinks=False)
   if not stat.S_ISREG(x.st_mode)or x.st_uid!=0 or x.st_mode&0o022:raise DelegationBlocked('controllerfilepermissions')
  ctr=os.open('cgroup.controllers',os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
  try:controllers=os.read(ctr,4096).decode().split()
  finally:os.close(ctr)
  if not {'memory','pids'}<=set(controllers):raise DelegationBlocked('memory+pidsdelegationrequired')
  return {'fd':os.dup(fd),'dev':st.st_dev,'ino':st.st_ino,'controllers':controllers,'first_fixture_only':True,'child_required_uid':65534,'general_noescape_proved':False}
 finally:os.close(fd)
