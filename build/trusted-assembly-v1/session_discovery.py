"""One exact positive session discovery. Distinguish root PAM leader and user child."""
import os,re,stat,hashlib,time
from dataclasses import dataclass
from collector import proc_identity,uid_workloads,subtree,read_file,O_DIR,O_FILE,scope_snapshot
from manager_authority import sessions,units,AuthorityBlocked,manager_owners
from teardown import command
UID=1201;WRAPPER='/usr/libexec/nav-user-session'
DAEMON='/usr/sbin/nav-test-greetd';DAEMON_SHA='980455303b71eaf77b0920974b7deb02b1ebd5db717397e5b6f672d35740d302'
@dataclass
class Session:
 id:str;scope:str;object:str;unit_object:str;cgroup:str;leader:int;leader_start:int;child:int;child_start:int;scope_fd:int;scope_dev:int;scope_inode:int;leader_pidfd:int;child_pidfd:int;manager_owners:tuple

def detail(sid):
 raw=command(['/usr/bin/loginctl','show-session',sid,'--no-pager','--property=Id','--property=User','--property=Name','--property=Leader','--property=Scope','--property=State','--property=Service','--property=Class','--property=Type'])
 d={}
 for line in raw.splitlines():
  if '='not in line:raise AuthorityBlocked('session detail encoding')
  k,v=line.split('=',1)
  if k in d:raise AuthorityBlocked('session property duplicate')
  d[k]=v
 if set(d)!={'Id','User','Name','Leader','Scope','State','Service','Class','Type'}:raise AuthorityBlocked('session properties missing')
 if (d['Id'],d['User'],d['Name'],d['Scope'],d['Service'],d['Class'],d['Type'])!=(sid,'1201','navtestuser','session-'+sid+'.scope','nav-test-user','user-light','tty')or d['State']not in ('active','online')or not d['Leader'].isdigit():raise AuthorityBlocked('wrong session')
 return d

def proc_details(proc_fd,pid):
 f=os.open(str(pid),O_DIR,dir_fd=proc_fd)
 try:
  status=read_file(f,'status',16384);parents=re.findall(r'^PPid:\s+([0-9]+)$',status,re.M)
  if len(parents)!=1:raise AuthorityBlocked('parent identity')
  fd=os.open('cmdline',O_FILE,dir_fd=f)
  try:raw=os.read(fd,4097)
  finally:os.close(fd)
  if len(raw)>4096 or not raw.endswith(b'\0'):raise AuthorityBlocked('command bounded')
  return {'ppid':int(parents[0]),'argv':raw[:-1].split(b'\0'),'exe':os.readlink('exe',dir_fd=f)}
 finally:os.close(f)

def discover(owner,proc_fd,cgroup_fd):
 if owner.child is None or owner.child.poll()is not None:raise AuthorityBlocked('creator unavailable')
 owners=manager_owners()
 rows=[r for r in sessions()if r[1]==UID or r[2]=='navtestuser']
 if len(rows)!=1 or rows[0][1:3]!=(UID,'navtestuser'):raise AuthorityBlocked('unique test session required')
 sid,_,_,_,obj=rows[0];d=detail(sid);leader=int(d['Leader']);cg='/user.slice/user-1201.slice/'+d['Scope']
 root=proc_identity(proc_fd,leader);rp=proc_details(proc_fd,leader)
 parent=proc_identity(proc_fd,owner.child.pid)
 if parent['uids']!=(0,)*4:raise AuthorityBlocked('owned creator privilege changed')
 if root['uids']!=(0,)*4 or root['cgroup']!=cg or rp['ppid']!=owner.child.pid or rp['exe']!=DAEMON:raise AuthorityBlocked('PAM root worker lineage')
 # Exact daemon bytes already verified immediately prelaunch. Leader must be a
 # live same executable inode, not merely the same pathname string.
 a=os.stat('/proc/'+str(leader)+'/exe');b=os.stat('/proc/'+str(owner.child.pid)+'/exe')
 if (a.st_dev,a.st_ino)!=(b.st_dev,b.st_ino):raise AuthorityBlocked('daemon executable inode')
 candidates=uid_workloads(proc_fd,UID)
 if len(candidates)!=1:raise AuthorityBlocked('unique nonroot workload required')
 child=candidates[0];cp=proc_details(proc_fd,child['pid'])
 if child['uids']!=(UID,)*4 or child['cgroup']!=cg or cp['ppid']!=leader or cp['exe']!='/usr/bin/python3.14' or cp['argv']!=[b'/usr/bin/python3',b'-IBS',WRAPPER.encode()]:raise AuthorityBlocked('fixed wrapper child identity')
 u=units().get(d['Scope'])
 if u is None or u[2:5]!=('loaded','active','running')or u[7]!=0:raise AuthorityBlocked('active owned scope required')
 sf=subtree(cgroup_fd,cg.strip('/').split('/'));lp=cpfd=None
 try:
  st=os.fstat(sf);snap=scope_snapshot(cgroup_fd,cg.strip('/').split('/'))
  if set(snap['pids'])!={leader,child['pid']}:raise AuthorityBlocked('unexpected scope processes')
  lp=os.pidfd_open(leader);cpfd=os.pidfd_open(child['pid'])
  if proc_identity(proc_fd,leader)!=root or proc_identity(proc_fd,child['pid'])!=child or detail(sid)!=d or manager_owners()!=owners or proc_identity(proc_fd,owner.child.pid)!=parent:raise AuthorityBlocked('session changed during binding')
  return Session(sid,d['Scope'],obj,u[6],cg,leader,root['starttime'],child['pid'],child['starttime'],sf,st.st_dev,st.st_ino,lp,cpfd,owners)
 except BaseException:
  for f in (sf,lp,cpfd):
   if f is not None:os.close(f)
  raise
