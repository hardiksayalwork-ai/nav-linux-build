"""Concrete narrow login1 teardown source, not invoked or launch-wired.

Only exact owned session binding accepted. Native DBus/namespace/ownership and
quiescence remain unverified. No generic command/execute callback is supported.
"""
import subprocess,re,time,os
from dataclasses import dataclass
class TeardownBlocked(Exception):pass
@dataclass(frozen=True)
class Target:
 uid:int
 session:str
 scope:str
 leader:int
 starttime:int
 cgroup:str
 dev:int
 inode:int

def command(argv):
 p=subprocess.run(argv,stdin=subprocess.DEVNULL,capture_output=True,timeout=3,
  close_fds=True,env={'PATH':'/usr/bin:/bin','LC_ALL':'C','HOME':'/nonexistent'})
 if p.returncode or len(p.stdout)>8192 or len(p.stderr)>4096:raise TeardownBlocked('native read/call failed')
 return p.stdout.decode('ascii','strict')

def read_session(sid):
 if not re.fullmatch(r'[A-Za-z0-9_-]{1,64}',sid):raise TeardownBlocked('session id')
 raw=command(['/usr/bin/loginctl','show-session',sid,'--no-pager','--property=Id','--property=User','--property=Leader','--property=Scope','--property=State'])
 fields={}
 for line in raw.splitlines():
  if '='not in line:raise TeardownBlocked('malformed session')
  k,v=line.split('=',1)
  if k in fields:raise TeardownBlocked('duplicate field')
  fields[k]=v
 if set(fields)!={'Id','User','Leader','Scope','State'}:raise TeardownBlocked('incomplete session')
 return fields

def compare_current(t,proc_fd,cgroup_fd):
 from collector import proc_identity,subtree
 if type(t)!=Target or any(type(x)!=int or x<=0 for x in(t.uid,t.leader,t.starttime,t.dev,t.inode)):
  raise TeardownBlocked('positive nonroot identity required')
 if not re.fullmatch(r'[A-Za-z0-9_-]{1,64}',t.session)or t.scope!='session-'+t.session+'.scope':raise TeardownBlocked('session scope mismatch')
 expected='/user.slice/user-'+str(t.uid)+'.slice/'+t.scope
 if t.cgroup!=expected:raise TeardownBlocked('wrong user slice')
 row=read_session(t.session)
 if (row['Id'],row['User'],row['Leader'],row['Scope'])!=(t.session,str(t.uid),str(t.leader),t.scope):raise TeardownBlocked('session ownership changed')
 p=proc_identity(proc_fd,t.leader)
 if p['starttime']!=t.starttime or p['uids']!=(0,)*4 or p['cgroup']!=t.cgroup:raise TeardownBlocked('root PAM leader binding changed')
 fd=subtree(cgroup_fd,t.cgroup.strip('/').split('/'))
 try:
  s=os.fstat(fd)
  if(s.st_dev,s.st_ino)!=(t.dev,t.inode):raise TeardownBlocked('scope identity changed')
 finally:os.close(fd)
 return row

def terminate_NOT_WIRED(t,proc_fd,cgroup_fd):
 # Necessary immediate checks, not atomic mutation authorization. The native
 # controller must ensure no competing actor can replace/reuse the session.
 compare_current(t,proc_fd,cgroup_fd)
 command(['/usr/bin/busctl','--system','--timeout=3s','call','org.freedesktop.login1',
  '/org/freedesktop/login1','org.freedesktop.login1.Manager','TerminateSession','s',t.session])
 return {'status':'termination-request-returned','session_clean':False,
  'requires_authoritative_scope_inactive':True,'requires_recursive_empty':True,
  'automatic_retry':False}

def teardown():
 raise TeardownBlocked('exclusive lifetime/native provenance/quiescence integration not reviewed')
