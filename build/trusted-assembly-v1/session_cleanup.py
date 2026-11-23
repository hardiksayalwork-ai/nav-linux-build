"""Bounded cleanup after frozen creator, independent manager/cgroup/proc evidence."""
import os,time,select
from collector import proc_identity,uid_workloads,scope_snapshot,subtree,Unverified
from manager_authority import sessions,scope_authority,AuthorityBlocked,manager_owners
from session_discovery import detail
from teardown import command

def revalidate(s,owner,proc_fd):
 if not getattr(owner,'creator_frozen',False):raise AuthorityBlocked('creator not quiesced')
 if manager_owners()!=s.manager_owners:raise AuthorityBlocked('manager authority changed')
 d=detail(s.id)
 if int(d['Leader'])!=s.leader or d['Scope']!=s.scope:raise AuthorityBlocked('session changed')
 for pid,start,uids in ((s.leader,s.leader_start,(0,)*4),(s.child,s.child_start,(1201,)*4)):
  p=proc_identity(proc_fd,pid)
  if p['starttime']!=start or p['uids']!=uids or p['cgroup']!=s.cgroup:raise AuthorityBlocked('owned process changed')
 st=os.fstat(s.scope_fd)
 if(st.st_dev,st.st_ino)!=(s.scope_dev,s.scope_inode):raise AuthorityBlocked('scope reference changed')

def terminate_once(s,owner,proc_fd):
 revalidate(s,owner,proc_fd)
 if getattr(owner,'termination_requested',False):raise AuthorityBlocked('duplicate termination forbidden')
 owner.termination_requested=True
 command(['/usr/bin/busctl','--system','--timeout=3s','call','org.freedesktop.login1','/org/freedesktop/login1','org.freedesktop.login1.Manager','TerminateSession','s',s.id])
 return {'termination_requested':True,'session_clean':False}

def pidfd_exited(fd):
 p=select.poll();p.register(fd,select.POLLIN);return bool(p.poll(0))
def observation(s,owner,proc_fd,cgroup_fd):
 if not getattr(owner,'creator_frozen',False)or not getattr(owner,'termination_requested',False):raise AuthorityBlocked('lifetime not quiesced')
 # Retain stopped creator until evidence closes. It cannot re-enter event loop.
 if owner.child.poll()is not None:raise AuthorityBlocked('creator lifetime unexpectedly ended')
 if manager_owners()!=s.manager_owners:raise AuthorityBlocked('manager authority changed')
 manager=scope_authority(s.scope,s.unit_object)
 if any(r[0]==s.id or r[1]==1201 or r[2]=='navtestuser'for r in sessions()):raise AuthorityBlocked('session still present or replacement')
 if uid_workloads(proc_fd,1201):raise AuthorityBlocked('test UID workload survives')
 if not pidfd_exited(s.leader_pidfd)or not pidfd_exited(s.child_pidfd):raise AuthorityBlocked('tracked process alive')
 path=s.cgroup.strip('/').split('/')
 try:fd=subtree(cgroup_fd,path)
 except FileNotFoundError:
  # Absence alone never passes: prior open scope identity + manager successful
  # full inventory absence/inactivity + no live references and UID required.
  if manager['state']not in ('authoritatively-not-listed','authoritatively-inactive'):raise AuthorityBlocked('scope absence unverified')
  st=os.fstat(s.scope_fd)
  if(st.st_dev,st.st_ino)!=(s.scope_dev,s.scope_inode)or st.st_nlink!=0:raise AuthorityBlocked('prior scope removal not verified')
  state='removed-prior-scope'
 else:
  try:
   st=os.fstat(fd)
   if(st.st_dev,st.st_ino)!=(s.scope_dev,s.scope_inode):raise AuthorityBlocked('scope replaced')
  finally:os.close(fd)
  snap=scope_snapshot(cgroup_fd,path)
  if not snap['empty']:raise AuthorityBlocked('recursive scope populated')
  state='same-scope-recursively-empty'
 if manager_owners()!=s.manager_owners:raise AuthorityBlocked('manager authority changed after observation')
 return {'scope':state,'manager':manager['state'],'uid_absent':True,'tracked_pidfds_exited':True,'creator_stopped':True}

def await_cleanup(s,owner,proc_fd,cgroup_fd):
 deadline=time.monotonic()+5;last=None;since=None
 while time.monotonic()<deadline:
  try:now=observation(s,owner,proc_fd,cgroup_fd)
  except (OSError,Unverified,AuthorityBlocked):last=None;since=None;time.sleep(.05);continue
  if now!=last:last=now;since=time.monotonic()
  elif time.monotonic()-since>=.3:return {'status':'post-quiescence-stable-clean-observed','evidence':now,'native_acceptance':False,'atomic_absence_proved':False,'fresh_login_permitted':False}
  time.sleep(.05)
 raise AuthorityBlocked('cleanup evidence deadline, dispose VM, no success')
