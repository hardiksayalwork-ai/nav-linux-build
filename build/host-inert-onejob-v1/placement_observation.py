"""Controller-owned read-only stopped-child membership gate.

No stop/move/unfreeze/exec occurs here. Independent caller must create a stopped
child before untrusted code,hold its pidfd,move it,and enforce no-escape cgroup.
A valid observation alone is not durable placement or permission to resume.
"""
from pathlib import PurePosixPath
class PlacementBlocked(Exception):pass

def parse_stat(text):
 # comm can contain spaces and ')';the final ')' precedes state and fields.
 close=text.rfind(')');open_=text.find('(')
 if open_<1 or close<=open_:raise PlacementBlocked('invalid proc stat')
 try:
  pid=int(text[:open_].strip());rest=text[close+1:].split();state=rest[0];ppid=int(rest[1]);start=int(rest[19])
 except (ValueError,IndexError):raise PlacementBlocked('invalid proc stat fields')
 return {'pid':pid,'state':state,'ppid':ppid,'starttime':start}

def canonical_cgroup(path):
 if not path.startswith('/')or '\x00'in path or any(c in ('.','..')for c in path.split('/')):raise PlacementBlocked('invalid cgroup')
 return str(PurePosixPath(path))

def verify_stopped_membership(before_stat,after_stat,proc_cgroup,cgroup_procs,expected):
 before=parse_stat(before_stat);after=parse_stat(after_stat)
 if before!=after:raise PlacementBlocked('process identity/state changed')
 for k in ('pid','ppid','starttime'):
  if type(expected.get(k))is not int or before[k]!=expected[k]:raise PlacementBlocked('process identity mismatch')
 if before['state']not in ('T','t'):raise PlacementBlocked('child not stopped')
 lines=[s[3:]for s in proc_cgroup.splitlines()if s.startswith('0::')]
 target=canonical_cgroup(expected['cgroup'])
 if len(lines)!=1 or canonical_cgroup(lines[0])!=target:raise PlacementBlocked('proc membership mismatch')
 try:members=[int(x)for x in cgroup_procs.split()]
 except ValueError:raise PlacementBlocked('invalid controller cgroup membership')
 if members!=[before['pid']]:raise PlacementBlocked('dedicated cgroup must contain only stopped child')
 return {'observed_stopped_member':True,'pid':before['pid'],'starttime':before['starttime'],'cgroup':target,'resume_permission':False,'requires_pidfd_and_atomic_control':True,'no_escape_proved':False}

def observe(read_proc,read_cgroup,expected):
 # read_proc and read_cgroup are controller-owned handles,never child reports.
 pid=expected['pid'];before=read_proc(pid,'stat');membership=read_proc(pid,'cgroup');members=read_cgroup('cgroup.procs');after=read_proc(pid,'stat')
 return verify_stopped_membership(before,after,membership,members,expected)

def verify_empty(events,procs):
 pairs={}
 for row in events.splitlines():
  vals=row.split()
  if len(vals)!=2:raise PlacementBlocked('invalid cgroup events')
  if vals[0]in pairs:raise PlacementBlocked('duplicate cgroup event')
  pairs[vals[0]]=vals[1]
 if pairs.get('populated')!='0'or procs.strip():raise PlacementBlocked('cgroup not independently empty')
 return True
