"""Read-only Linux resource collection. No cleanup,reclaim,spawn or mount.

Fail closed on incomplete cgroup ancestry,mount layouts or contradictory data.
This covers the current process,not some future runner or child namespace.
"""
from pathlib import Path
import os,re,time
class CollectionBlocked(Exception):pass

def memory_info(text):
 values={}
 for line in text.splitlines():
  m=re.fullmatch(r'(MemTotal|MemAvailable):\s+(\d+) kB',line)
  if m:values[m[1]]=int(m[2])*1024
 if not 0<values.get('MemAvailable',0)<=values.get('MemTotal',0):raise CollectionBlocked('missing/invalid physical memory')
 return values

def unified_path(text):
 matches=[line[3:]for line in text.splitlines()if line.startswith('0::')]
 if len(matches)!=1:raise CollectionBlocked('unified cgroup required')
 p=matches[0]
 if not p.startswith('/')or any(c in ('.','..')for c in p.split('/')):raise CollectionBlocked('invalid cgroup path')
 return p

def ancestry(path):
 p=Path(path);result=[]
 while True:
  result.append(p)
  if p==Path('/'):return result
  p=p.parent

def effective_memory(physical,cgroup_path,read):
 # For each ancestor,its current includes siblings charged to that ancestor.
 # Its remaining allowance therefore caps this process's additional use.
 headroom=physical['MemAvailable'];limits=[]
 for p in ancestry(cgroup_path):
  limit=read(str(p/'memory.max'));usage=read(str(p/'memory.current'))
  # Unified root memory controller files may be absent by kernel design.
  if p==Path('/')and limit is None and usage is None:continue
  if limit is None or usage is None:raise CollectionBlocked('incomplete cgroup ancestor')
  try:used=int(usage)
  except ValueError:raise CollectionBlocked('invalid cgroup usage')
  if used<0:raise CollectionBlocked('negative usage')
  if limit.strip()=='max':limits.append({'path':str(p),'limit':None,'current':used});continue
  try:cap=int(limit)
  except ValueError:raise CollectionBlocked('invalid cgroup limit')
  if cap<=0:raise CollectionBlocked('invalid cgroup cap')
  left=max(0,cap-used);headroom=min(headroom,left);limits.append({'path':str(p),'limit':cap,'current':used,'remaining':left})
 # Admission interface uses a synthetic effective cap with usage0,clearly
 # labeled;not an assertion all ancestors charge usage identically.
 return {'effective_memory_limit_bytes':headroom,'effective_memory_usage_bytes':0,'cgroup_ancestor_limits':limits,'effective_headroom_not_raw_cap':True}

def collect(disk_path,proc=Path('/proc'),cgroot=Path('/sys/fs/cgroup')):
 # Resolve actual controller root mapping,not a guessed /user path.
 # This conservative implementation only supports a full visible unified root.
 mounts=(proc/'self/mountinfo').read_text().splitlines()
 matches=[m.split()for m in mounts if ' - cgroup2 'in m]
 if len(matches)!=1:raise CollectionBlocked('single visible cgroup2 mount required')
 m=matches[0]
 if m[3]!='/'or m[4]!=str(cgroot):raise CollectionBlocked('cgroup namespace root mapping unproved')
 physical=memory_info((proc/'meminfo').read_text());path=unified_path((proc/'self/cgroup').read_text())
 def read(p):
  f=cgroot/p.lstrip('/')
  try:return f.read_text().strip()
  except FileNotFoundError:return None
 x=effective_memory(physical,path,read);v=os.statvfs(disk_path)
 x.update({'host_available_bytes':physical['MemAvailable'],'physical_total_bytes':physical['MemTotal'],'disk_available_bytes':v.f_bavail*v.f_frsize,'disk_device':os.stat(disk_path).st_dev,'cgroup_path':path,'collected_monotonic_ns':time.monotonic_ns(),'scope':'CURRENT_PROCESS_POINT_IN_TIME_NOT_LAUNCH_PERMISSION'})
 return x
