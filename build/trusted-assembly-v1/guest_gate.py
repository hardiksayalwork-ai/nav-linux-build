"""Strict read-only guest mount/source gate, synthetic fixtures only tested.

Verifies necessary structural conditions, not authenticated VM/image identity.
Host launch receipt must independently bind image/kernel/initramfs and namespaces.
"""
import re
class GateBlocked(Exception):pass

def decode(s):
 # proc mountinfo escapes these bytes; unknown escapes are rejected.
 def sub(m):
  if m.group(0)not in ('\\040','\\011','\\012','\\134'):raise GateBlocked('mount escape')
  return chr(int(m.group(0)[1:],8))
 return re.sub(r'\\[0-9]{3}',sub,s)

def parse_mounts(text):
 if len(text)>262144:raise GateBlocked('mountinfo limit')
 rows=[]
 for line in text.splitlines():
  parts=line.split(' - ')
  if len(parts)!=2:raise GateBlocked('mount separator')
  a,b=parts[0].split(),parts[1].split()
  if len(a)<6 or len(b)!=3:raise GateBlocked('mount fields')
  if not a[0].isdigit()or not a[1].isdigit()or not re.fullmatch(r'[0-9]+:[0-9]+',a[2]):raise GateBlocked('mount ids')
  rows.append({'id':int(a[0]),'parent':int(a[1]),'dev':a[2],'root':decode(a[3]),'point':decode(a[4]),
   'options':set(a[5].split(',')),'fs':b[0],'source':decode(b[1]),'super':set(b[2].split(','))})
 if len(rows)>512 or len({r['id']for r in rows})!=len(rows):raise GateBlocked('mount count/id')
 return rows

def required_mounts(text,pre_systemd=False):
 rows=parse_mounts(text)
 def exact(point,fs,options=()):
  r=[r for r in rows if r['point']==point]
  if len(r)!=1 or r[0]['fs']!=fs or not set(options)<=r[0]['options']:raise GateBlocked('required mount mismatch')
  return r[0]
 root=exact('/','overlay',('rw',));cow=exact('/run/live/cow','tmpfs',('rw',));run=exact('/run','tmpfs',('rw','nosuid','nodev'));exact('/proc','proc')
 if not pre_systemd:exact('/sys/fs/cgroup','cgroup2')
 exact('/run/live/lower','squashfs',('ro',));exact('/run/live/media','iso9660',('ro',))
 kv={}
 for item in root['super']:
  if '='in item:
   k,v=item.split('=',1);kv[k]=decode(v)
 if kv.get('upperdir')!='/run/live/cow/upper' or kv.get('workdir')!='/run/live/cow/work' or kv.get('lowerdir')!='/run/live/lower':
  # Moved mounts sometimes retain old /cow upperdir option strings. Do not
  # guess equivalence: a reviewed mount-ID/source relation must establish it.
  raise GateBlocked('overlay backing relationship unresolved')
 for r in rows:
  if r['point'] not in ('/','/run') and any(r['point']==p or r['point'].startswith(p+'/')for p in ('/etc','/home','/run/nav-test')):
   raise GateBlocked('unexpected account/home/test mount')
 return {'status':'necessary-mount-structure-observed','root_mount':root['id'],'cow_mount':cow['id'],
  'run_mount':run['id'],'host_identity_bound':False,'effect_authorized':False}
