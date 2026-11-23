"""Read-only exact mount-ID/device/inode binding, no provisioning."""
import os,stat,re
from guest_gate import required_mounts,parse_mounts,GateBlocked
DIR=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC
PATHS=('/','/run','/run/live/cow','/run/live/cow/upper','/run/live/cow/work','/run/live/lower','/run/live/media','/etc','/home')
def secure_directory(path):
 fd=os.open('/',DIR)
 try:
  for part in path.strip('/').split('/')if path!='/'else():
   n=os.open(part,DIR,dir_fd=fd);os.close(fd);fd=n
   s=os.fstat(fd)
   if s.st_uid!=0 or s.st_mode&0o022:raise GateBlocked('untrusted directory')
  return fd
 except BaseException:os.close(fd);raise

def fd_identity(fd):
 s=os.fstat(fd)
 with open('/proc/self/fdinfo/'+str(fd),encoding='ascii')as f:raw=f.read(4097)
 if len(raw)>4096:raise GateBlocked('fdinfo bound')
 ids=re.findall(r'^mnt_id:\s+([0-9]+)$',raw,re.M)
 if len(ids)!=1:raise GateBlocked('mount id unavailable')
 return {'mount_id':int(ids[0]),'dev':str(os.major(s.st_dev))+':'+str(os.minor(s.st_dev)),'inode':s.st_ino,'uid':s.st_uid,'mode':s.st_mode&0o7777}

def verify_observation(before,after,identities,pre_systemd=False):
 if before!=after:raise GateBlocked('mount table changed')
 result=required_mounts(before,pre_systemd=pre_systemd);rows=parse_mounts(before)
 if set(identities)!=set(PATHS):raise GateBlocked('directory identity set')
 bypoint={r['point']:r for r in rows}
 def same(path,mount):
  q=identities[path];m=bypoint[mount]
  if q['mount_id']!=m['id']or q['dev']!=m['dev']or q['uid']!=0 or q['mode']&0o022:raise GateBlocked('directory mount/device/owner mismatch')
 for p in ('/','/run','/run/live/cow','/run/live/lower','/run/live/media'):same(p,p)
 for p in ('/run/live/cow/upper','/run/live/cow/work'):same(p,'/run/live/cow')
 for p in ('/etc','/home'):same(p,'/')
 if len({identities[p]['inode']for p in ('/run/live/cow','/run/live/cow/upper','/run/live/cow/work')})!=3:raise GateBlocked('cow alias')
 if identities['/']['dev']==identities['/run/live/cow']['dev']:raise GateBlocked('overlay/cow alias')
 # Mount source IDs cannot be guessed from old pathname text. This candidate
 # requires init create paths at their final /run/live names before overlay.
 result.update({'directory_mount_ids_bound':True,'upper_work_device_inode_distinct':True,'effect_authorized':False})
 return result

def observe_live(pre_systemd=False):
 fds={}
 try:
  with open('/proc/self/mountinfo',encoding='ascii')as f:before=f.read(262145)
  for p in PATHS:fds[p]=secure_directory(p)
  identities={p:fd_identity(fd)for p,fd in fds.items()}
  with open('/proc/self/mountinfo',encoding='ascii')as f:after=f.read(262145)
  return verify_observation(before,after,identities,pre_systemd=pre_systemd)
 finally:
  for fd in fds.values():os.close(fd)
