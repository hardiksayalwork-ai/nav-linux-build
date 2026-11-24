"""Nofollow component traversal and FDrelative group admission source.

Read-only helpers not invoked on live cgroup paths in this task. Full-visible
cgroup2mount is a mandatory environment gate,not a deployability promise.
"""
import os,stat
from filesystem_identity import require_type,CGROUP_MAGIC
class AdmissionBlocked(Exception):pass

def open_directory_chain(path):
 if not isinstance(path,str)or not path.startswith('/')or any(x in ('.','..','')for x in path.split('/')[1:]):raise AdmissionBlocked('canonical absolute directory required')
 fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC|os.O_NOFOLLOW)
 try:
  for part in path.split('/')[1:]:
   new=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC|os.O_NOFOLLOW,dir_fd=fd);os.close(fd);fd=new
  return fd
 except BaseException:os.close(fd);raise

def full_cgroup_mount(mountinfo):
 rows=[x.split()for x in mountinfo.splitlines()if ' - cgroup2 'in x]
 if len(rows)!=1 or rows[0][3]!='/'or rows[0][4]!='/sys/fs/cgroup':raise AdmissionBlocked('full visible cgroup2mount required')
 return rows[0][0],rows[0][2]

def verify_group_fd(fd):
 # Enforced by class __init__,not optionalfactory convention.
 st=os.fstat(fd)
 if not stat.S_ISDIR(st.st_mode)or st.st_uid!=0 or st.st_mode&0o077:raise AdmissionBlocked('dedicated root0700group required')
 for name in ['cgroup.procs','cgroup.kill','cgroup.events','memory.max','memory.swap.max','pids.max']:
  s=os.stat(name,dir_fd=fd,follow_symlinks=False)
  if not stat.S_ISREG(s.st_mode)or s.st_dev!=st.st_dev or s.st_uid!=0 or s.st_mode&0o022:raise AdmissionBlocked('controller file identity/permissions')
 # This excludes ordinary fixture directories only with filesystem identity.
 # A future native fstatfs wrapper must bind CGROUP2_SUPER_MAGIC. Until then
 # construction cannotpassjustbecausea directorycontainslookalikefiles.
 require_type(fd,CGROUP_MAGIC)
 return True
