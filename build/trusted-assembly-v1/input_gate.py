"""Read-only exact runtime/source verifier. Not host-launch authority."""
import os,stat,hashlib,json,pathlib
class InputBlocked(Exception):pass

def regular_bytes(path,digest,size):
 fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  parts=path.strip('/').split('/')
  for p in parts[:-1]:
   n=os.open(p,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd);os.close(fd);fd=n;s=os.fstat(fd)
   if s.st_uid!=0 or s.st_mode&0o022:raise InputBlocked('writable input ancestor')
  f=os.open(parts[-1],os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
  try:
   before=os.fstat(f)
   if not stat.S_ISREG(before.st_mode)or before.st_uid!=0 or before.st_mode&0o022 or before.st_size!=size:raise InputBlocked('input metadata')
   h=hashlib.sha256();count=0
   while True:
    b=os.read(f,65536)
    if not b:break
    count+=len(b)
    if count>size:raise InputBlocked('input grew')
    h.update(b)
   after=os.fstat(f)
   if count!=size or h.hexdigest()!=digest or (before.st_dev,before.st_ino,before.st_mtime_ns,before.st_ctime_ns)!=(after.st_dev,after.st_ino,after.st_mtime_ns,after.st_ctime_ns):raise InputBlocked('input byte/race')
  finally:os.close(f)
 finally:os.close(fd)

def runtime_inputs(binding):
 # Runtime canonical file paths and image symlink mapping have separate checks.
 # Symlink parent aliases are allowed ONLY for those exact recorded links.
 for path,target in binding['symlinks'].items():
  if os.readlink(path)!=target or os.lstat(path).st_uid!=0:raise InputBlocked('runtime symlink')
 for path,row in binding['files'].items():regular_bytes(path,row['sha256'],row['bytes'])
 return {'all_bound_runtime_bytes_observed':True,'native_import_success':False,'effect_authorized':False}
