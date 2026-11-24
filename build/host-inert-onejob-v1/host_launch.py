"""Bound regular ELF input only. No NAV or guest inputs."""
import os,hashlib,pathlib,stat
class LaunchBlocked(Exception):pass

def open_bound(path,digest,size=None):
 p=pathlib.Path(path)
 if not p.is_absolute():raise LaunchBlocked('absolute host input required')
 f=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:
  for c in p.parts[1:-1]:
   n=os.open(c,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=f);os.close(f);f=n
  fd=os.open(p.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=f)
 finally:os.close(f)
 try:
  st=os.fstat(fd)
  if not stat.S_ISREG(st.st_mode)or size is not None and st.st_size!=size:raise LaunchBlocked('host input metadata')
  h=hashlib.sha256()
  while True:
   b=os.read(fd,1048576)
   if not b:break
   h.update(b)
  end=os.fstat(fd)
  if (st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns,st.st_ctime_ns)!=(end.st_dev,end.st_ino,end.st_size,end.st_mtime_ns,end.st_ctime_ns)or h.hexdigest()!=digest:raise LaunchBlocked('host input changed')
  os.lseek(fd,0,os.SEEK_SET);return fd
 except BaseException:os.close(fd);raise
