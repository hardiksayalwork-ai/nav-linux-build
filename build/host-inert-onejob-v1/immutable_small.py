"""Sealed immutable file descriptors for bounded small inputs.

Not used against real NAV bytes here. Large base ISO requires separately proved
read-only staging,mount and host access model;this helper does not solve disk.
"""
import os,fcntl,stat,hashlib
class SealBlocked(Exception):pass
SEALS=fcntl.F_SEAL_SEAL|fcntl.F_SEAL_SHRINK|fcntl.F_SEAL_GROW|fcntl.F_SEAL_WRITE

def seal_input(source_fd,expected_sha,expected_bytes,allocation_cap):
 if expected_bytes<1 or expected_bytes>allocation_cap:raise SealBlocked('allocation cap')
 st=os.fstat(source_fd)
 if not stat.S_ISREG(st.st_mode)or st.st_size!=expected_bytes:raise SealBlocked('input metadata')
 fd=os.memfd_create('nav-bound-input',os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING)
 try:
  h=hashlib.sha256();offset=0
  while offset<expected_bytes:
   b=os.pread(source_fd,min(1048576,expected_bytes-offset),offset)
   if not b:raise SealBlocked('short source')
   h.update(b);view=memoryview(b)
   while view:
    n=os.write(fd,view)
    if n<=0:raise SealBlocked('short write')
    view=view[n:]
   offset+=len(b)
  end=os.fstat(source_fd)
  attrs=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
  if attrs(st)!=attrs(end)or h.hexdigest()!=expected_sha:raise SealBlocked('changed source or digest')
  fcntl.fcntl(fd,fcntl.F_ADD_SEALS,SEALS)
  if fcntl.fcntl(fd,fcntl.F_GET_SEALS)&SEALS!=SEALS:raise SealBlocked('kernel seals absent')
  # Verify immutable snapshot,not just source while copying.
  h=hashlib.sha256();offset=0
  while offset<expected_bytes:
   b=os.pread(fd,min(1048576,expected_bytes-offset),offset);h.update(b);offset+=len(b)
  if h.hexdigest()!=expected_sha:raise SealBlocked('sealed snapshot digest')
  os.lseek(fd,0,os.SEEK_SET);return fd
 except BaseException:os.close(fd);raise
