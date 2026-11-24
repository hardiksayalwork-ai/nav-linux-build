"""FDidentitysnapshotsource. Actualcontrollerusageunrun;purefixturesonly."""
import os,stat
class FDSnapshotBlocked(Exception):pass

def snapshot():
 result={}
 for n in os.listdir('/proc/self/fd'):
  if not n.isdigit():continue
  fd=int(n)
  try:s=os.fstat(fd);flags=__import__('fcntl').fcntl(fd,__import__('fcntl').F_GETFD)
  except OSError:continue
  result[fd]=(s.st_dev,s.st_ino,s.st_mode,s.st_rdev,flags)
 return result

def verify_closed(before,after):
 if before!=after:raise FDSnapshotBlocked('FDidentityorallowlistchanged')
 return {'fd_identity_table_restored':True,'single_thread_no_async_opener_assumed':True}
