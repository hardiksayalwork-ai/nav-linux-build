#!/usr/bin/python3 -IBS
"""Fixed synthetic user-session wrapper source. Not installed or invoked.

No shell, compositor, app, arbitrary argument or command execution. Fails closed
until the complete integration supplies root-bound config and startup identity.
"""
import os,sys,json,stat,fcntl,time
from pathlib import Path
USER='navtestuser';UID=1201;GID=1201
class Refuse(Exception):pass

def check_directory(path,uid):
 f=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  parts=path.split('/')[1:]
  for i,part in enumerate(parts):
   if not part or part in ('.','..'):raise Refuse('invalid path')
   n=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=f);os.close(f);f=n;s=os.fstat(f)
   if i<len(parts)-1:
    if s.st_uid!=0 or s.st_mode&0o022:raise Refuse('untrusted ancestor')
   elif s.st_uid!=uid or s.st_mode&0o7777!=0o700:raise Refuse('owned private directory required')
  return f
 except BaseException:os.close(f);raise

def fixed_probe_NOT_WIRED():
 if len(sys.argv)!=1 or os.getresuid()!=(UID,UID,UID) or os.getresgid()!=(GID,GID,GID) or set(os.getgroups())!={GID}:
  raise Refuse('fixed nonroot identity/arguments required')
 import pwd
 rows=[(r.pw_name,r.pw_uid,r.pw_gid,r.pw_dir)for r in pwd.getpwall()if r.pw_uid==UID or r.pw_name==USER]
 if rows!=[(USER,UID,GID,'/home/'+USER)]:raise Refuse('NSS identity alias/mismatch')
 runtime='/run/user/'+str(UID);home='/home/'+USER
 homefd=check_directory(home,UID);runfd=check_directory(runtime,UID)
 try:
  # Environment is rebuilt before any workload. The first milestone has no
  # D-Bus/display and does not launch arbitrary commands.
  os.environ.clear();os.environ.update({'HOME':home,'USER':USER,'LOGNAME':USER,
   'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','SHELL':'/bin/sh','XDG_RUNTIME_DIR':runtime})
  os.fchdir(homefd);os.umask(0o077)
  lock=os.open('nav-test-session.lock',os.O_CREAT|os.O_EXCL|os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=runfd)
  try:
   fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
   # Fixed one-shot harmless workload, bounded even if controller disappears.
   # Native controller must collect identity/scope and terminate this session;
   # natural timeout is not successful containment or logout acceptance.
   end=time.monotonic()+20
   while time.monotonic()<end:time.sleep(.1)
   return 74
  finally:os.close(lock)
 finally:os.close(homefd);os.close(runfd)

def main():
 # Source candidate for the fixed wrapper only. Controller independently pins
 # exact bytes before launch; current public native controller still refuses.
 for path in ('/usr','/usr/libexec','/usr/libexec/nav-user-session'):
  st=os.lstat(path)
  if stat.S_ISLNK(st.st_mode)or st.st_uid!=0 or st.st_mode&0o022:raise Refuse('untrusted wrapper path')
 return fixed_probe_NOT_WIRED()
if __name__=='__main__':
 try:raise SystemExit(main())
 except Refuse:raise SystemExit(78)
