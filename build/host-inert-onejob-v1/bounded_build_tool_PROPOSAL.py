"""Bounded compile/readelf subprocess adapter SOURCE,notinvoked.

Onlyreviewedabsolutecompiler/toolsargv;noexecutedbuildoutputs permitted.
Directchildsessionkill+waitmandatory;generaldescendantnoescapeNOTproved.
"""
import os,signal,subprocess,selectors,time
class ToolBlocked(Exception):pass

def bounded_tool(argv,seconds=60,limit=1024*1024):
 if not argv or not os.path.isabs(argv[0])or seconds>60 or limit>1024*1024:raise ToolBlocked('fixedtoolbounds')
 p=None;sel=selectors.DefaultSelector();data={'stdout':bytearray(),'stderr':bytearray()};why=None
 try:
  p=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env={'PATH':'/usr/bin:/bin','LC_ALL':'C'},close_fds=True,start_new_session=True)
  for n in data:
   f=getattr(p,n);os.set_blocking(f.fileno(),False);sel.register(f,selectors.EVENT_READ,n)
  deadline=time.monotonic()+seconds
  while sel.get_map():
   if time.monotonic()>=deadline:why='tooltimeout';break
   for key,_ in sel.select(.05):
    try:b=os.read(key.fileobj.fileno(),65536)
    except BlockingIOError:continue
    if not b:sel.unregister(key.fileobj);continue
    remain=limit-sum(len(v)for v in data.values());data[key.data].extend(b[:remain])
    if len(b)>=remain:why='tooldiagnosticcap';break
   if why:break
  if why:raise ToolBlocked(why)
  left=deadline-time.monotonic()
  if left<=0:raise ToolBlocked('tooltimeout')
  status=p.wait(timeout=left)
  return {'returncode':status,'stdout':bytes(data['stdout']),'stderr':bytes(data['stderr'])}
 finally:
  sel.close()
  if p is not None:
   # Sessionprocessgroup mayhavecompilerdescendantsafterrootexit;alwayskill.
   try:os.killpg(p.pid,signal.SIGKILL)
   except ProcessLookupError:pass
   try:p.wait(timeout=2)
   except subprocess.TimeoutExpired:raise ToolBlocked('toolnotreaped')
   p.stdout.close();p.stderr.close()
