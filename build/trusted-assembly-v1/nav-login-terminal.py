#!/usr/bin/python3 -IBS
"""Fixed-command terminal prototype. Source/fixture only, not native accepted.
No PAM, session execution, camera or account operations. No CLI override.
"""
import os,socket,struct,json,termios,signal,select,time,stat
COMMAND='/usr/libexec/nav-user-session'
class Failure(Exception):pass
class Unknown(Failure):pass

def obj(pairs):
 d={}
 for k,v in pairs:
  if k in d:raise Failure('duplicate key')
  d[k]=v
 return d

def parse(b):
 if not 0<len(b)<=16384:raise Failure('frame size')
 try:r=json.loads(b.decode('utf8'),object_pairs_hook=obj,parse_constant=lambda x:(_ for _ in ()).throw(Failure('nonfinite')))
 except (ValueError,UnicodeError):raise Failure('json')
 if type(r)!=dict:raise Failure('object required')
 kind=r.get('type')
 if kind=='success' and set(r)=={'type'}:return r
 if kind=='error' and set(r)=={'type','error_type','description'} and r['error_type']in ('error','auth_error') and type(r['description'])is str and len(r['description'])<=4096:return r
 if kind=='auth_message' and set(r)=={'type','auth_message_type','auth_message'} and r['auth_message_type']in ('visible','secret','info','error') and type(r['auth_message'])is str and len(r['auth_message'])<=4096:return r
 raise Failure('response schema')

class Client:
 def __init__(self,sock,deadline):self.s=sock;self.deadline=deadline;self.started=False
 def remaining(self):
  n=self.deadline-time.monotonic()
  if n<=0:raise Failure('deadline')
  return min(10,n)
 def exchange(self,request,start=False):
  try:
   body=json.dumps(request,separators=(',',':'),ensure_ascii=True).encode();self.s.settimeout(self.remaining())
   if len(body)>16384:raise Failure('request size')
   if start:self.started=True
   self.s.sendall(struct.pack('=I',len(body))+body)
   def exact(n):
    b=bytearray()
    while len(b)<n:
     self.s.settimeout(self.remaining());x=self.s.recv(n-len(b))
     if not x:raise Failure('eof')
     b.extend(x)
    return bytes(b)
   size=struct.unpack('=I',exact(4))[0]
   if not 0<size<=16384:raise Failure('response size')
   return parse(exact(size))
  except (OSError,Failure,ValueError,struct.error) as e:
   if self.started:raise Unknown('uncertain handoff')from None
   raise Failure('protocol failure')from None

def safe(s):return ''.join(c for c in s if c.isprintable())[:512]
class Terminal:
 def __init__(self,fd=0,out=1):self.fd=fd;self.out=out;self.saved=None
 def __enter__(self):
  if not os.isatty(self.fd)or not os.isatty(self.out):raise Failure('interactive terminal required')
  self.saved=termios.tcgetattr(self.fd);return self
 def __exit__(self,*args):
  if self.saved is not None:termios.tcsetattr(self.fd,termios.TCSANOW,self.saved)
 def write(self,s):os.write(self.out,s.encode('utf8'))
 def line(self,prompt,secret,deadline):
  attrs=list(self.saved);attrs[6]=list(self.saved[6]);attrs[3]|=termios.ICANON
  if secret:attrs[3]&=~(termios.ECHO|termios.ECHONL)
  termios.tcflush(self.fd,termios.TCIFLUSH);termios.tcsetattr(self.fd,termios.TCSANOW,attrs);self.write(prompt)
  if not select.select([self.fd],[],[],max(0,deadline-time.monotonic()))[0]:raise Failure('input deadline')
  raw=bytearray(os.read(self.fd,1026))
  try:
   if not raw.endswith(b'\n')or len(raw)>1025 or b'\n'in raw[:-1]:raise Failure('input limit/typeahead')
   answer=raw[:-1].decode('utf8','strict')
   if '\0'in answer or '\r'in answer:raise Failure('input control')
   if secret:self.write('\n')
   return answer
  finally:
   for i in range(len(raw)):raw[i]=0


def transaction(client,tty):
 username=tty.line(USERNAME,False,client.deadline)
 if not username or len(username)>32 or not username.isascii()or not all(c.isalnum()or c in '_-'for c in username)or username[0]in '-!':raise Failure('account syntax')
 # Reset incomplete previous authentication only before creating any new one.
 r=client.exchange({'type':'cancel_session'})
 if r!={'type':'success'}:raise Failure('reset rejected')
 r=client.exchange({'type':'create_session','username':username})
 for _ in range(16):
  if r['type']=='error':tty.write(DENIED+'\n');return 70
  if r['type']=='success':break
  typ=r['auth_message_type'];prompt=safe(r['auth_message'])
  if typ in ('visible','secret'):answer=tty.line(PASSWORD if typ=='secret' else prompt+': ',typ=='secret',client.deadline)
  else:tty.line(prompt+'\nPress Enter: ',False,client.deadline);answer=None
  r=client.exchange({'type':'post_auth_message_response','response':answer});answer=None
 else:raise Failure('prompt count')
 if tty.line(START,False,client.deadline)!='START':return 70
 r=client.exchange({'type':'start_session','cmd':[COMMAND],'env':[]},start=True)
 if r['type']=='success':tty.write(SCHEDULED+'\n');return 0
 if r['type']=='error':tty.write(DENIED+'\n');return 70
 raise Unknown('unexpected start reply')

def main():
 import sys
 global USERNAME,START,DENIED,SCHEDULED,UNCERTAIN,PASSWORD
 # Root-owned shared literal module path; refuse writable/symlink ancestors.
 for path in ('/usr','/usr/libexec','/usr/libexec/nav-login','/usr/libexec/nav-login/prompt_literals.py'):
  st=os.lstat(path)
  if stat.S_ISLNK(st.st_mode) or st.st_uid!=0 or st.st_mode&0o022:raise SystemExit(78)
 sys.path.insert(0,'/usr/libexec/nav-login')
 from prompt_literals import USERNAME,START,DENIED,SCHEDULED,UNCERTAIN,PASSWORD

 if len(sys.argv)!=1:return 64
 sock=None;client=None;handlers={}
 def stop(signum,frame):raise Unknown('signal after start')if client and client.started else Failure('signal')
 try:
  for sig in (signal.SIGINT,signal.SIGTERM,signal.SIGHUP,signal.SIGQUIT):handlers[sig]=signal.signal(sig,stop)
  path=os.environ.get('GREETD_SOCK','')
  import re
  if not re.fullmatch(r'/run/greetd-[1-9][0-9]*\.sock',path):raise Failure('socket path')
  st=os.lstat(path)
  if not stat.S_ISSOCK(st.st_mode)or st.st_uid!=os.getuid():raise Failure('socket owner/type')
  sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);sock.settimeout(10);sock.connect(path)
  pid,uid,gid=struct.unpack('3i',sock.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,struct.calcsize('3i')))
  if uid!=0 or pid<=0:raise Failure('root peer required')
  client=Client(sock,time.monotonic()+45)
  with Terminal()as tty:return transaction(client,tty)
 except Unknown:
  if os.isatty(1):os.write(1,(UNCERTAIN+'\n').encode())
  return 75
 except (Failure,OSError,ValueError,UnicodeError):return 75 if client and client.started else 70
 finally:
  if sock:sock.close()
  for sig,handler in handlers.items():signal.signal(sig,handler)
if __name__=='__main__':raise SystemExit(main())
