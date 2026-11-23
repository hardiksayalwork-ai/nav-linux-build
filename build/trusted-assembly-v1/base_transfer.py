#!/usr/bin/env python3
"""Bounded exact base-asset transfer. Never retries metadata, HTTP, auth or hash failures."""
import os,json,pathlib,hashlib,time,socket,http.client,urllib.request,urllib.error,signal
from urllib.parse import urlsplit
API='https://api.github.com/repos/hardiksayalwork-ai/nav-linux-build'
RELEASE=453724002
ASSET=775726636
SIZE=1734334464
SHA='09cf7f18940f8f84b9301050d98ee004a401a212a18c1abbadb18a547db83467'
HOSTS={'release-assets.githubusercontent.com','objects.githubusercontent.com','github-releases.githubusercontent.com'}
class Failure(Exception):pass
class Retryable(Exception):pass
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*a):return None
def is_retryable(e):
 if isinstance(e,urllib.error.HTTPError):return False
 if isinstance(e,urllib.error.URLError):e=e.reason
 return isinstance(e,(ConnectionResetError,socket.timeout,TimeoutError,http.client.IncompleteRead))
def metadata(x):
 if type(x)is not dict or x.get('id')!=RELEASE or x.get('draft')is not True or x.get('published_at')is not None or x.get('tag_name')!='nav-development-packaging-44910263539':raise Failure('metadata')
 rows=x.get('assets')
 if type(rows)is not list:raise Failure('metadata')
 a=[a for a in rows if type(a)is dict and a.get('id')==ASSET]
 if len(a)!=1:raise Failure('metadata')
 a=a[0]
 if a.get('name')!='NAV-development-001.iso'or type(a.get('size'))is not int or a['size']!=SIZE or a.get('digest')!='sha256:'+SHA or a.get('state')!='uploaded':raise Failure('metadata')
 return True
def signed_url(url):
 p=urlsplit(url)
 if p.scheme!='https'or p.hostname not in HOSTS or p.netloc!=p.hostname or p.username or p.password or p.fragment or not p.path.startswith('/'):raise Failure('redirect')
 return url
def transfer(token,destination,opener=None,clock=time.monotonic):
 # A maximum of two full-body attempts within one 240-second budget.
 # No partial resume/Range acceptance and no overwrite of an existing final file.
 if type(token)is not str or not token:raise Failure('auth')
 destination=pathlib.Path(destination);part=destination.with_suffix(destination.suffix+'.part')
 if destination.exists()or part.exists():raise Failure('existing_path')
 opener=opener or urllib.request.build_opener(NoRedirect())
 deadline=clock()+240
 def budget():
  left=deadline-clock()
  if left<=0:raise Failure('deadline')
  return min(30,left)
 def req(url,binary=False,auth=True):
  headers={'Accept':'application/octet-stream'if binary else'application/vnd.github+json','User-Agent':'NAV-exact-base-transfer','X-GitHub-Api-Version':'2022-11-28','Cache-Control':'no-store'}
  if auth:
   if url not in (API+'/releases/'+str(RELEASE),API+'/releases/assets/'+str(ASSET)):raise Failure('scope')
   headers['Authorization']='Bearer '+token
  else:signed_url(url)
  return opener.open(urllib.request.Request(url,headers=headers),timeout=budget())
 def check_metadata():
  try:
   with req(API+'/releases/'+str(RELEASE))as r:
    if r.status!=200 or r.headers.get('Link'):raise Failure('metadata')
    b=r.read(1048577)
    if len(b)>1048576:raise Failure('metadata')
    def unique(pairs):
     out={}
     for k,v in pairs:
      if k in out:raise Failure('metadata')
      out[k]=v
     return out
    metadata(json.loads(b,object_pairs_hook=unique))
  except Exception:raise Failure('metadata')from None
 def asset():
  try:return req(API+'/releases/assets/'+str(ASSET),True)
  except urllib.error.HTTPError as e:
   if e.code not in (301,302,303,307,308):raise Failure('http')from None
   # Exactly one GitHub API-to-allowlisted-signed-host redirect. No token forwarded.
   url=signed_url(e.headers.get('Location',''))
   try:return req(url,True,False)
   except urllib.error.HTTPError:raise Failure('http')from None
 check_metadata()
 for attempt in (1,):
  try:
   h=hashlib.sha256();count=0
   with asset()as r:
    if r.status!=200 or r.headers.get('Content-Range')or r.headers.get('Content-Encoding')not in (None,'identity'):raise Failure('response')
    length=r.headers.get('Content-Length')
    if length is None or not length.isdigit()or int(length)!=SIZE:raise Failure('length')
    fd=os.open(part,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb')as f:
     while True:
      budget();b=r.read(min(1048576,SIZE-count+1))
      if not b:break
      count+=len(b)
      if count>SIZE:raise Failure('oversize')
      f.write(b);h.update(b)
     f.flush();os.fsync(f.fileno())
   if count!=SIZE:raise Retryable('incomplete_body')
   if h.hexdigest()!=SHA:raise Failure('hash')
   check_metadata();budget();part.chmod(0o444);os.link(part,destination);part.unlink()
   return {'asset':ASSET,'bytes':count,'sha256':SHA,'attempts':attempt,'draft':True}
  except Exception as e:
   if part.exists():part.unlink()
   retry=isinstance(e,Retryable)or is_retryable(e)
   if not retry or attempt==1:raise Failure('transport'if retry else'terminal')from None
   budget()
 raise Failure('terminal')
def main():
 def alarm(*args):raise Failure('deadline')
 signal.signal(signal.SIGALRM,alarm);signal.alarm(240)
 try:r=transfer(os.environ.get('GH_TOKEN',''),'/tmp/NAV-development-001.iso')
 except Exception:raise SystemExit('NAV_BASE_TRANSFER_FAILED_NO_RAW_DIAGNOSTIC')from None
 print('NAV_BASE_EXACT_VERIFIED '+json.dumps(r,sort_keys=True))
if __name__=='__main__':main()
