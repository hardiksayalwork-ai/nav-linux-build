"""Exact systemd261.2 manager read methods, fixed scope mutation only."""
import subprocess,json,re
class AuthorityBlocked(Exception):pass
LOGIN=('org.freedesktop.login1','/org/freedesktop/login1','org.freedesktop.login1.Manager')
SYSTEM=('org.freedesktop.systemd1','/org/freedesktop/systemd1','org.freedesktop.systemd1.Manager')
def unique(pairs):
 d={}
 for k,v in pairs:
  if k in d:raise AuthorityBlocked('duplicate reply key')
  d[k]=v
 return d
def bus(args,signature):
 p=subprocess.run(['/usr/bin/busctl','--system','--timeout=3s','--json=short','--no-pager',*args],stdin=subprocess.DEVNULL,capture_output=True,timeout=4,close_fds=True,env={'PATH':'/usr/bin:/bin','LC_ALL':'C','HOME':'/nonexistent'})
 if p.returncode or len(p.stdout)>131072 or len(p.stderr)>4096:raise AuthorityBlocked('manager reply unavailable')
 try:r=json.loads(p.stdout,object_pairs_hook=unique)
 except (ValueError,UnicodeError):raise AuthorityBlocked('manager reply encoding')from None
 if type(r)!=dict or set(r)!={'type','data'}or r['type']!=signature or type(r['data'])is not list:raise AuthorityBlocked('manager reply signature')
 return r['data']
def call(manager,method,signature):return bus(['call',*manager,method],signature)
def sessions():
 r=call(LOGIN,'ListSessions','a(susso)')
 if len(r)!=1 or type(r[0])is not list or len(r[0])>64:raise AuthorityBlocked('session list shape')
 out=[]
 for x in r[0]:
  if type(x)is not list or len(x)!=5 or type(x[1])is not int or any(type(x[i])is not str for i in (0,2,3,4)):raise AuthorityBlocked('session row')
  if not re.fullmatch(r'[A-Za-z0-9_-]{1,64}',x[0])or not re.fullmatch('/org/freedesktop/login1/session/[A-Za-z0-9_]+',x[4]):raise AuthorityBlocked('session identity syntax')
  out.append(tuple(x))
 if len({x[0]for x in out})!=len(out):raise AuthorityBlocked('session aliases')
 return tuple(out)
def units():
 r=call(SYSTEM,'ListUnits','a(ssssssouso)')
 if len(r)!=1 or type(r[0])is not list or len(r[0])>1024:raise AuthorityBlocked('unit list shape')
 out={}
 for x in r[0]:
  if type(x)is not list or len(x)!=10 or any(type(x[i])is not str for i in (0,1,2,3,4,5,6,8,9))or type(x[7])is not int:raise AuthorityBlocked('unit row')
  if x[0]in out:raise AuthorityBlocked('unit aliases')
  out[x[0]]=tuple(x)
 return out

def scope_authority(scope,prior_object):
 # Successful complete ListUnits supplies absence authority. No error text,
 # nonzero process exit or GetUnit failure can be treated as not-found.
 if not re.fullmatch('session-[A-Za-z0-9_-]{1,64}\\.scope',scope):raise AuthorityBlocked('fixed scope syntax')
 row=units().get(scope)
 if row is None:return {'state':'authoritatively-not-listed','unit_object':prior_object}
 if row[6]!=prior_object:raise AuthorityBlocked('unit replacement')
 if row[2]not in ('loaded','not-found')or row[3]!='inactive' or row[4]!='dead' or row[7]!=0:raise AuthorityBlocked('scope still live or pending job')
 return {'state':'authoritatively-inactive','unit_object':row[6]}

def owner(service):
 if service not in ('org.freedesktop.login1','org.freedesktop.systemd1'):raise AuthorityBlocked('bus owner scope')
 r=bus(['call','org.freedesktop.DBus','/org/freedesktop/DBus','org.freedesktop.DBus','GetNameOwner','s',service],'s')
 if len(r)!=1 or type(r[0])is not str or not re.fullmatch(r':[0-9]+\.[0-9]+',r[0]):raise AuthorityBlocked('unique manager owner')
 return r[0]
def manager_owners():return (owner('org.freedesktop.login1'),owner('org.freedesktop.systemd1'))
