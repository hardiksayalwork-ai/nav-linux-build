"""Build exact revised initrd as bytes, no boot. Requires real hosted bundle."""
import gzip,io,hashlib,json
from trusted_bootstrap_builder import bootstrap

def entries(raw):
 body=gzip.decompress(raw);pos=0;out=[]
 while True:
  h=body[pos:pos+110]
  if h[:6]!=b'070701':raise ValueError('newc format')
  v=[int(h[6+i*8:14+i*8],16)for i in range(13)];name=body[pos+110:pos+109+v[11]].decode('ascii');off=(pos+110+v[11]+3)&~3;b=body[off:off+v[6]];pos=(off+v[6]+3)&~3
  out.append((name,v,b))
  if name=='TRAILER!!!':return out

def build(old_initrd,private_bundle,runtime_sha,pinset_sha):
 if hashlib.sha256(old_initrd).hexdigest()!='100bf5e2191482ed24c11af195c0343393cf650f724a3d52cdb989cf61209075':raise ValueError('exact prior initrd')
 sha=hashlib.sha256(private_bundle).hexdigest();script=bootstrap(sha,runtime_sha,pinset_sha);rows=entries(old_initrd);out=bytearray();receipt=[]
 for n,v,b in rows[:-1]:
  if n=='init':
   move=b'mount --move /run /newroot/run || fail move-run'
   handoff=b'exec switch_root /newroot /sbin/init'
   if b.count(move)!=1 or b.count(handoff)!=1 or b.index(move)>b.index(handoff):raise ValueError('exact init move/handoff')
   # Write while /run still names the tmpfs. move then preserves these inodes
   # at /newroot/run; switch_root exposes that same mount as final /run.
   copies=b'umask 077\ncat /nav-private-input.tar.gz > /run/nav-private-input.tar.gz || fail overlay\ncat /nav-trusted-bootstrap.py > /run/nav-trusted-bootstrap.py || fail overlay\n'
   b=b.replace(move,copies+move).replace(handoff,b'exec switch_root /newroot /usr/bin/python3 -IBS /run/nav-trusted-bootstrap.py')
  receipt.append((n,v[:],b))
 for i,(n,b,mode)in enumerate((('nav-private-input.tar.gz',private_bundle,0o100600),('nav-trusted-bootstrap.py',script,0o100600))):
  receipt.append((n,[99001+i,mode,0,0,1,0,len(b),0,0,0,0,len(n)+1,0],b))
 receipt.append(rows[-1])
 for n,v,b in receipt:
  v[6]=len(b);v[11]=len(n)+1;h=b'070701'+b''.join(('%08x'%x).encode()for x in v);out.extend(h+n.encode()+b'\0');out.extend(b'\0'*((-len(out))%4));out.extend(b);out.extend(b'\0'*((-len(out))%4))
 out.extend(b'\0'*((-len(out))%512));gz=gzip.compress(out,mtime=0)
 return gz,{'scope':'EXACT_TRUSTED_PID1_INJECTION_INITRD_NOT_BOOT_TESTED','bundle_sha256':sha,'bootstrap_sha256':hashlib.sha256(script).hexdigest(),'initrd_sha256':hashlib.sha256(gz).hexdigest(),'initrd_bytes':len(gz),'native_executed':False,'members':{n:{'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}for n,v,b in receipt}}
