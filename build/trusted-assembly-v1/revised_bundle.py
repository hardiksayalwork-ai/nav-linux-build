"""Private hosted input bundle builder. Source only, no bytes retained here."""
import pathlib,json,hashlib,io,tarfile,gzip
from injection_inputs import observed_daemon

def build(source_dir,old_private_assembly):
 root=pathlib.Path(source_dir);pins=json.loads((root/'injection-pinset.json').read_bytes());files={}
 for destination,row in pins['files'].items():
  if row['source'].startswith('VERIFIED_'):data=observed_daemon(old_private_assembly)
  else:data=(root/row['source']).read_bytes()
  if len(data)!=row['bytes']or hashlib.sha256(data).hexdigest()!=row['sha256']:raise ValueError('reviewed source input changed')
  files[destination.lstrip('/')]=(data,row['mode'])
 files['usr/libexec/nav-test/injection-pinset.json']=((root/'injection-pinset.json').read_bytes(),0o600)
 # Runtime pinset is itself pinned by the bundle, not ambient root JSON.
 blob=io.BytesIO()
 with tarfile.open(fileobj=blob,mode='w:')as t:
  for name,(data,mode)in sorted(files.items()):
   if name.startswith('/')or '..'in name.split('/'):raise ValueError('destination')
   x=tarfile.TarInfo(name);x.size=len(data);x.uid=x.gid=x.mtime=0;x.mode=mode;t.addfile(x,io.BytesIO(data))
 bundle=gzip.compress(blob.getvalue(),mtime=0)
 receipt={'schema':1,'scope':'REVISED_PRIVATE_INPUT_BUNDLE_NOT_BOOTABLE','source_assembly_sha256':'432053fc9ec3240b2a7ad670aca97817abd6cb2a0e1e4a332df2a9e0b142d493','daemon_executed':False,'installed':False,'bundle':{'bytes':len(bundle),'sha256':hashlib.sha256(bundle).hexdigest()},'files':{n:{'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'mode':m}for n,(b,m)in sorted(files.items())}}
 return bundle,receipt
