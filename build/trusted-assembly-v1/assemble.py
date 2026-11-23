"""Host-only exact assembly. No target binaries execute; no boot entry."""
import os,pathlib,json,hashlib,gzip,io,tarfile,subprocess
from trusted_initrd_builder import entries,build as initrd_build
from revised_bundle import build as bundle_build
from injection_inputs import observed_daemon,ASSEMBLY_SHA
from retention_transport import Transport,retain,release_identity,asset_identity,API
from compile_ledger import initialize,audience_guard
from base_transfer import transfer
from cache_verify import load_manifest,verify_inventory
D=pathlib.Path('/mnt/nav-assembly-v1')
BASE_SHA='09cf7f18940f8f84b9301050d98ee004a401a212a18c1abbadb18a547db83467'
ORIGINAL_INITRD='2a37cda18c4f99020b964f5481d28b2d93c26fb38dfe440960b708894d77a28b'
PRIOR_INITRD='100bf5e2191482ed24c11af195c0343393cf650f724a3d52cdb989cf61209075'
def digest(b):return hashlib.sha256(b).hexdigest()
def rebuild_prior(raw,init):
 if digest(raw)!=ORIGINAL_INITRD:raise ValueError('original initrd identity')
 out=bytearray()
 for n,v,b in entries(raw):
  if n=='init':b=init
  # Exact reviewed prior writer normalized only trailer inode in addition to init.
  if n=='TRAILER!!!':v[0]=10303421
  v[6]=len(b);v[11]=len(n)+1
  out.extend(b'070701'+b''.join(('%08x'%x).encode()for x in v)+n.encode()+b'\0');out.extend(b'\0'*(-len(out)%4));out.extend(b);out.extend(b'\0'*(-len(out)%4))
 out.extend(b'\0'*(-len(out)%512));b=bytearray(gzip.compress(out,mtime=0));b[9]=255;b=bytes(b)
 if digest(b)!=PRIOR_INITRD:raise ValueError('prior initrd regeneration')
 return b
def fresh_audience(token,label):
 p=D/('audience-'+label+'.json');initialize(p);audience_guard(p,token)
def cache_guard(token):
 import urllib.request
 from retention_transport import NoRedirect
 url=API+'/actions/caches?per_page=100'
 req=urllib.request.Request(url,headers={'Authorization':'Bearer '+token,'Accept':'application/vnd.github+json','Cache-Control':'no-store'})
 with urllib.request.build_opener(NoRedirect()).open(req,timeout=30)as r:
  if r.status!=200 or r.headers.get('Link'):raise ValueError('cache pagination')
  b=r.read(1048577)
 if len(b)>1048576:raise ValueError('cache cap')
 m=load_manifest(D/'cache-manifest45.json','678ed61b4bdb6eb2cee53cbd2d7b0a2cdebd4d169d59d55c2652cd5fc7b75cc5')
 result=verify_inventory(m,json.loads(b))
 if result['count']!=45:raise ValueError('exact45')
 return result
def assemble_local(source,old,original_initrd):
 # No transport. Useful for fixture testing without any hosted effects.
 observed_daemon(old)
 bundle,br=bundle_build(source,old)
 prior=rebuild_prior(original_initrd,(source/'init.failclosed').read_bytes())
 final,ir=initrd_build(prior,bundle,digest((source/'runtime-input-binding.json').read_bytes()),digest((source/'injection-pinset.json').read_bytes()))
 members={'trusted-inputs.tar.gz':bundle,'trusted-initramfs.gz':final,'bundle-receipt.json':json.dumps(br,sort_keys=True).encode(),'initrd-receipt.json':json.dumps(ir,sort_keys=True).encode()}
 out=io.BytesIO()
 with tarfile.open(fileobj=out,mode='w:')as t:
  for n,b in sorted(members.items()):
   h=tarfile.TarInfo(n);h.size=len(b);h.mode=0o600;h.uid=h.gid=h.mtime=0;t.addfile(h,io.BytesIO(b))
 archive=gzip.compress(out.getvalue(),mtime=0)
 if len(archive)>16777216:raise ValueError('output cap')
 # Public projection is deliberately aggregate only. Member paths remain private.
 public={'schema':1,'scope':'SOURCE_ASSEMBLY_NOT_BOOT_TESTED','daemon_executed':False,'installed':False,'native_executed':False,'source_assembly_sha256':ASSEMBLY_SHA,'bundle':{'bytes':len(bundle),'sha256':digest(bundle),'members':len(br['files'])},'initrd':{'bytes':len(final),'sha256':digest(final),'bootstrap_sha256':ir['bootstrap_sha256'],'members':len(ir['members'])},'retained':{'bytes':len(archive),'sha256':digest(archive)}}
 return archive,public

def main():
 assert os.environ['GITHUB_REPOSITORY']=='hardiksayalwork-ai/nav-linux-build'
 assert os.environ['GITHUB_RUN_NUMBER']=='1' and os.environ['GITHUB_RUN_ATTEMPT']=='1'
 assert D.is_dir() and not(D/'work').exists()
 token=os.environ['GH_TOKEN'];fresh_audience(token,'pre-source');cache_guard(token)
 (D/'work').mkdir(mode=0o700);t=Transport(token)
 r=t.get(API+'/releases/455152400');release_identity(r,'DRAFT ONLY: daemon frontend assembly 45138759616','daemon-frontend-45138759616',455152400)
 assert r['target_commitish']=='c20482628a5b30d53652b8018c40023f9c522d91' and len(r['assets'])==1
 a=r['assets'][0]
 assert a['id']==782146280 and a['size']==911432 and a['digest']=='sha256:'+ASSEMBLY_SHA and a['name']=='daemon-frontend-private.tar.gz' and a['state']=='uploaded' and a['url']==API+'/releases/assets/782146280'
 old=t.download(API+'/releases/assets/782146280');asset_identity(a,'daemon-frontend-private.tar.gz',old,782146280)
 assert t.get(API+'/releases/455152400')==r
 # Exact base transfer is single body attempt. No cache restore/save/delete.
 transfer(token,D/'work/base.iso')
 host=pathlib.Path('/usr/bin/xorriso');assert host.is_file()
 # Only host ISO extractor executes. All output remains private, no raw log print.
 with (D/'work/extract.log').open('xb')as log:
  subprocess.run([str(host),'-osirrox','on','-indev',str(D/'work/base.iso'),'-extract','/boot/initramfs.gz',str(D/'work/original-initrd.gz')],check=True,timeout=60,stdin=subprocess.DEVNULL,stdout=log,stderr=log,env={'PATH':'/usr/bin:/bin','LC_ALL':'C'},close_fds=True)
 private,public=assemble_local(D,old,(D/'work/original-initrd.gz').read_bytes())
 (D/'work/assembly-private.tar.gz').write_bytes(private)
 fresh_audience(token,'pre-retention');cache_guard(token)
 state=D/'work/retention';state.mkdir(mode=0o700)
 def journal(row):
  p=state/'next'
  with p.open('x')as f:json.dump(row,f);f.flush();os.fsync(f.fileno())
  os.replace(p,state/'receipt.json')
 result=retain(t,journal,'DRAFT ONLY: trusted input assembly '+os.environ['GITHUB_RUN_ID'],'trusted-input-'+os.environ['GITHUB_RUN_ID'],os.environ['GITHUB_SHA'],'trusted-input-private.tar.gz',private)
 fresh_audience(token,'post-retention');cache_guard(token)
 print('NAV_TRUSTED_ASSEMBLY_FIXED_RECEIPT '+json.dumps(public,sort_keys=True))
 print('NAV_TRUSTED_PRIVATE_READBACK '+json.dumps(result,sort_keys=True))
if __name__=='__main__':
 try:main()
 except BaseException:raise SystemExit('NAV_TRUSTED_ASSEMBLY_FAILED_NO_RAW_DIAGNOSTIC')from None
