"""One-shot exact retained daemon reuse. HOST ONLY, no target execution."""
import os,pathlib,json,hashlib
from retention_transport import Transport,retain,release_identity,asset_identity,API
from artifact import members,assemble,ARCHIVE_SHA,ARCHIVE_BYTES
D=pathlib.Path('/mnt/nav-greetd')
def fresh_audience(label):
 from compile_ledger import initialize,audience_guard
 path=D/('audience-'+label+'.json');initialize(path)
 audience_guard(path,os.environ['GH_TOKEN'])
def main():
 assert os.environ['GITHUB_RUN_NUMBER']=='1'and os.environ['GITHUB_RUN_ATTEMPT']=='1'
 assert os.environ['GITHUB_REPOSITORY']=='hardiksayalwork-ai/nav-linux-build'
 fresh_audience('before-source-read')
 t=Transport(os.environ['GH_TOKEN'])
 r=t.get(API+'/releases/455105183')
 release_identity(r,'DRAFT ONLY: greetd compile 45131311407','greetd-compile-45131311407',455105183)
 assert r['target_commitish']=='efab294242e4c612122d692e2d2978f7cb7b95d1'
 assert len(r['assets'])==1
 a=r['assets'][0]
 assert a['id']==781979518 and a['name']=='greetd-compile.tar.gz'and a['state']=='uploaded'
 assert a['size']==ARCHIVE_BYTES and a['digest']=='sha256:'+ARCHIVE_SHA
 assert a['url']==API+'/releases/assets/781979518'
 data=t.download(a['url'])
 asset_identity(a,'greetd-compile.tar.gz',data,781979518)
 # No arbitrary archive helper is imported; strict members are interpreted only
 # by immutable reviewed public code already staged with per-file hashes.
 r2=t.get(API+'/releases/455105183')
 assert r2==r
 retained=members(data)
 frontend=(D/'nav-login-terminal.py').read_bytes();literals=(D/'prompt_literals.py').read_bytes()
 private,receipt=assemble(retained,frontend,literals)
 receipt['assembly']={'bytes':len(private),'sha256':hashlib.sha256(private).hexdigest()}
 (D/'private-daemon-frontend.tar.gz').write_bytes(private)
 (D/'member-receipt.json').write_text(json.dumps(receipt,sort_keys=True,indent=2))
 state=D/'reuse-retention';state.mkdir(mode=0o700)
 def journal(row):
  p=state/'receipt.next'
  with p.open('x')as f:json.dump(row,f);f.flush();os.fsync(f.fileno())
  os.replace(p,state/'receipt.json')
 fresh_audience('before-private-retention')
 result=retain(t,journal,'DRAFT ONLY: daemon frontend assembly '+os.environ['GITHUB_RUN_ID'],
  'daemon-frontend-'+os.environ['GITHUB_RUN_ID'],os.environ['GITHUB_SHA'],
  'daemon-frontend-private.tar.gz',private)
 # Only the source-reviewed fixed receipt schema is disclosed, no retained
 # raw status/ELF/binary/base64, credentials or member content printed.
 print('NAV_REUSED_MEMBER_RECEIPT '+json.dumps(receipt,sort_keys=True))
 print('NAV_PRIVATE_ASSEMBLY_BYTE_VERIFIED '+json.dumps(result,sort_keys=True))
if __name__=='__main__':
 try:main()
 except Exception:raise SystemExit('NAV_REUSE_FAILED_NO_RAW_DIAGNOSTIC')from None
