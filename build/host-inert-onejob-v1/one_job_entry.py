"""Exact one-job proposal entry. Not invoked, published or authorized yet.
Future reviewed workflow is the only caller. No input parameters, no retries.
"""
import os,json,hashlib,io,tarfile,gzip,shutil
from pathlib import Path
from fresh_host_admission_PROPOSAL import fresh_admission
from resource_collect import unified_path
from read_only_github_guard import guard
from combined_driver_PROPOSAL import _combined_UNREACHABLE
from retention_transport import Transport,retain
D=Path(__file__).resolve().parent
SCOPE='ONE_HOST_ONLY_FIXED_INERT_NORMAL_NO_NAMESPACE_NO_QEMU_NO_NAV'

def durable(path,value):
 raw=json.dumps(value,sort_keys=True,indent=2).encode()+b'\n';tmp=path.with_suffix('.next')
 fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb')as f:f.write(raw);f.flush();os.fsync(f.fileno())
 os.replace(tmp,path);fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
 try:os.fsync(fd)
 finally:os.close(fd)

def main(setup):
 # All checks up to mkdir are reads only. Workflow bootstrap has independently
 # pinned exact source bytes and performed the same admission before staging.
 if os.environ.get('GITHUB_REPOSITORY')!='hardiksayalwork-ai/nav-linux-build'or os.environ.get('GITHUB_EVENT_NAME')!='workflow_dispatch'or os.environ.get('GITHUB_RUN_NUMBER')!='2'or os.environ.get('GITHUB_RUN_ATTEMPT')!='1':raise ValueError('single_exact_first_dispatch_only')
 commit=os.environ['GITHUB_SHA'];run=os.environ['GITHUB_RUN_ID']
 if len(commit)!=40 or any(c not in '0123456789abcdef'for c in commit)or not run.isdigit():raise ValueError('run_identity')
 token=os.environ.pop('GH_TOKEN');cache=(D/'protected-caches.json').read_bytes()
 admission_github=guard(token,cache)
 from delegated_scope_setup import verify_setup
 parent,cgpath=verify_setup(setup)
 host_admission=fresh_admission(parent,'/usr/bin/gcc')
 root=Path('/mnt/nav-host-normal-v2')
 if root.exists():raise ValueError('fresh_private_receipt_root_required')
 raw=(D/'source-manifest.json').read_bytes()
 from source_anchor import SOURCE_MANIFEST_SHA
 from literal_combined_source import verify_literal
 import literal_combined_source
 literal_combined_source.COMBINED_SOURCE_MANIFEST_SHA=SOURCE_MANIFEST_SHA
 manifest=verify_literal(raw,lambda n:(D/n).read_bytes())
 group='nav-host-normal-'+hashlib.sha256((commit+':'+run).encode()).hexdigest()[:16]
 reviewed={'delegated_parent':parent,'compiler':'/usr/bin/gcc','manifest_sha':SOURCE_MANIFEST_SHA,'source_dir':str(D),'inert_source_pins':{n:manifest['files'][n]['sha256']for n in ['outer_stopped_guard_PROPOSAL.c','inert_host_fixture.c']},'active_source_sha':manifest['active_source_sha256'],'unique_group':group,'expected_cgroup_path':cgpath+'/'+group}
 root.mkdir(mode=0o700);status=False;receipt={'scope':SCOPE,'commit':commit,'run_id':run,'attempt':1,'github_admission':admission_github,'host_admission':host_admission,'explicit_scope_setup':setup,'complete':False,'permission_to_retry':False,'native_or_guest':False,'hermetic_toolchain_claim':False}
 try:
  receipt['result']=_combined_UNREACHABLE(reviewed,root/'build');receipt['complete']=True;status=True
 except BaseException as e:
  receipt['failure_class']=type(e).__name__
  if isinstance(getattr(e,'receipt',None),dict):receipt['cleanup']=e.receipt
 durable(root/'case-receipt.json',receipt)
 # Success is not announced yet. Retention includes JSON and capped compiler
 # diagnostics only. No ELF, private inputs, source repository or environment.
 out=io.BytesIO()
 with tarfile.open(fileobj=out,mode='w:')as t:
  files=[root/'case-receipt.json']+[p for p in (root/'build').rglob('*')if p.is_file()and (p.name=='receipt.json'or p.suffix=='.compiler-stdout'or p.suffix=='.compiler-stderr'or p.name in ('compiler.stdout','compiler.stderr'))]
  for p in sorted(files):
   b=p.read_bytes()
   if len(b)>4*1024*1024:raise ValueError('receipt_member_cap')
   h=tarfile.TarInfo(str(p.relative_to(root)));h.size=len(b);h.mode=0o600;h.uid=h.gid=h.mtime=0;t.addfile(h,io.BytesIO(b))
 # Remove build outputs before retention and success. A cleanup failure stops
 # the job without success, rather than claiming the retained case implies it.
 if (root/'build').exists():shutil.rmtree(root/'build',ignore_errors=False)
 if (root/'build').exists():raise ValueError('build_cleanup_incomplete')
 archive=gzip.compress(out.getvalue(),mtime=0)
 if len(archive)>16*1024*1024:raise ValueError('receipt_archive_cap')
 guard(token,cache)
 retained=retain(Transport(token),lambda row:durable(root/'retention.json',row),'DRAFT ONLY: inert host receipts '+run,'inert-host-receipts-'+run,commit,'inert-host-receipts.tar.gz',archive)
 guard(token,cache)
 durable(root/'durable-completion.json',{'case_complete':status,'retention':retained,'readback_verified':True})
 # Fixed status and aggregate digest only, never raw diagnostic or host paths.
 print('NAV_HOST_RECEIPT_READBACK_VERIFIED '+hashlib.sha256(archive).hexdigest(),flush=True)
 if not status:raise SystemExit('NAV_FIXED_HOST_CASE_FAILED_RECEIPT_RETAINED_NO_RETRY')
 print('NAV_ONE_FIXED_INERT_HOST_CASE_COMPLETE_NOT_OS_READINESS',flush=True)

if __name__=='__main__':
 try:raise ValueError('reviewed_memory_bootstrap_is_only_caller')
 except BaseException:raise SystemExit('NAV_HOST_JOB_ENDED_STATUS_ONLY_NO_RAW_DIAGNOSTIC')from None
