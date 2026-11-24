"""Integrated FIRST HOST-ONLY lifecycle entrypoint SOURCE, not deployed.

Only fixed inert child,NO NAV,QEMU,bwrap,network,private inputs. Main refuses.
Requires reviewed compiled guard with hardstop removed under separate authority.
No function here has been run against live process/cgroup operations.
"""
import os,fcntl,signal,struct,select,time,subprocess
from pathlib import Path
from guard_fd_abi import guard_file_actions
from guard_handoff import verify_hint
from placement_observation import parse_stat
from linux_controller_adapter_PROPOSAL import OwnedStoppedController,read_relative
from cgroup_controller_PROPOSAL import DedicatedCgroup
from host_launch import open_bound
from pidfd_identity import verify_pidfd_info
from immutable_small import seal_input
from first_fixture_delegation_PROPOSAL import inspect_parent
from fd_group_admission import full_cgroup_mount,open_directory_chain
from fixture_completion import verify_completion
from filesystem_identity import require_type,PROC_MAGIC
from literal_host_manifest import load_runtime_manifest
class EntryBlocked(Exception):pass
class LifecycleFailure(EntryBlocked):
 def __init__(self,receipt):
  self.receipt=receipt;super().__init__('hostfixturefailed;sanitizedreceiptretained')

def read_bounded(fd,amount,deadline):
 out=b'';poll=select.poll();poll.register(fd,select.POLLIN|select.POLLHUP|select.POLLERR)
 while len(out)<amount:
  left=deadline-time.monotonic()
  if left<=0:raise EntryBlocked('guard hint timeout')
  if not poll.poll(max(1,int(left*1000))):continue
  b=os.read(fd,amount-len(out))
  if not b:raise EntryBlocked('guard hint EOF')
  out+=b
 return out

def gp_completed(fd):
 poll=select.poll();poll.register(fd,select.POLLIN);return bool(poll.poll(0))

def snapshot_fds():
 # Directory listing may include its own ephemeral FD;only fstat-live entries
 # are included. Singlethread/no asynchronous FD creation is prerequisite.
 out=[]
 for n in os.listdir('/proc/self/fd'):
  if not n.isdigit():continue
  fd=int(n)
  try:os.fstat(fd)
  except OSError:continue
  out.append(fd)
 return out

def run_source_only_proposal(raw_manifest):
 """Complete wiring proposal,never called. Caller may NOT supply arbitraryexe.
 config must itself be literal reviewed pinned data at eventual deployment.
 """
 config=load_runtime_manifest(raw_manifest) # Alwaysrefusesuntilreviewedbuildanchor.
 raise EntryBlocked('NO LIVE AUTHORITY:source proposal only')

def _lifecycle_UNREACHABLE(config):
 # Single-threaded dedicated fresh helper process. No parent-ownedFDs are
 # closed except this helper's table via posixspawn child file_actions.
 if len(os.listdir('/proc/self/task'))!=1:raise EntryBlocked('singlethread required')
 owned=[];child_pidfd=None;procfd=None;cg=None;guard_pid=None;guard_pidfd=None;stage='NEW';result=None
 release_w=lifetime_w=hint_r=None;group_empty=False
 try:
  # Expected cgroup path must be a controller-created empty dedicated child of
  # a freshly verified delegated subtree. No source-only check can create that
  # verification. Exact device/inode is bound before handle construction.
  parent=Path(config['delegated_parent']);group=parent/config['unique_group']
  if '/'in config['unique_group']or group.name in ('','.','..')or group.exists():raise EntryBlocked('fresh dedicated cgroup required')
  parent_receipt=inspect_parent(str(parent));owned.append(parent_receipt['fd'])
  # Generaluntrustednoescapeisnotclaimed:fixedstaticinertchilddropstonobody.
  # Verifyvisiblecgroup2mount,parentidentityandcontrollerenablementfirst.
  mountinfo=Path('/proc/self/mountinfo').read_text()
  full_cgroup_mount(mountinfo)
  if not str(parent).startswith('/sys/fs/cgroup/'):raise EntryBlocked('delegatedparentoutsidecgroupmount')
  enablefd=os.open('cgroup.subtree_control',os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW,dir_fd=parent_receipt['fd'])
  try:enabled=os.read(enablefd,4096).decode().split()
  finally:os.close(enablefd)
  if not {'memory','pids'}<=set(enabled):raise EntryBlocked('controllersmustalreadybeenabled,nosilenthostchange')
  parentfd=parent_receipt['fd'];groupname=config['unique_group']
  os.mkdir(groupname,mode=0o700,dir_fd=parentfd);stage='CG_CREATED'
  cgfd=os.open(groupname,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parentfd);owned.append(cgfd)
  st=os.fstat(cgfd);cg=DedicatedCgroup(cgfd,st.st_dev,st.st_ino)
  cg.set_limits(64*1024*1024,8)
  # Open fixed binaries as bound immutable inputs. Content hash does not
  # prevent writable aliases:final deployment must use sealed executable FDs
  # or owner-held immutable namespace. This entrypoint remains blocked here.
  guardfd=open_bound(config['guard_path'],config['guard_sha'],config['guard_bytes']);owned.append(guardfd)
  fixturefd=open_bound(config['fixture_path'],config['fixture_sha'],config['fixture_bytes']);owned.append(fixturefd)
  killfd=cg._open('cgroup.kill',os.O_WRONLY);owned.append(killfd)
  release_r,release_w=os.pipe2(os.O_CLOEXEC);lifetime_r,lifetime_w=os.pipe2(os.O_CLOEXEC);hint_r,hint_w=os.pipe2(os.O_CLOEXEC)
  owned.extend([release_r,release_w,lifetime_r,lifetime_w,hint_r,hint_w])
  # Seal executablebytes too;ELFfdexec avoids pathTOCTOU. Bound smallcaps.
  sealed_guard=seal_input(guardfd,config['guard_sha'],config['guard_bytes'],1024*1024);owned.append(sealed_guard)
  sealed_fixture=seal_input(fixturefd,config['fixture_sha'],config['fixture_bytes'],1024*1024);owned.append(sealed_fixture)
  sources={}
  for role,fd in [('kill',killfd),('release_read',release_r),('owner_lifetime_read',lifetime_r),('hint_write',hint_w),('fixture_exec',sealed_fixture),('guard_exec',sealed_guard)]:
   high=fcntl.fcntl(fd,fcntl.F_DUPFD_CLOEXEC,1024);sources[role]=high;owned.append(high)
  nullfd=os.open('/dev/null',os.O_RDWR|os.O_CLOEXEC);owned.append(nullfd)
  nullhigh=fcntl.fcntl(nullfd,fcntl.F_DUPFD_CLOEXEC,1024);owned.append(nullhigh)
  actions=[(os.POSIX_SPAWN_DUP2,nullhigh,i)for i in range(3)]+guard_file_actions(sources,snapshot_fds())['file_actions']
  # ExactsealedguardFD8 resolvedafterfileactions;childfixtureFD7 consumed
  # byexecveat in guardchild afterplacementrelease. Notpathmutableexec.
  guard_pid=os.posix_spawn('/proc/self/fd/8',['nav-host-guard',str(os.getpid()),'sealed-fixture-fd7'],{},file_actions=actions,setsigmask=(),setsigdef=(signal.SIGTERM,signal.SIGHUP,signal.SIGINT))
  for fd in [release_r,lifetime_r,hint_w]+list(sources.values()):
   os.close(fd);owned.remove(fd)
  stage='GUARD_CREATED';guard_pidfd=os.pidfd_open(guard_pid,0);owned.append(guard_pidfd)
  # Controller retains exclusivewait ownership,guard stopschild beforehint.
  guardproc=open_directory_chain('/proc/'+str(guard_pid));owned.append(guardproc)
  require_type(guardproc,PROC_MAGIC)
  gb=read_relative(guardproc,'stat');hint=read_bounded(hint_r,16,time.monotonic()+3)
  _,hintguard,child,_=struct.unpack('<IIII',hint)
  procfd=open_directory_chain('/proc/'+str(child));owned.append(procfd)
  require_type(procfd,PROC_MAGIC)
  cb=read_relative(procfd,'stat');child_pidfd=os.pidfd_open(child,0);owned.append(child_pidfd)
  ca=read_relative(procfd,'stat');ga=read_relative(guardproc,'stat');bound=verify_hint(hint,guard_pid,gb,ga,cb,ca)
  expected={'pid':child,'ppid':guard_pid,'starttime':bound['child_starttime'],'cgroup':config['expected_cgroup_path'],'ns_pids':[child]}
  # Owned stopped child cannot execute/exit/reuse beforeCONT unless another
  # actor canresume/kill;that threat requires noescape/delegation/ownerproof.
  cg._write('cgroup.procs',str(child).encode())
  ctl=OwnedStoppedController(procfd,child_pidfd,release_w,cg,expected)
  try:
   ctl.release_stopped();stage='RELEASED'
   # Firstfixturewritesnothing;stdioinheritancepolicyrequiresfixednullFDs.
   # Thismustbewiredbeforeapproval,notassumedfromemptyoutput.
   poll=select.poll();poll.register(child_pidfd,select.POLLIN)
   if not poll.poll(1000):raise EntryBlocked('fixed fixture deadline')
   ctl.terminate_empty(time.monotonic_ns()+2_000_000_000);group_empty=True
   # Guard reaps its own directchild. Controller reapsguard;waitowner distinct.
   completion={}
   def reap():
    gp=select.poll();gp.register(guard_pidfd,select.POLLIN)
    if not gp.poll(2000):raise EntryBlocked('guardreapdeadline')
    got,status=os.waitpid(guard_pid,os.WNOHANG)
    if got!=guard_pid or not os.WIFEXITED(status)or os.WEXITSTATUS(status)!=0:raise EntryBlocked('guard exit not successful')
    raw=read_bounded(hint_r,16,time.monotonic()+1)
    completion.update(verify_completion(raw,child,status))
   def dispose():os.rmdir(groupname,dir_fd=parentfd)
   def postflight():
    try:os.stat(groupname,dir_fd=parentfd,follow_symlinks=False);return False
    except FileNotFoundError:return completion.get('guard_exit')==0 and completion.get('fixture_exit')==0 and gp_completed(guard_pidfd)
   result=ctl.finish(reap,dispose,postflight);stage='DONE'
  finally:ctl.close()
 except BaseException as failure:
  cleanup_errors=[]
  # Even partialspawn requires wholecgroupkill/empty before teardown. Guard
  # outsidegroup must also be signaled/reaped usingownedguardpidfd.
  if cg is not None:
   try:cg.kill_and_verify_empty(time.monotonic_ns()+2_000_000_000);group_empty=True
   except BaseException:group_empty=False;cleanup_errors.append('cgroupnotverifiedempty')
  if guard_pidfd is not None:
   try:signal.pidfd_send_signal(guard_pidfd,signal.SIGTERM,None,0)
   except ProcessLookupError:pass
   except BaseException:cleanup_errors.append('guardsignalfailed')
  if guard_pidfd is not None and guard_pid is not None:
   gp=select.poll();gp.register(guard_pidfd,select.POLLIN)
   if gp.poll(2000):
    try:os.waitpid(guard_pid,os.WNOHANG)
    except ChildProcessError:cleanup_errors.append('exclusivewaitownershiplost')
   else:cleanup_errors.append('guardnotreaped')
  if group_empty and 'parentfd'in locals() and 'groupname'in locals():
   try:os.rmdir(groupname,dir_fd=parentfd)
   except OSError:cleanup_errors.append('groupnotdisposed')
  receipt={'state':stage,'failure_class':type(failure).__name__,'guard_pid':guard_pid,'child_pid':locals().get('child'),'group_name':locals().get('groupname'),'group_empty_observed':group_empty,'cleanup_errors':cleanup_errors,'complete':False,'permission_to_retry':False}
  raise LifecycleFailure(receipt)from None
 finally:
  if lifetime_w is not None:
   try:os.close(lifetime_w);owned.remove(lifetime_w)
   except OSError:pass
  if cg is not None:cg.close()
  for fd in reversed(owned):
   try:os.close(fd)
   except OSError:pass
 return result

if __name__=='__main__':raise SystemExit('BLOCKED:source-only lifecycle proposal,no live authority')
