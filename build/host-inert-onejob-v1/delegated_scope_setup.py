"""Explicit setup inside a new systemd-delegated scope only.
Not general containment. Never repair the runner's existing shared parent.
"""
import os,re,stat
from pathlib import Path
from resource_collect import unified_path
from fd_group_admission import open_directory_chain,full_cgroup_mount
from filesystem_identity import require_type,CGROUP_MAGIC

class SetupBlocked(Exception):pass

def prepare_scope(unit):
 if os.geteuid()!=0 or len(os.listdir('/proc/self/task'))!=1:raise SetupBlocked('root_single_thread')
 if not re.fullmatch(r'nav-inert-[0-9]+-3-1\.scope',unit):raise SetupBlocked('literal_unit_identity')
 full_cgroup_mount(Path('/proc/self/mountinfo').read_text())
 cg=unified_path(Path('/proc/self/cgroup').read_text())
 # Scope name supplied to systemd-run, no inferred/guessed slice mapping.
 if cg=='/' or cg.split('/')[-1]!=unit:raise SetupBlocked('not_exact_new_scope')
 p='/sys/fs/cgroup'+cg;fd=open_directory_chain(p)
 try:
  require_type(fd,CGROUP_MAGIC)
  st=os.fstat(fd)
  if st.st_uid!=0 or st.st_mode&0o022:raise SetupBlocked('root_exclusive_scope')
  def read(n):
   f=os.open(n,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
   try:
    b=os.read(f,65537)
    if len(b)>65536:raise SetupBlocked('read_cap')
    return b.decode('ascii').strip()
   finally:os.close(f)
  # systemd v251+ delegation marker is required, not inferred from permissions.
  if os.getxattr(fd,'user.delegate')!=b'1':raise SetupBlocked('delegation_marker')
  if read('cgroup.type')!='domain':raise SetupBlocked('domain_scope_only')
  if read('cgroup.procs').split()!=[str(os.getpid())]:raise SetupBlocked('sole_initial_process')
  if any(stat.S_ISDIR(os.stat(x,dir_fd=fd,follow_symlinks=False).st_mode) for x in os.listdir(fd)):raise SetupBlocked('fresh_no_subgroups')
  if not {'memory','pids'}<=set(read('cgroup.controllers').split()):raise SetupBlocked('controllers_not_delegated')
  os.mkdir('manager',mode=0o700,dir_fd=fd)
  manager=os.open('manager',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
  try:
   target=os.open('cgroup.procs',os.O_WRONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=manager)
   try:
    b=str(os.getpid()).encode()
    if os.write(target,b)!=len(b):raise SetupBlocked('short_self_move')
   finally:os.close(target)
  finally:os.close(manager)
  if read('cgroup.procs'):raise SetupBlocked('scope_not_empty')
  target=os.open('cgroup.subtree_control',os.O_WRONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
  try:
   b=b'+memory +pids'
   if os.write(target,b)!=len(b):raise SetupBlocked('short_enable')
  finally:os.close(target)
  if not {'memory','pids'}<=set(read('cgroup.subtree_control').split()):raise SetupBlocked('enable_readback')
  if unified_path(Path('/proc/self/cgroup').read_text())!=cg+'/manager':raise SetupBlocked('self_move_readback')
  return {'parent':p,'parent_cgroup':cg,'manager_cgroup':cg+'/manager','scope_unit':unit,'parent_identity':[st.st_dev,st.st_ino],'controllers_enabled_only_in_fresh_delegated_scope':True}
 finally:os.close(fd)

def verify_setup(setup):
 if set(setup)!={'parent','parent_cgroup','manager_cgroup','scope_unit','parent_identity','controllers_enabled_only_in_fresh_delegated_scope'}:raise SetupBlocked('setup_fields')
 if unified_path(Path('/proc/self/cgroup').read_text())!=setup['manager_cgroup']:raise SetupBlocked('manager_membership_changed')
 fd=open_directory_chain(setup['parent'])
 try:
  require_type(fd,CGROUP_MAGIC);st=os.fstat(fd)
  if [st.st_dev,st.st_ino]!=setup['parent_identity']:raise SetupBlocked('scope_identity_changed')
 finally:os.close(fd)
 return setup['parent'],setup['parent_cgroup']
