"""Fresh HOSTONLY environment admission source,never invoked in this task.

No capability probing through processcreation/namespace;only reads. Kernel
version minimum is necessary,not syscallavailability. Missingactualcapability
receipt blocksrun,not guessed fromversion.
"""
import os,platform,re,stat
from pathlib import Path
from resource_collect import collect
from first_fixture_delegation_PROPOSAL import inspect_parent
from fd_group_admission import open_directory_chain,full_cgroup_mount
from filesystem_identity import require_type,PROC_MAGIC,CGROUP_MAGIC
class FreshBlocked(Exception):pass

def fresh_admission(parent,compiler):
 if os.geteuid()!=0 or len(os.listdir('/proc/self/task'))!=1:raise FreshBlocked('root_singlethread_required')
 if platform.system()!='Linux'or platform.machine()!='x86_64':raise FreshBlocked('linux_x86_64_required')
 version=re.match(r'(\d+)\.(\d+)\.(\d+)',platform.release())
 if not version or tuple(map(int,version.groups()))<(5,14,0):raise FreshBlocked('kernel_minimum_for_pidfd_close_range_cgroupkill')
 proc=open_directory_chain('/proc');cg=open_directory_chain('/sys/fs/cgroup')
 try:
  require_type(proc,PROC_MAGIC);require_type(cg,CGROUP_MAGIC)
  info=Path('/proc/self/mountinfo').read_text();full_cgroup_mount(info)
 finally:os.close(proc);os.close(cg)
 resources=collect('/mnt')
 if resources['host_available_bytes']<512*1024**2 or resources['effective_memory_limit_bytes']<512*1024**2 or resources['disk_available_bytes']<256*1024**2:raise FreshBlocked('fixed_tiny_case_resource_floor')
 checked=inspect_parent(parent)
 try:
  fd=os.open('cgroup.subtree_control',os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW,dir_fd=checked['fd'])
  try:enabled=os.read(fd,4096).decode().split()
  finally:os.close(fd)
  if not {'memory','pids'}<=set(enabled):raise FreshBlocked('controllers_must_already_be_enabled')
  if not os.access(parent,os.W_OK):raise FreshBlocked('parent_not_writable')
 finally:os.close(checked['fd'])
 st=os.stat(compiler,follow_symlinks=True)
 if not stat.S_ISREG(st.st_mode)or st.st_uid!=0 or st.st_mode&0o022:raise FreshBlocked('trusted_compiler_permissions')
 return {'read_admission_passed':True,'kernel':platform.release(),'resources':resources,'actual_syscall_capabilities_proved':False,'general_containment_proved':False,'scope':'ONLY_FIXED_INERT_HOST_CHILD','permission':False}
