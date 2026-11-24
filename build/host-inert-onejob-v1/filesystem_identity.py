"""Linux x86_64 filesystem type binding SOURCE,not called on live files here.

libc fstatfs writes into oversize4096byte aligned storage;only f_type native
signedlong consumed. Architecture hardgate;no guessed full statfsfieldlayout.
"""
import ctypes,os,platform
class FilesystemBlocked(Exception):pass
PROC_MAGIC=0x9fa0
CGROUP_MAGIC=0x63677270

def filesystem_magic(fd):
 if platform.system()!='Linux'or platform.machine()!='x86_64'or ctypes.sizeof(ctypes.c_long)!=8:raise FilesystemBlocked('reviewedLinuxx86_64ABIrequired')
 # c_long array is aligned and larger than Linuxx86_64structstatfs. VerifyABI
 # againstpinnedrunnerheadersatfuturebuild;sourcefixturesdonotdoit.
 storage=(ctypes.c_long*512)();libc=ctypes.CDLL(None,use_errno=True)
 f=libc.fstatfs;f.argtypes=[ctypes.c_int,ctypes.c_void_p];f.restype=ctypes.c_int
 if f(fd,ctypes.byref(storage))!=0:raise FilesystemBlocked('fstatfsfailed')
 return int(storage[0])

def require_type(fd,magic):
 if filesystem_magic(fd)!=magic:raise FilesystemBlocked('filesystemtypemismatch')
 return True
