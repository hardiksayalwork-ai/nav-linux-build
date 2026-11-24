"""Collision-safe fixed guard ABI posix_spawn file_actions builder,data only.

Caller duplicates every retained sourceFD above a fresh>=1024base BEFORE any
fixed remap,then obtains authoritativecurrentFDtable withoutasyncopeners. This
planner requires that already-done disjointFDallocation;doesn't fake dup proof.
"""
import os
class ABIBLBlocked(Exception):pass
ROLES={'kill':3,'release_read':4,'owner_lifetime_read':5,'hint_write':6,'fixture_exec':7,'guard_exec':8}

def guard_file_actions(role_sources,observed_fds):
 if set(role_sources)!=set(ROLES):raise ABIBLBlocked('exact guard roles required')
 vals=list(role_sources.values())
 if len(set(vals))!=6 or any(type(x)is not int or x<1024 for x in vals):raise ABIBLBlocked('unique highFD sources required')
 if not set(vals)<=set(observed_fds):raise ABIBLBlocked('missing sourceFD')
 if any(type(x)is not int or x<0 for x in observed_fds):raise ABIBLBlocked('invalid FDtable')
 # CLOEXEC flag of source is immaterial to DUP2 action;new fixedFD staysopen
 # in guardonly. Guard-child dropskill/lifetime/hint beforeexec. FreshFDtable
 # must be scrubbed entirely,includingreleasewrite andhintread/controlFDs.
 actions=[(os.POSIX_SPAWN_DUP2,role_sources[r],target)for r,target in ROLES.items()]
 approved={0,1,2,*ROLES.values()}
 actions +=[(os.POSIX_SPAWN_CLOSE,fd)for fd in sorted(set(observed_fds)-approved)]
 return {'file_actions':actions,'guard_inherited_fds':sorted(approved),'role_targets':dict(ROLES),'source_duplication_verified_here':False,'spawn_permitted':False,'single_thread_no_async_openers_required':True}

def host_fixture_entrypoint(*args,**kwargs):
 raise ABIBLBlocked('no spawn:guard/helper build provenance,cgroupnoescape andownedprocesscreation review open')
