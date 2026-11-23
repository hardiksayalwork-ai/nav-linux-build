#!/usr/bin/python3 -IBS
import os,sys,stat
# Exact bytes installed by PID1 from host-authenticated private bundle.
# No CLI, environment flag, root JSON or caller boolean can enable a case.
if len(sys.argv)!=1 or os.getresuid()!=(0,0,0):raise SystemExit(78)
for p in ('/usr','/usr/libexec','/usr/libexec/nav-test'):
 s=os.lstat(p)
 if stat.S_ISLNK(s.st_mode)or s.st_uid!=0 or s.st_mode&0o022:raise SystemExit(78)
sys.path.insert(0,'/usr/libexec/nav-test')
from native_lifecycle import _positive_body_after_exact_launch_and_input_gate
try:
 result=_positive_body_after_exact_launch_and_input_gate()
 # Fixed projection only, no identities/prompts/secrets/exception output.
 if result['cleanup']['status']!='post-quiescence-stable-clean-observed':raise SystemExit(78)
 os.write(1,b'NAV POSITIVE DISPOSABLE CASE OBSERVED; VM DISPOSAL REQUIRED\n')
except BaseException:
 os.write(2,b'NAV POSITIVE DISPOSABLE CASE UNVERIFIED; VM DISPOSAL REQUIRED\n')
 raise SystemExit(78)
