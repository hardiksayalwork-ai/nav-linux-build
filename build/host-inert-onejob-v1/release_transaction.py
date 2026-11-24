"""Controller ordered release integration over real identity observations.

No process/cgroup operations here. Capabilities must come from future owned
pidfd/proc/cgroup handles. Constructor still blocked for actual deployment.
"""
from placement_observation import verify_stopped_membership,verify_empty
class ReleaseBlocked(Exception):pass
class ReleaseTransaction:
 def __init__(self,expected):self.expected=expected;self.state='NEW';self.released=False
 def observed(self,before,after,proc_cgroup,procs,pidfd_identity_matches):
  if self.state!='NEW'or pidfd_identity_matches is not True:raise ReleaseBlocked('owned pidfd observation required')
  self.observation=verify_stopped_membership(before,after,proc_cgroup,procs,self.expected);self.state='OBSERVED'
 def release(self,write_exact_token,pidfd_sigcont,reobserve):
  if self.state!='OBSERVED':raise ReleaseBlocked('controller observation required before release')
  # Recheck immediately before release because earlier snapshots expire.
  before,after,cgroup,procs,pidfd_ok=reobserve()
  if pidfd_ok is not True:raise ReleaseBlocked('pidfd identity lost')
  verify_stopped_membership(before,after,cgroup,procs,self.expected)
  try:
   n=write_exact_token(b'\xa5')
   if n!=1:raise ReleaseBlocked('token write failed')
   self.state='TOKEN_WRITTEN';pidfd_sigcont();self.state='RELEASED';self.released=True
  except BaseException:self.state='ABORT_REQUIRES_KILL';raise
 def killed(self,events,procs):
  verify_empty(events,procs);self.state='EMPTY_OBSERVED'
 def finish(self,reap,dispose,postflight):
  if self.state!='EMPTY_OBSERVED':raise ReleaseBlocked('independent empty cgroup observation required')
  reap();self.state='REAPED';dispose();self.state='DISPOSED'
  if postflight()is not True:raise ReleaseBlocked('postflight failed')
  self.state='DONE';return {'ordering_complete':True,'runtime_enforcement_proved':False,'launch_permission':False}
