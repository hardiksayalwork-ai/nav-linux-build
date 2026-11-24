"""Strict controller pidfd-info identity parser,data only."""
class PidfdBlocked(Exception):pass

def verify_pidfd_info(text,expected_outer_pid,expected_ns_pids):
 fields={}
 for line in text.splitlines():
  if ':'not in line:raise PidfdBlocked('invalid fdinfo')
  key,value=line.split(':',1)
  if key in fields:raise PidfdBlocked('duplicate fdinfo field')
  fields[key]=value.strip()
 try:
  pid=int(fields['Pid']);nspid=[int(x)for x in fields['NSpid'].split()]
 except (KeyError,ValueError):raise PidfdBlocked('pidfd identity fields missing')
 if pid!=expected_outer_pid or pid<2 or nspid!=expected_ns_pids:raise PidfdBlocked('pidfd identity mismatch')
 return True
