"""Combinedbuild->receipt->singlecase phasegate,SOURCEONLYnotinvoked.

Deploymentgatealwaysrefuses. Callable phasegate verifiesboundartifacts,never
manufacturesapproval. Onlyfutureexactreviewedworkflowmayconnectactivecase.
"""
import hashlib
class PhaseBlocked(Exception):pass
EXPECTED_SCOPE='ONE_HOST_ONLY_FIXED_INERT_NORMAL_NO_NAMESPACE_NO_QEMU_NO_NAV'
class CombinedGate:
 def __init__(self,source_manifest_sha):self.manifest_sha=source_manifest_sha;self.phase='NEW';self.active_binary_sha=None
 def inert_receipt(self,r):
  if self.phase!='NEW':raise PhaseBlocked('phaseorder')
  if r.get('scope')!='COMPILE_ONLY_INERT_GUARD_AND_STATIC_FIXTURE'or r.get('output_executed')is not False or r.get('installed')is not False or r.get('active_guard_provenance')is not False:raise PhaseBlocked('inertreceiptshape')
  if {x['name']for x in r.get('outputs',[])}!={'guard-inert119','fixture-inert0'}:raise PhaseBlocked('inertartifacts')
  if any(x.get('static_ELF')is not True or x.get('executed')is not False for x in r['outputs']):raise PhaseBlocked('staticunexecutedinertrequired')
  self.inert=r;self.phase='INERT_RECEIPT'
 def active_receipt(self,r,reviewed_active_source_sha,raw_binary):
  if self.phase!='INERT_RECEIPT':raise PhaseBlocked('inertfirst')
  if r.get('source_sha256')!=reviewed_active_source_sha or r.get('static_ELF')is not True or r.get('executed')is not False:raise PhaseBlocked('activereceiptidentity')
  digest=hashlib.sha256(raw_binary).hexdigest()
  if r.get('binary_sha256')!=digest or r.get('binary_bytes')!=len(raw_binary):raise PhaseBlocked('activebinarybinding')
  if digest in {x['sha256']for x in self.inert['outputs']}:raise PhaseBlocked('activeandinertartifactsmustbedistinct')
  self.active_binary_sha=digest;self.phase='ACTIVE_RECEIPT'
 def prepare_case(self,scope):
  if self.phase!='ACTIVE_RECEIPT'or scope!=EXPECTED_SCOPE:raise PhaseBlocked('exactsinglecaseonly')
  self.phase='CASE_READY_SOURCE_ONLY'
  return {'active_binary_sha256':self.active_binary_sha,'case_scope':scope,'permission':False,'native_permission':False}
 def run(self,*args,**kwargs):raise PhaseBlocked('deployment/authoritygateclosed;sourceonly')

def combined_workflow_entrypoint(*args,**kwargs):raise PhaseBlocked('noapprovedpublication/build/runner/hostexecution')
