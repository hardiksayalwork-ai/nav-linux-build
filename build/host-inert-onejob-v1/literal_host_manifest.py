"""Literal FIRSTHOSTONLY runtime manifest verifier. No arbitrarypayloadconfig.

Finaldigestconstant remainsUNSETuntil exactbuildreceipt exists. Therefore
integratedentrycannotusecallerassertiontoselectexecutable,cgrouporconstraints.
"""
import json,hashlib,re
PINNED_RUNTIME_MANIFEST_SHA=None
class ManifestBlocked(Exception):pass

def load_runtime_manifest(raw):
 if PINNED_RUNTIME_MANIFEST_SHA is None:raise ManifestBlocked('noexactreviewedbuildreceipt/literalruntimeanchor')
 if hashlib.sha256(raw).hexdigest()!=PINNED_RUNTIME_MANIFEST_SHA:raise ManifestBlocked('runtimeanchor mismatch')
 x=json.loads(raw)
 required={'guard_path','guard_sha','guard_bytes','fixture_path','fixture_sha','fixture_bytes','delegated_parent','unique_group','expected_cgroup_path','authority'}
 if set(x)!=required or x['authority']!='UNSET':raise ManifestBlocked('exactmanifestshape')
 for role in ('guard','fixture'):
  if not re.fullmatch('[0-9a-f]{64}',x[role+'_sha'])or type(x[role+'_bytes'])is not int or not 1<=x[role+'_bytes']<=1024*1024:raise ManifestBlocked('boundexecutableidentity')
 if not re.fullmatch('nav-host-normal-[0-9a-f]{16}',x['unique_group']):raise ManifestBlocked('fixedgroupnameformat')
 if not x['delegated_parent'].startswith('/sys/fs/cgroup/')or x['expected_cgroup_path']!='/'+x['delegated_parent'].split('/sys/fs/cgroup/',1)[1]+'/'+x['unique_group']:raise ManifestBlocked('groupbinding')
 return x
