"""Literal exact combined SOURCE manifest,not runtimepermission.

Globalconstantsetonlyafterpackaging review. Runtimebuildbinarypinscome from
actualreceipts,notsource-manifestplaceholder. CurrentconstantNoneblocksrun.
"""
import json,hashlib
COMBINED_SOURCE_MANIFEST_SHA=None
class SourceManifestBlocked(Exception):pass

def verify_literal(raw,read_source):
 if COMBINED_SOURCE_MANIFEST_SHA is None:raise SourceManifestBlocked('reviewed_combined_source_anchor_unset')
 if hashlib.sha256(raw).hexdigest()!=COMBINED_SOURCE_MANIFEST_SHA:raise SourceManifestBlocked('combined_manifest_digest')
 def unique(pairs):
  d={}
  for k,v in pairs:
   if k in d:raise SourceManifestBlocked('duplicate_key')
   d[k]=v
  return d
 x=json.loads(raw,object_pairs_hook=unique)
 if x['scope']!='ONE_HOST_ONLY_FIXED_INERT_NORMAL_NO_NAMESPACE_NO_QEMU_NO_NAV':raise SourceManifestBlocked('exact_scope')
 for name,r in x['files'].items():
  if '/'in name or name in ('.','..'):raise SourceManifestBlocked('flat_reviewed_source_names')
  b=read_source(name)
  if len(b)!=r['bytes']or hashlib.sha256(b).hexdigest()!=r['sha256']:raise SourceManifestBlocked('source_bytes_changed')
 return x
