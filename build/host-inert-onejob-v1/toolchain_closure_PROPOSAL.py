"""Read-only compile toolchain sourceclosure generator,not run here.

ldd/tooloutputneverexecuted. readelfbytesonlyvia boundedreviewedtooladapter.
Completeoptional_dlopen/implicitcompilerconfigsremainunknownandblockready.
"""
from pathlib import Path
import os,re
from compile_only_receipt_PROPOSAL import digest,BuildBlocked
from bounded_build_tool_PROPOSAL import bounded_tool

def bind_toolchain_UNINVOKED(compiler):
 tools={'compiler':str(Path(compiler).resolve()),'readelf':'/usr/bin/readelf'}
 for name in ('cc1','as','collect2','ld'):
  r=bounded_tool([compiler,'-print-prog-name='+name],seconds=5)
  if r['returncode']:raise BuildBlocked('toolintrospectionfailed')
  p=r['stdout'].decode().strip()
  if not p.startswith('/'):
   resolved={str((Path(d)/p).resolve())for d in ['/usr/bin','/bin']if(Path(d)/p).is_file()}
   if len(resolved)!=1:raise BuildBlocked('toolpathambiguous')
   p=next(iter(resolved))
  tools[name]=str(Path(p).resolve())
 ld=bounded_tool(['/sbin/ldconfig','-p'],seconds=5)
 if ld['returncode']:raise BuildBlocked('loadercacheunreadable')
 cache={}
 for line in ld['stdout'].decode().splitlines():
  m=re.match(r'\s*(\S+)\s+\(([^)]*)\)\s+=>\s+(/\S+)',line)
  if m and 'x86-64'in m[2]:cache.setdefault(m[1],set()).add(str(Path(m[3]).resolve()))
 queue=list(tools.values());bound={};gaps=[]
 while queue:
  p=queue.pop()
  if p in bound:continue
  bound[p]=digest(p);b=Path(p).read_bytes()
  if not b.startswith(b'\x7fELF'):raise BuildBlocked('tool_or_dependency_not_ELF')
  r=bounded_tool(['/usr/bin/readelf','-lWd',p],seconds=10)
  if r['returncode']:raise BuildBlocked('ELFparsefailed')
  text=r['stdout'].decode()
  # Exactpath/RPATHnotmodeledhere;failclosedratherthanguess.
  if '(RUNPATH)'in text or '(RPATH)'in text:gaps.append({'path':p,'gap':'path_tag_requires_ordered_resolution'})
  for interp in re.findall(r'Requesting program interpreter: (.*?)\]',text):queue.append(str(Path(interp).resolve()))
  for name in re.findall(r'\(NEEDED\).*?\[(.*?)\]',text):
   candidates=cache.get(name,set())
   if len(candidates)!=1:gaps.append({'path':p,'needed':name,'gap':'missing_or_ambiguous_cache_candidate'})
   else:queue.append(next(iter(candidates)))
 # NeedincludeGCCspecs/plugins/ldscripts/openfilesbeyondDTNEEDED;actual-Wl,-t
 # and-MDpostcompilecoversomebutnotread-before/useimmutability.
 return {'tools':tools,'bound_files':bound,'direct_elf_gaps':gaps,'optional_dlopen_complete':False,'implicit_config_complete':False,'ready':False,'executed_built_outputs':False}
