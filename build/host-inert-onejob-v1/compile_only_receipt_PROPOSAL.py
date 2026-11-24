"""COMPILE-ONLY proposal,not invoked. No publish/runner/build authority.

Creates static inert guard(return119intact) and inertfixture;never executes
outputs,installs,loads,callsnamespaces,cgroups,signalsorQEMU. ReceiptdoesNOT
claim provenance for a future activatedguard.
"""
from pathlib import Path
from bounded_build_tool_PROPOSAL import bounded_tool
import subprocess,hashlib,json,os,re
D=Path(__file__).parent
class BuildBlocked(Exception):pass

def digest(p):
 b=Path(p).read_bytes();return {'path':str(p),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}

def compile_only_UNINVOKED(source_dir,output_dir,expected_source_pins,compiler):
 src=Path(source_dir);out=Path(output_dir)
 if out.exists():raise BuildBlocked('freshoutputdirectoryrequired')
 names=['outer_stopped_guard_PROPOSAL.c','inert_host_fixture.c']
 if set(expected_source_pins)!=set(names):raise BuildBlocked('exacttwosources')
 for n in names:
  if digest(src/n)['sha256']!=expected_source_pins[n]:raise BuildBlocked('sourcepinmismatch')
 guard=(src/names[0]).read_text()
 if 'if(argc>=0)return 119;'not in guard:raise BuildBlocked('guardhardstopnotintact')
 # Callerchoosesexactreviewedcompilerpath,notPATHsearch. Bindcompilerbefore
 # launchandagainafter;dependencydrivers/librariesmustbeincludedbyreview.
 if not Path(compiler).is_absolute():raise BuildBlocked('absolutecompilerrequired')
 cc_identity=digest(Path(compiler).resolve());out.mkdir(mode=0o700)
 tools={}
 for tool in ('cc1','as','collect2','ld'):
  path=bounded_tool([compiler,'-print-prog-name='+tool],seconds=5)['stdout'].decode().strip()
  if not path.startswith('/'):
   # ExactfixedPATHsearchmustresolveuniquely,notcurrentdirectory.
   candidates=[Path(d)/path for d in ('/usr/bin','/bin')if(Path(d)/path).is_file()]
   real={str(p.resolve())for p in candidates}
   if len(real)!=1:raise BuildBlocked('ambiguouscompilertool')
   path=next(iter(real))
  tools[tool]=digest(Path(path).resolve())
 receipt={'scope':'COMPILE_ONLY_INERT_GUARD_AND_STATIC_FIXTURE','compiler':cc_identity,'compiler_tools':tools,'linked_inputs':{},'readelf':digest('/usr/bin/readelf'),'sources':[digest(src/n)for n in names],'outputs':[],'headers':{},'output_executed':False,'installed':False,'upstream_tests':'EXCLUDED_NOT_RUN_NOT_PASSED','host_lifecycle':'NOT_RUN','active_guard_provenance':False}
 for n,artifact in zip(names,['guard-inert119','fixture-inert0']):
  # -MD recordsactualnon-systemANDsystemheadersusedbythiscompile.
  dep=out/(artifact+'.d');exe=out/artifact
  argv=[compiler,'-std=gnu11','-O2','-static','-Wall','-Wextra','-Werror','-Wl,-t','-MD','-MF',str(dep),str(src/n),'-o',str(exe)]
  r=bounded_tool(argv)
  (out/(artifact+'.compiler-stdout')).write_bytes(r['stdout']);(out/(artifact+'.compiler-stderr')).write_bytes(r['stderr'])
  if r['returncode']:raise BuildBlocked('compilefailure;privatecompilerdiagnosticsretained')
  for line in r['stdout'].decode('utf-8',errors='strict').splitlines():
   path=line.strip()
   if path.startswith('/')and Path(path).is_file():receipt['linked_inputs'][path]=digest(path)
   elif path:raise BuildBlocked('unsupportedlinktraceentry')
  # Never runexe,not even--help/version. readelfreadsbytesonly.
  elf=bounded_tool(['/usr/bin/readelf','-lWd',str(exe)],seconds=10)['stdout'].decode()
  if 'INTERP'in elf or '(NEEDED)'in elf:raise BuildBlocked('staticELFrequired')
  (out/(artifact+'.elf.txt')).write_text(elf)
  tokens=dep.read_text().replace('\\\n',' ').split(':',1)[1].split()
  if any('\\'in x for x in tokens):raise BuildBlocked('unsupporteddepfileescaping')
  for path in tokens:receipt['headers'][path]=digest(path)
  receipt['outputs'].append({'name':artifact,**digest(exe),'static_ELF':True,'executed':False})
 for tool,bound in tools.items():
  if digest(bound['path'])!=bound:raise BuildBlocked('compilertoolchanged')
 for bound in list(receipt['headers'].values())+list(receipt['linked_inputs'].values()):
  if digest(bound['path'])!=bound:raise BuildBlocked('headerorlinkinputchanged')
 if digest(Path(compiler).resolve())!=cc_identity:raise BuildBlocked('compilerchanged')
 (out/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
 return receipt

if __name__=='__main__':raise SystemExit('BLOCKED:compile-onlyproposalnotauthorized')
