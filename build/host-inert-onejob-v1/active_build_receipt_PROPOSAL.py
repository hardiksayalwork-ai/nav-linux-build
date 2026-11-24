"""Exact active-build receipt source. Never invoked. No outputs executed."""
from pathlib import Path
from bounded_build_tool_PROPOSAL import bounded_tool
import subprocess,hashlib,json
from compile_only_receipt_PROPOSAL import digest,BuildBlocked
from activation_delta import derive_active

def build_active_UNINVOKED(inert_source,inert_source_sha,expected_active_sha,compiler,output_dir):
 derivation=derive_active(Path(inert_source).read_bytes(),inert_source_sha)
 if derivation['source_sha256']!=expected_active_sha:raise BuildBlocked('exactactivesourcepin')
 out=Path(output_dir)
 if out.exists():raise BuildBlocked('freshactiveoutputdir')
 out.mkdir(mode=0o700);source=out/'guard-active.c';source.write_bytes(derivation['source'])
 cc=digest(Path(compiler).resolve());exe=out/'guard-active';dep=out/'headers.d'
 argv=[compiler,'-std=gnu11','-O2','-static','-Wall','-Wextra','-Werror','-Wl,-t','-MD','-MF',str(dep),str(source),'-o',str(exe)]
 r=bounded_tool(argv)
 (out/'compiler.stdout').write_bytes(r['stdout']);(out/'compiler.stderr').write_bytes(r['stderr'])
 if r['returncode']:raise BuildBlocked('activecompilefailed,privatediagnostics')
 headers={}
 for p in dep.read_text().replace('\\\n',' ').split(':',1)[1].split():
  if '\\'in p:raise BuildBlocked('depfileescape')
  headers[p]=digest(p)
 linked={}
 for p in r['stdout'].decode().splitlines():
  p=p.strip()
  if not p:continue
  if not p.startswith('/')or not Path(p).is_file():raise BuildBlocked('linktraceunsupported')
  linked[p]=digest(p)
 elf=bounded_tool(['/usr/bin/readelf','-lWd',str(exe)],seconds=10)['stdout'].decode()
 if 'INTERP'in elf or '(NEEDED)'in elf:raise BuildBlocked('activemustbestaticELF')
 if digest(Path(compiler).resolve())!=cc:raise BuildBlocked('compilerchanged')
 for x in list(headers.values())+list(linked.values()):
  if digest(x['path'])!=x:raise BuildBlocked('buildinputchanged')
 b=exe.read_bytes();receipt={'source_sha256':expected_active_sha,'inert_source_sha256':inert_source_sha,'binary_sha256':hashlib.sha256(b).hexdigest(),'binary_bytes':len(b),'binary_path':str(exe),'compiler':cc,'headers':headers,'linked_inputs':linked,'static_ELF':True,'executed':False,'installed':False,'authority_from_receipt':False,'upstream_tests':'EXCLUDED_NOT_RUN_NOT_PASSED'}
 (out/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n');return receipt
