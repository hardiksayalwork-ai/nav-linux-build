"""Strict retained-member validation and private assembly, no target execution."""
import io,tarfile,gzip,json,hashlib,pathlib,struct
ARCHIVE_SHA='7c4bb03163f827e173f65e592e8f154ac1a4e8c706ceaf38485d4d7ca803f208'
ARCHIVE_BYTES=910738
INPUT_SHA='555ac5743a3deaa3c7dfbeeb0653ef717e3f048508f10cf369719ddf303084ae'
class Rejected(Exception):pass

def unique(pairs):
 out={}
 for k,v in pairs:
  if k in out:raise Rejected('duplicate json')
  out[k]=v
 return out

def members(raw):
 # This archive is fixed by external observed digest, not caller metadata.
 if len(raw)!=ARCHIVE_BYTES or hashlib.sha256(raw).hexdigest()!=ARCHIVE_SHA:raise Rejected('archive binding')
 return parse_tar(raw)

def parse_tar(raw):
 import zlib
 z=zlib.decompressobj(16+zlib.MAX_WBITS);body=z.decompress(raw,16*1024*1024+1)
 if len(body)>16*1024*1024 or z.unconsumed_tail:raise Rejected('expanded size')
 body+=z.flush()
 if not z.eof or z.unused_data or len(body)>16*1024*1024:raise Rejected('gzip stream')
 out={}
 with tarfile.open(fileobj=io.BytesIO(body),mode='r:')as t:
  for m in t:
   if m.name not in {'outer.json','status.json','elf.txt','greetd'}or m.name in out or not m.isfile()or m.issym()or m.islnk()or m.size<=0 or m.size>8*1024*1024:raise Rejected('tar member')
   # Harmless tarfile-generated path/mtime headers may exist; no unbounded
   # archive extraction or path interpretation occurs.
   if any(k not in ('mtime','atime','ctime')for k in m.pax_headers):raise Rejected('pax header')
   out[m.name]=t.extractfile(m).read(m.size+1)
   if len(out[m.name])!=m.size:raise Rejected('member length')
 if set(out)!={'outer.json','status.json','elf.txt','greetd'}:raise Rejected('member set')
 return out

def validate(m):
 from compile_validate import validate_output
 from compile_ledger import validate as ledger_validate
 import tempfile
 outer=ledger_validate(json.loads(m['outer.json'],object_pairs_hook=unique))
 if outer['compile_diagnostic']!={'stage':'complete','outcome':'success','kind':'none','exit':0}:raise Rejected('compile not successful')
 # Reuse exact reviewed status/binary private-string validator on private temp
 # data only; never import/execute the retained binary or a retained helper.
 with tempfile.TemporaryDirectory()as temp:
  d=pathlib.Path(temp)
  for k in ('greetd','status.json','elf.txt'):(d/k).write_bytes(m[k])
  s=validate_output(d)
 if s['compile_exit']!=0 or s['input_manifest_sha256']!=INPUT_SHA:raise Rejected('source/status binding')
 b=m['greetd']
 if len(b)<64 or b[:7]!=b'\x7fELF\x02\x01\x01' or struct.unpack_from('<H',b,18)[0]!=62:raise Rejected('x86-64 ELF')
 return {'schema':1,'source_run_id':45131311407,'source_commit':'efab294242e4c612122d692e2d2978f7cb7b95d1',
  'source_archive_sha256':ARCHIVE_SHA,'daemon_executed':False,'installed':False,
  'members':{k:{'bytes':len(v),'sha256':hashlib.sha256(v).hexdigest()}for k,v in sorted(m.items())},
  'elf':{'class':64,'endian':'little','machine':62}}

def assemble(m,frontend,literals):
 receipt=validate(m)
 if not isinstance(frontend,bytes)or len(frontend)>32768 or not frontend.startswith(b'#!/usr/bin/python3 -IB\n'):raise Rejected('frontend source')
 receipt['assembly_scope']='DAEMON_AND_FRONTEND_ONLY_NOT_BOOTABLE_LOGIN'
 receipt['frontend']={'bytes':len(frontend),'sha256':hashlib.sha256(frontend).hexdigest()}
 receipt['literals']={'bytes':len(literals),'sha256':hashlib.sha256(literals).hexdigest()}
 files={'usr/sbin/nav-test-greetd':m['greetd'],'usr/libexec/nav-login-terminal':frontend,
  'usr/libexec/nav-login/prompt_literals.py':literals,
  'evidence/daemon-member-receipt.json':json.dumps(receipt,sort_keys=True).encode()}
 # This is ONLY daemon+frontend input assembly, not complete login injection.
 bio=io.BytesIO()
 with tarfile.open(fileobj=bio,mode='w:')as t:
  for name,data in sorted(files.items()):
   item=tarfile.TarInfo(name);item.size=len(data);item.uid=item.gid=item.mtime=0;item.mode=0o755 if name in ('usr/sbin/nav-test-greetd','usr/libexec/nav-login-terminal')else 0o644 if name.endswith('prompt_literals.py')else 0o600;t.addfile(item,io.BytesIO(data))
 return gzip.compress(bio.getvalue(),mtime=0),receipt
