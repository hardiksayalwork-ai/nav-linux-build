#!/usr/bin/env python3
"""Fixed-schema host phase ledger, never stores command output or exceptions."""
import json,os,pathlib,sys,time,subprocess
PHASES=('preflight','tools','capability','base-fetch','input-fetch','extract','compile','retention','postflight')
def write(path,value):
    path=pathlib.Path(path);tmp=path.with_suffix('.next');fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'w')as f:json.dump(value,f,sort_keys=True);f.flush();os.fsync(f.fileno())
    os.replace(tmp,path);fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
def initialize(path):
    path=pathlib.Path(path);assert not path.exists()
    write(path,{'schema':1,'scope':'target-userland-compile-only','daemon_executed':False,'installed':False,'build_diagnostic':diagnostic_empty(),'compile_diagnostic':{'stage':'not_started','outcome':'not_started','kind':'none','exit':None},'audience':{'state':'unknown','code':'not_checked','rows':0},'phases':{p:{'state':'not_started'}for p in PHASES}})
def update(path,phase,state,exit_code=None):
    assert phase in PHASES and state in ('started','ended')
    x=json.loads(pathlib.Path(path).read_text());old=x['phases'][phase]['state']
    assert (old,state)in (('not_started','started'),('started','ended'))
    item={'state':state}
    if state=='ended':assert type(exit_code)is int and -255<=exit_code<=255;item['exit']=exit_code
    x['phases'][phase]=item;write(path,x)
def validate(x):
    assert set(x)=={'schema','scope','daemon_executed','installed','audience','compile_diagnostic','build_diagnostic','phases'}
    assert x['schema']==1 and x['scope']=='target-userland-compile-only' and x['daemon_executed']is False and x['installed']is False
    validate_audience_diagnostic(x['audience'])
    validate_compile_diagnostic(x['compile_diagnostic'])
    validate_build_diagnostic(x['build_diagnostic'])
    assert set(x['phases'])==set(PHASES)
    for v in x['phases'].values():
        assert v['state']in ('not_started','started','ended')
        if v['state']=='ended':assert set(v)=={'state','exit'}and type(v['exit'])is int and -255<=v['exit']<=255
        else:assert set(v)=={'state'}
    return x
OWNER={'id':246844948,'login':'hardiksayalwork-ai','node_id':'U_kgDODraOFA','type':'User'}
CODES={'not_checked','empty','individual_owner','owner_mismatch','response_invalid','pagination','external_or_ambiguous','transport_error'}
def validate_audience_diagnostic(v):
    assert type(v)is dict and set(v)=={'state','code','rows'}
    assert v['state']in ('owner_only','unknown') and v['code']in CODES
    assert type(v['rows'])is int and 0<=v['rows']<=100
    assert (v['state']=='owner_only')==(v['code']in ('empty','individual_owner'))
    return v
def audience_decision(repo,rows,status=200,link=None):
    def diag(code,n=0):return validate_audience_diagnostic({'state':'owner_only'if code in ('empty','individual_owner')else 'unknown','code':code,'rows':n})
    if type(repo)is not dict or repo.get('full_name')!='hardiksayalwork-ai/nav-linux-build' or repo.get('private')is not False:return diag('owner_mismatch')
    owner=repo.get('owner')
    if type(owner)is not dict or any(type(owner.get(k))is not type(v)or owner.get(k)!=v for k,v in OWNER.items()):return diag('owner_mismatch')
    if status!=200 or type(rows)is not list:return diag('response_invalid')
    n=min(len(rows),100)
    if link or len(rows)>=100:return diag('pagination',n)
    if not rows:return diag('empty')
    if len(rows)!=1:return diag('external_or_ambiguous',n)
    row=rows[0]
    if type(row)is not dict or any(type(row.get(k))is not type(v)or row.get(k)!=v for k,v in OWNER.items()):return diag('external_or_ambiguous',n)
    return diag('individual_owner',1)
def record_audience(path,diagnostic):
    validate_audience_diagnostic(diagnostic)
    x=validate(json.loads(pathlib.Path(path).read_text()))
    assert x['audience']['code']=='not_checked'
    x['audience']=diagnostic;validate(x);write(path,x)
def audience_guard(path,token,opener=None):
    # Only fixed enums/counts enter the private ledger. No raw identities/logs.
    import urllib.request,urllib.error
    base='https://api.github.com/repos/hardiksayalwork-ai/nav-linux-build'
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self,*a):return None
    opener=opener or urllib.request.build_opener(NoRedirect())
    def get(suffix):
        req=urllib.request.Request(base+suffix,headers={'Authorization':'Bearer '+token,'Accept':'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28','Cache-Control':'no-store'})
        with opener.open(req,timeout=30)as r:
            b=r.read(1048577)
            if len(b)>1048576:raise ValueError('oversize')
            def unique(pairs):
                out={}
                for key,value in pairs:
                    if key in out:raise ValueError('duplicate JSON key')
                    out[key]=value
                return out
            return json.loads(b,object_pairs_hook=unique),r.status,r.headers.get('Link')
    diagnostic={'state':'unknown','code':'transport_error','rows':0}
    try:
        assert type(token)is str and token
        repo,rs,rl=get('')
        if rs!=200 or rl:diagnostic={'state':'unknown','code':'response_invalid','rows':0}
        else:
            rows,status,link=get('/collaborators?affiliation=direct&per_page=100&page=1')
            diagnostic=audience_decision(repo,rows,status,link)
    except Exception:
        pass
    record_audience(path,diagnostic)
    if diagnostic['state']!='owner_only':raise SystemExit('NAV_AUDIENCE_GUARD_FAILED_NO_IDENTITIES_LOGGED')
COMPILE_STAGES=('not_started','imports','root_capability','selected_tree','fresh_paths','input_manifest','lock_pin','disk','tool_paths','work_config','command_ready','host_process','status_projection','binary_validation','status_write','complete')
COMPILE_OUTCOMES=('not_started','checkpoint','success','process_failure','host_exception','host_exit')
COMPILE_KINDS=('none','assertion','missing_file','permission','timeout','subprocess','value','os','other','system_exit')
def validate_compile_diagnostic(v):
    assert type(v)is dict and set(v)=={'stage','outcome','kind','exit'}
    assert v['stage']in COMPILE_STAGES and v['outcome']in COMPILE_OUTCOMES and v['kind']in COMPILE_KINDS
    assert v['exit']is None or type(v['exit'])is int and -255<=v['exit']<=255
    return v
def compile_diagnostic(path,stage,outcome='checkpoint',kind='none',exit_code=None):
    v=validate_compile_diagnostic({'stage':stage,'outcome':outcome,'kind':kind,'exit':exit_code})
    x=validate(json.loads(pathlib.Path(path).read_text()));x['compile_diagnostic']=v;write(path,x)
    # Fixed enums/bounded integer only. Never a raw message,path,output or identity.
    print('NAV_COMPILE_FIXED_DIAGNOSTIC '+json.dumps(v,sort_keys=True),flush=True)
"""Fixed diagnostic signature projection. Never emits input strings or captures.
A match is signature_seen, not trusted authorship or a proven failure cause.
"""
import re
REASONS=('cargo_configuration','cargo_manifest','cargo_dependency','cargo_build_script','linker_command','tool_startup')
LIMIT=64*1024*1024
PATTERNS={
 'cargo_configuration':(rb'error: could not load Cargo configuration',),
 'cargo_manifest':(rb'error: failed to parse manifest at `[^`\r\n]{1,4096}`',),
 'cargo_dependency':(rb'error: failed to load source for (?:a dependency on|dependency) `[^`\r\n]{1,4096}`',rb'error: no matching package named `[^`\r\n]{1,4096}` found',rb'error: failed to select a version for (?:the requirement|`)[^\r\n]{1,4096}'),
 'cargo_build_script':(rb'error: failed to run custom build command for `[^`\r\n]{1,4096}`',),
 'linker_command':(rb'error: linking with `[^`\r\n]{1,4096}` failed: exit status: [0-9]{1,3}',rb'error: linker `[^`\r\n]{1,4096}` not found'),
 'tool_startup':(rb'  could not execute process `[^`\r\n]{1,4096}` \(never executed\)',rb'error: could not execute process `[^`\r\n]{1,4096}` \(never executed\)',rb'bwrap: execvp [^\r\n]{1,4096}: (?:No such file or directory|Permission denied|Exec format error)',rb'timeout: failed to run command [^\r\n]{1,4096}: (?:No such file or directory|Permission denied|Exec format error)',rb'prlimit: failed to execute [^\r\n]{1,4096}: (?:No such file or directory|Permission denied|Exec format error)')}
_PATTERNS={k:tuple(re.compile(x)for x in v)for k,v in PATTERNS.items()}
_SGR=re.compile(rb'\x1b\[[0-9;]{0,32}m')
def diagnostic_empty(state='unavailable'):
 return {'state':state,'reasons':[],'matches':{k:0 for k in REASONS},'counts':{'error_lines':0,'warning_lines':0,'compile_lines':0},'line_rejected':0}
def validate_build_diagnostic(x):
 assert type(x)is dict and set(x)=={'state','reasons','matches','counts','line_rejected'}
 assert x['state']in ('unavailable','unknown','signature_seen','input_rejected')
 assert type(x['reasons'])is list and x['reasons']==[k for k in REASONS if k in x['reasons']]
 assert type(x['matches'])is dict and set(x['matches'])==set(REASONS)
 assert type(x['counts'])is dict and set(x['counts'])=={'error_lines','warning_lines','compile_lines'}
 assert all(type(v)is int and 0<=v<=1000000 for v in list(x['matches'].values())+list(x['counts'].values())+[x['line_rejected']])
 assert x['reasons']==[k for k in REASONS if x['matches'][k]>0]
 assert (x['state']=='signature_seen')==bool(x['reasons'])
 if x['state']in ('unavailable','input_rejected'):assert x==diagnostic_empty(x['state'])
 return x
def project_build_diagnostic(raw):
 if type(raw)is not bytes or len(raw)>LIMIT:return diagnostic_empty('input_rejected')
 x=diagnostic_empty('unknown')
 # Iteration avoids a splitlines list proportional to arbitrary input line count.
 import io
 for original in io.BytesIO(raw):
  if len(original)>8192:x['line_rejected']+=1;continue
  line=_SGR.sub(b'',original.rstrip(b'\r\n'))
  if any(v<32 and v!=9 or v==127 for v in line):x['line_rejected']+=1;continue
  for k,rxs in _PATTERNS.items():
   if any(rx.fullmatch(line)for rx in rxs):x['matches'][k]+=1
  for key,rx in (('error_lines',rb'error(?:\[[A-Z][0-9]{4}\])?:.*'),('warning_lines',rb'warning:.*'),('compile_lines',rb' *Compiling [^\r\n]{1,4096}')):
   if re.fullmatch(rx,line):x['counts'][key]+=1
  if any(v>1000000 for v in list(x['matches'].values())+list(x['counts'].values())+[x['line_rejected']]):return diagnostic_empty('input_rejected')
 if x['line_rejected']>1000000:return diagnostic_empty('input_rejected')
 x['reasons']=[k for k in REASONS if x['matches'][k]]
 if x['reasons']:x['state']='signature_seen'
 return validate_build_diagnostic(x)

def record_build_diagnostic(path,raw):
    value=project_build_diagnostic(raw)
    x=validate(json.loads(pathlib.Path(path).read_text()))
    x['build_diagnostic']=value;validate(x);write(path,x)
    return value
if __name__=='__main__':
    p=pathlib.Path('/mnt/nav-greetd/outer.json')
    if sys.argv[1]=='initialize':initialize(p)
    else:update(p,sys.argv[1],sys.argv[2],int(sys.argv[3])if len(sys.argv)>3 else None)
