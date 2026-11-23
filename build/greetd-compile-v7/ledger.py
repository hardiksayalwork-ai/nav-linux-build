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
    write(path,{'schema':1,'scope':'target-userland-compile-only','daemon_executed':False,'installed':False,'compile_diagnostic':{'stage':'not_started','outcome':'not_started','kind':'none','exit':None},'audience':{'state':'unknown','code':'not_checked','rows':0},'phases':{p:{'state':'not_started'}for p in PHASES}})
def update(path,phase,state,exit_code=None):
    assert phase in PHASES and state in ('started','ended')
    x=json.loads(pathlib.Path(path).read_text());old=x['phases'][phase]['state']
    assert (old,state)in (('not_started','started'),('started','ended'))
    item={'state':state}
    if state=='ended':assert type(exit_code)is int and -255<=exit_code<=255;item['exit']=exit_code
    x['phases'][phase]=item;write(path,x)
def validate(x):
    assert set(x)=={'schema','scope','daemon_executed','installed','audience','compile_diagnostic','phases'}
    assert x['schema']==1 and x['scope']=='target-userland-compile-only' and x['daemon_executed']is False and x['installed']is False
    validate_audience_diagnostic(x['audience'])
    validate_compile_diagnostic(x['compile_diagnostic'])
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
if __name__=='__main__':
    p=pathlib.Path('/mnt/nav-greetd/outer.json')
    if sys.argv[1]=='initialize':initialize(p)
    else:update(p,sys.argv[1],sys.argv[2],int(sys.argv[3])if len(sys.argv)>3 else None)
