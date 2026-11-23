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
    write(path,{'schema':1,'scope':'target-userland-compile-only','daemon_executed':False,'installed':False,'phases':{p:{'state':'not_started'}for p in PHASES}})
def update(path,phase,state,exit_code=None):
    assert phase in PHASES and state in ('started','ended')
    x=json.loads(pathlib.Path(path).read_text());old=x['phases'][phase]['state']
    assert (old,state)in (('not_started','started'),('started','ended'))
    item={'state':state}
    if state=='ended':assert type(exit_code)is int and -255<=exit_code<=255;item['exit']=exit_code
    x['phases'][phase]=item;write(path,x)
def validate(x):
    assert set(x)=={'schema','scope','daemon_executed','installed','phases'}
    assert x['schema']==1 and x['scope']=='target-userland-compile-only' and x['daemon_executed']is False and x['installed']is False
    assert set(x['phases'])==set(PHASES)
    for v in x['phases'].values():
        assert v['state']in ('not_started','started','ended')
        if v['state']=='ended':assert set(v)=={'state','exit'}and type(v['exit'])is int and -255<=v['exit']<=255
        else:assert set(v)=={'state'}
    return x
if __name__=='__main__':
    p=pathlib.Path('/mnt/nav-greetd/outer.json')
    if sys.argv[1]=='initialize':initialize(p)
    else:update(p,sys.argv[1],sys.argv[2],int(sys.argv[3])if len(sys.argv)>3 else None)
