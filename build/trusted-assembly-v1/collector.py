"""Read-only cgroup/proc evidence collector, no CLI or mutation operations.

Only synthetic fixture roots have been exercised. No evidence from this module
has native acceptance authority. Root FDs must come from an independently bound
trusted collector/controller; this module cannot authenticate its caller.
"""
import os,re,stat
from dataclasses import dataclass

class Unverified(Exception):pass

@dataclass(frozen=True)
class Limits:
    directories:int=128
    depth:int=16
    file_bytes:int=16384
    pids:int=512
    proc_entries:int=4096

O_DIR=os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC|os.O_NOFOLLOW
O_FILE=os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NONBLOCK

def read_file(fd,name,limit):
    if '/' in name or name in ('.','..'):raise Unverified('invalid leaf')
    f=os.open(name,O_FILE,dir_fd=fd)
    try:
        s=os.fstat(f)
        if not stat.S_ISREG(s.st_mode):raise Unverified('nonregular leaf')
        a=os.read(f,limit+1)
        if len(a)>limit:raise Unverified('file limit')
        if os.read(f,1):raise Unverified('file grew beyond limit')
        return a.decode('ascii','strict')
    finally:os.close(f)

def subtree(root_fd,components):
    if not components or any(not re.fullmatch(r'[A-Za-z0-9_.:@\\-]{1,128}',c) or c in ('.','..') for c in components):
        raise Unverified('invalid cgroup path')
    f=os.dup(root_fd)
    try:
        for c in components:
            n=os.open(c,O_DIR,dir_fd=f);os.close(f);f=n
        return f
    except BaseException:os.close(f);raise

def parse_pids(text,limit):
    out=[]
    for row in text.splitlines():
        if not re.fullmatch('[1-9][0-9]{0,9}',row):raise Unverified('invalid pid')
        out.append(int(row))
    if len(out)>limit or len(out)!=len(set(out)):raise Unverified('pid count or duplicate')
    return tuple(sorted(out))

def scope_snapshot(root_fd,components,limits=Limits()):
    """No-follow recursive subtree snapshot, preserving inode identities."""
    records={};all_pids=set();seen=set()
    def visit(fd,path,depth):
        if depth>limits.depth or len(records)>=limits.directories:raise Unverified('directory limit')
        s=os.fstat(fd);key=(s.st_dev,s.st_ino)
        if key in seen:raise Unverified('repeated directory identity')
        seen.add(key)
        ev=read_file(fd,'cgroup.events',limits.file_bytes)
        fields={}
        for line in ev.splitlines():
            parts=line.split()
            if len(parts)!=2 or parts[0] in fields:raise Unverified('malformed events')
            fields[parts[0]]=parts[1]
        if fields.get('populated') not in ('0','1'):raise Unverified('missing populated')
        pids=parse_pids(read_file(fd,'cgroup.procs',limits.file_bytes),limits.pids)
        if fields['populated']=='0' and pids:raise Unverified('contradictory empty event')
        all_pids.update(pids)
        if len(all_pids)>limits.pids:raise Unverified('total pid limit')
        records[path]={'dev':key[0],'inode':key[1],'populated':int(fields['populated']),'pids':pids}
        names=sorted(os.listdir(fd))
        if len(names)>limits.proc_entries:raise Unverified('entry limit')
        for name in names:
            st=os.stat(name,dir_fd=fd,follow_symlinks=False)
            if stat.S_ISLNK(st.st_mode):raise Unverified('symlink inside cgroup')
            if stat.S_ISDIR(st.st_mode):
                if not re.fullmatch(r'[A-Za-z0-9_.:@\\-]{1,128}',name) or name in ('.','..'):raise Unverified('invalid child')
                child=os.open(name,O_DIR,dir_fd=fd)
                try:
                    opened=os.fstat(child)
                    if (opened.st_dev,opened.st_ino)!=(st.st_dev,st.st_ino):raise Unverified('child identity changed')
                    visit(child,path+'/'+name,depth+1)
                    after=os.stat(name,dir_fd=fd,follow_symlinks=False)
                    if (after.st_dev,after.st_ino)!=(st.st_dev,st.st_ino):raise Unverified('child replaced')
                finally:os.close(child)
        if os.fstat(fd).st_ino!=key[1] or sorted(os.listdir(fd))!=names:raise Unverified('subtree changed')
    f=subtree(root_fd,components)
    try:visit(f,'/'.join(components),0)
    finally:os.close(f)
    # Parent populated must reflect every descendant, not only direct members.
    for path,row in records.items():
        if row['populated']==0 and any(other['populated'] for p,other in records.items() if p.startswith(path+'/')):
            raise Unverified('contradictory descendant population')
    return {'records':records,'pids':tuple(sorted(all_pids)),'empty':all(r['populated']==0 and not r['pids'] for r in records.values())}

def proc_identity(proc_fd,pid,limits=Limits()):
    if type(pid)!=int or pid<=0:raise Unverified('invalid pid')
    f=os.open(str(pid),O_DIR,dir_fd=proc_fd)
    try:
        def tick():
            raw=read_file(f,'stat',limits.file_bytes);prefix=raw.split(' ',1)[0]
            end=raw.rfind(')')
            if prefix!=str(pid) or end<raw.find('('):raise Unverified('bad stat identity')
            rest=raw[end+2:].split()
            if len(rest)<20 or not rest[19].isdecimal():raise Unverified('bad starttime')
            return int(rest[19])
        before=tick();status=read_file(f,'status',limits.file_bytes)
        uids=[l.split()[1:] for l in status.splitlines() if l.startswith('Uid:')]
        if len(uids)!=1 or len(uids[0])!=4 or any(not x.isdecimal() for x in uids[0]):raise Unverified('bad uid record')
        cg=read_file(f,'cgroup',limits.file_bytes).splitlines()
        if len(cg)!=1 or not cg[0].startswith('0::/'):raise Unverified('not unified cgroup')
        path=cg[0][3:]
        if '..' in path.split('/') or '\x00' in path:raise Unverified('bad proc cgroup')
        after=tick()
        if before!=after:raise Unverified('process identity changed')
        return {'pid':pid,'starttime':before,'uids':tuple(int(x) for x in uids[0]),'cgroup':path}
    finally:os.close(f)

def uid_workloads(proc_fd,uid,limits=Limits()):
    if type(uid)!=int or uid<=0:raise Unverified('nonroot test uid required')
    names=sorted(n for n in os.listdir(proc_fd) if n.isdecimal())
    if len(names)>limits.proc_entries:raise Unverified('proc entry limit')
    out=[]
    for name in names:
        # Disappearing or unreadable records fail closed. A future retry is a
        # separately bounded collection decision, never an inferred clean row.
        row=proc_identity(proc_fd,int(name),limits)
        if uid in row['uids']:out.append(row)
    if names!=sorted(n for n in os.listdir(proc_fd) if n.isdecimal()):raise Unverified('proc list changed')
    return tuple(out)

def cleanup_observation(cgroup_fd,components,proc_fd,uid,tracked,limits=Limits()):
    """One logical clean observation only, NOT authorization for fresh login.

    Double snapshots reduce obvious races but cannot prove atomic absence of
    arbitrary hostile workloads. Future native controller must quiesce creation
    and independently verify scope inactive, lifetime and collector provenance.
    """
    try:
        first=scope_snapshot(cgroup_fd,components,limits)
        workloads=uid_workloads(proc_fd,uid,limits)
        survivors=[]
        for pid,start in tracked:
            try:row=proc_identity(proc_fd,pid,limits)
            except FileNotFoundError:continue
            if row['starttime']==start:survivors.append((pid,start))
        last=scope_snapshot(cgroup_fd,components,limits)
        if first!=last:raise Unverified('scope snapshots disagree')
        return {'status':'observed' if first['empty'] and not workloads and not survivors else 'not-clean',
            'scope':last,'uid_workloads':workloads,'tracked_survivors':tuple(survivors),
            'native_acceptance':False,'atomic_absence_proved':False}
    except (OSError,UnicodeError,ValueError,Unverified) as exc:
        return {'status':'unverified','error_class':type(exc).__name__,
            'native_acceptance':False,'atomic_absence_proved':False}
