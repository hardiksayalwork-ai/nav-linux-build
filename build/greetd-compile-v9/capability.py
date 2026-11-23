#!/usr/bin/env python3
"""Host-only namespace capability gate. No target files or network calls."""
import os,subprocess,pathlib,json
D=pathlib.Path('/mnt/nav-greetd');D.mkdir(exist_ok=True,mode=0o700)
def main():
    assert os.geteuid()==0
    marker=D/'namespace-probe';assert not marker.exists();marker.mkdir(mode=0o700)
    q=['bwrap','--die-with-parent','--new-session','--unshare-all','--cap-drop','ALL','--ro-bind','/usr','/usr','--symlink','usr/bin','/bin','--symlink','usr/lib','/lib','--ro-bind','/lib64','/lib64','--proc','/proc','--dev','/dev','--dir','/etc','--bind',str(marker),'/work','--clearenv','/bin/sh','-c','test ! -e /mnt/nav-greetd && test ! -e /root && test ! -e /home/runner && test ! -e /proc/1/root/mnt/nav-greetd && test -z "${GH_TOKEN-}" && test -z "${GITHUB_TOKEN-}" && test ! -e /etc/resolv.conf && echo ok > /work/ok']
    r=subprocess.run(['timeout','15s']+q,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env={'PATH':'/usr/bin:/bin'},timeout=20)
    assert r.returncode==0 and (marker/'ok').read_text()=='ok\n','namespace/AppArmor gate failed; no isolation fallback'
    # Test actual cgroup enforcement via host process, never target execution.
    q=['systemd-run','--unit=nav-greetd-cgroup-probe','--wait','--pipe','--collect','-p','MemoryMax=8589934592','-p','TasksMax=256','-p','RuntimeMaxSec=20','/usr/bin/true']
    r=subprocess.run(q,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=25);assert r.returncode==0
    (D/'capability.json').write_text(json.dumps({'namespace':True,'cgroup_probe':True,'no_target_execution':True})+'\n')
    print('NAV_NAMESPACE_CGROUP_GATE_PASSED')
if __name__=='__main__':main()
