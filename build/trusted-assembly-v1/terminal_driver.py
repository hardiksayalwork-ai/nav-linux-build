"""Bounded terminal protocol driver source, NOT RUN against a native frontend.

Caller owns a private PTY and client lifetime. Never persists prompt text or
answers. Does not create a PTY, spawn a process, provision accounts or call PAM.
"""
import os,select,time,termios
from prompt_literals import USERNAME,START,DENIED,SCHEDULED,UNCERTAIN,PASSWORD
class DriverBlocked(Exception):pass

def drive(master_fd,slave_fd,username,secret,deadline,expect_success,empty_password=False,expect_secret_sent=True):
    if type(empty_password)!=bool or type(expect_secret_sent)!=bool:raise DriverBlocked('explicit case flags required')
    if not isinstance(secret,bytearray) or len(secret)>256 or (empty_password != (len(secret)==0)):raise DriverBlocked('bounded mutable disposable secret required')
    if not isinstance(username,bytes) or not username.isascii() or not username.replace(b'_',b'a').isalnum():raise DriverBlocked('fixed simple account name required')
    if type(expect_success)!=bool:raise DriverBlocked('expected case required')
    if deadline<=time.monotonic() or deadline-time.monotonic()>60:raise DriverBlocked('bounded deadline required')
    if not os.isatty(master_fd) or not os.isatty(slave_fd):raise DriverBlocked('private PTY required')
    buf=bytearray();state='USER';seen=0;answer_sent=False
    try:
        while time.monotonic()<deadline:
            ready,_,_=select.select([master_fd],[],[],min(.1,max(0,deadline-time.monotonic())))
            if not ready:continue
            try:data=os.read(master_fd,4096)
            except OSError:raise DriverBlocked('terminal disconnected')
            if not data:raise DriverBlocked('terminal ended without terminal result')
            seen+=len(data)
            if seen>16384:raise DriverBlocked('terminal output limit')
            buf.extend(data)
            if secret and secret in buf:raise DriverBlocked('secret echoed; discard raw output')
            if state=='USER' and USERNAME.encode() in buf:
                os.write(master_fd,username+b'\n');state='SECRET';buf.clear()
            elif state=='SECRET' and PASSWORD.encode() in buf:
                # Observe actual terminal mode before any credential write.
                flags=termios.tcgetattr(slave_fd)[3]
                if flags&(termios.ECHO|termios.ECHONL):raise DriverBlocked('secret input echo not disabled')
                n=os.write(master_fd,secret+b'\n')
                if n!=len(secret)+1:raise DriverBlocked('partial secret write')
                answer_sent=True;state='RESULT';buf.clear()
            elif state=='RESULT' and START.encode() in buf:
                if not expect_success:raise DriverBlocked('unexpected acceptance of rejected case')
                os.write(master_fd,b'START\n');state='START';buf.clear()
            elif UNCERTAIN.encode() in buf:raise DriverBlocked('uncertain handoff; no retry')
            elif DENIED.encode() in buf:
                if expect_success:raise DriverBlocked('correct-secret login rejected')
                if answer_sent!=expect_secret_sent:raise DriverBlocked('secret delivery did not match case')
                return {'terminal_result':'rejected','secret_sent':answer_sent,'native_session_verified':False}
            elif state=='START' and SCHEDULED.encode() in buf:
                if answer_sent!=expect_secret_sent:raise DriverBlocked('secret delivery did not match case')
                return {'terminal_result':'scheduled-only','secret_sent':answer_sent,'native_session_verified':False}
        raise DriverBlocked('terminal deadline')
    finally:
        for i in range(len(buf)):buf[i]=0
        # Caller must retain a distinct one-run secret only if needed for its
        # subsequent approved attempt, then overwrite it. No copy guarantee.
