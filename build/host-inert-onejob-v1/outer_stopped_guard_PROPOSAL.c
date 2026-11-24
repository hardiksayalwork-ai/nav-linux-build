/* Source proposal only: owned OUTER launcher stopped before bwrap exec.
 * Hard-stopped until independently reviewed host-only validation is authorized.
 * Future ABI fd3=dedicated cgroup.kill held by guard,fd4=controller release read,
 * fd5=controller ownership lifetime read,fd6=guard->controller PIDhintwrite.
 * fd7=sealedinertfixtureELF,fixed targetFDpolicy stdioONLY. Controller owns parent PID and pidfd.
 * Entire child must be placed while stopped before release,SIGCONT or exec.
 */
#define _GNU_SOURCE
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <stdlib.h>
#include <poll.h>
#include <fcntl.h>
#include <stdint.h>
#include <grp.h>
#include <sys/syscall.h>
#include <linux/close_range.h>
#ifndef CLOSE_RANGE_CLOEXEC
#define CLOSE_RANGE_CLOEXEC (1U << 2)
#endif
static volatile sig_atomic_t dying=0;
static void parent_died(int sig){(void)sig;dying=1;ssize_t n=write(3,"1",1);(void)n;}
static int authorized_byte(int fd){
 unsigned char b=0;ssize_t n;
 do{n=read(fd,&b,1);}while(n<0&&errno==EINTR&&!dying);
 return n==1&&b==0xA5&&!dying; /* EOF or wrong byte never releases */
}
int main(int argc,char **argv){
 if(argc>=0)return 119; /* NONNEGOTIABLE SOURCE-REVIEW HARDSTOP */
 if(argc<3)return 120;
 close(8); /* guardELFconsumedbyposixspawn,notinheritableinput */
 char *end=0;long expected=strtol(argv[1],&end,10);
 if(!end||*end||expected<2)return 121;
 struct sigaction sa={0};sa.sa_handler=parent_died;sigemptyset(&sa.sa_mask);
 if(sigaction(SIGTERM,&sa,0)||sigaction(SIGHUP,&sa,0)||sigaction(SIGINT,&sa,0))return 122;
 if(prctl(PR_SET_PDEATHSIG,SIGTERM)||getppid()!=(pid_t)expected){parent_died(SIGTERM);return 123;}
 sigset_t blocked,old;sigemptyset(&blocked);sigaddset(&blocked,SIGTERM);sigaddset(&blocked,SIGHUP);sigaddset(&blocked,SIGINT);
 if(sigprocmask(SIG_BLOCK,&blocked,&old))return 124;
 pid_t guard=getpid(),child=fork();
 if(child<0)return 124;
 if(child==0){
  if(prctl(PR_SET_PDEATHSIG,SIGKILL)||getppid()!=guard)_exit(125);
  close(3);close(5);close(6);
  struct sigaction def={0};def.sa_handler=SIG_DFL;sigemptyset(&def.sa_mask);
  if(sigaction(SIGTERM,&def,0)||sigaction(SIGHUP,&def,0)||sigaction(SIGINT,&def,0)||sigprocmask(SIG_SETMASK,&old,0))_exit(125);
  /* No target code/namespace setup before stopped-owned placement. */
  if(raise(SIGSTOP))_exit(126);
  if(!authorized_byte(4))_exit(127);
  close(4);
  /* FIRSTHOSTONLYfixture:dropallgroupsandUID/GIDtonobody;rootowned0700
   * dedicatedcgroup isnotwritablebychild. ResetPDEATHSIGaftercredentialchange. */
  if(setgroups(0,0)||setgid(65534)||setuid(65534))_exit(128);
  if(prctl(PR_SET_PDEATHSIG,SIGKILL)||getppid()!=guard)_exit(128);
  if(prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0))_exit(128);
  /* Future controller must ensure precise inheritable FD allowlist here.
   * No setuid/credential transition permitted after PDEATHSIG installation. */
  /* Exactfixture is sealedFD7,not mutablepath argv. MarkallnonstdioCLOEXEC,
   * then execveat ELFfd withAT_EMPTY_PATH;targetinheritsstdioONLY. */
#ifdef __NR_close_range
  if(syscall(__NR_close_range,3U,~0U,CLOSE_RANGE_CLOEXEC))_exit(128);
#else
  _exit(128);
#endif
#ifdef __NR_execveat
  char *fixed_argv[]={"nav-host-inert-fixture",0};char *empty_env[]={0};
  syscall(__NR_execveat,7,"",fixed_argv,empty_env,AT_EMPTY_PATH);_exit(128);
#else
  _exit(128);
#endif
 }
 close(4);
 if(sigprocmask(SIG_SETMASK,&old,0)){parent_died(SIGTERM);return 129;}
 int status=0;pid_t got;
 do{got=waitpid(child,&status,WUNTRACED);}while(got<0&&errno==EINTR&&!dying);
 if(got!=child||!WIFSTOPPED(status)||WSTOPSIG(status)!=SIGSTOP||dying){parent_died(SIGTERM);return 129;}
 /* Fixed binary handoff is a location hint,NOT membership authority. */
 struct {uint32_t version;uint32_t guard;uint32_t child;uint32_t reserved;} handoff={1,(uint32_t)getpid(),(uint32_t)child,0};
 if(write(6,&handoff,sizeof(handoff))!=(ssize_t)sizeof(handoff)){parent_died(SIGTERM);return 131;}
 /* Controller independently observes proc stat/ppid/starttime and owned
  * pidfd,cgroup.procs and proc/cgroup;writes release then pidfdSIGCONT.
  * Guard cannot substitute its own child-status report for that evidence. */
 struct pollfd lifetime={.fd=5,.events=POLLIN|POLLHUP|POLLERR};
 while(!dying){
  got=waitpid(child,&status,WNOHANG);
  if(got==child)break;
  if(got<0&&errno!=EINTR){parent_died(SIGTERM);break;}
  int r=poll(&lifetime,1,100);
  if(r<0&&errno!=EINTR){parent_died(SIGTERM);break;}
  if(r>0){parent_died(SIGTERM);break;} /* EOF/readability=owner gone */
 }
 int normal=(got==child && WIFEXITED(status) && WEXITSTATUS(status)==0 && !dying);
 struct {uint32_t version;uint32_t child;uint32_t wait_status;uint32_t normal;} completion={2,(uint32_t)child,(uint32_t)status,(uint32_t)normal};
 ssize_t written=write(6,&completion,sizeof(completion));close(6);
 parent_died(SIGTERM); /* always kill dedicated subtree on root exit */
 /* Outer controller MUST observe empty cgroup,reap all children,and dispose.
  * Guard does not claim its write succeeded or that descendants could not escape. */
 return normal && written==(ssize_t)sizeof(completion)?0:130;
}
