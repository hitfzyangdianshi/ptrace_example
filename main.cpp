/* C standard library */
#include <cerrno>
#include <cstdio>
#include <cstddef>
#include <cstdlib>
#include <cstring>

/* POSIX */
#include <unistd.h>
#include <sys/user.h>
#include <sys/wait.h>

/* Linux */
#include <syscall.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <linux/elf.h>

using namespace std;

#define FATAL(...) \
    do { \
        fprintf(stderr, "STrace: " __VA_ARGS__); \
        fputc('\n', stderr); \
        exit(EXIT_FAILURE); \
    } while (0)



char composite_number[]="777850139815515823432937985104439249598190573151700075968989406179695960875331150269514998940399022488467916090825849114465503642910133770861457271969532878537031815230446931840061684995416357349745183381771279860684246236778849474628625674942902795509939309916363937745442241024561396926537841449463846747213991413648112534401838116568615587203457359448034002605339982599140780190821876471767613";


int main(int argc, char** argv){

    int count[10000];
    memset(count,0,sizeof(count[0])*10000);


    pid_t pid = fork();
    // printf("pid = %d\n",pid);
    switch (pid) {
        case -1: /* error */
            FATAL("%s", strerror(errno));
        case 0:  /* child */
            ptrace(PTRACE_TRACEME, 0, 0, 0);
            /* Because we're now a tracee, execvp will block until the parent
             * attaches and allows us to continue. */
            char challenge_path[]="../DPI_challenge-interposition/DPI_challenge";
            char *args[]={challenge_path,argv[1], NULL};
            execvp(challenge_path,args);
            FATAL("[error execvp] %s", strerror(errno));
    }

    /* parent */
    waitpid(pid, 0, 0); // sync with execvp
    ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_EXITKILL);



    for (;;) {
        /* Enter next system call */
        if (ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1)
            FATAL("[error PTRACE_SYSCALL1] %s", strerror(errno));
        if (waitpid(pid, 0, 0) == -1)
            FATAL("[error waitpid1] %s", strerror(errno));


        /* Gather system call arguments */
        struct user_regs_struct regs;
        struct iovec io;
        io.iov_base = &regs;
        io.iov_len = sizeof(regs);

        if (ptrace(PTRACE_GETREGSET, pid, (void*)NT_PRSTATUS, &io) == -1)
            FATAL("[error PTRACE_GETREGSET] %s", strerror(errno));


        long syscall_ = (long)regs.regs[8];

        /* Print a representation of the system call */
        // if(syscall_!=-1)
        fprintf(stderr, "%ld(%ld, %ld, %ld, %ld, %ld, %ld)",
                syscall_,
                (long)regs.regs[0], (long)regs.regs[1], (long)regs.regs[2],
                (long)regs.regs[3], (long)regs.regs[4],  (long)regs.regs[5]);


        /* Run system call and stop on exit */
        if (ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1)
            FATAL("[error PTRACE_SYSCALL2] %s", strerror(errno));
        if (waitpid(pid, 0, 0) == -1)
            FATAL("[error waitpid2] %s", strerror(errno));

        /* Get system call result */
        if (ptrace(PTRACE_GETREGSET, pid, (void*)NT_PRSTATUS, &io) == -1) {
            //fputs(" = ?\n", stderr);
             if (errno == ESRCH && !(syscall_ == SYS_exit || syscall_ == SYS_exit_group))
                 exit((long)regs.regs[0]); // system call was _exit(2) or similar
             if(!(syscall_ == SYS_exit || syscall_ == SYS_exit_group))
                 FATAL("%s", strerror(errno));
        }

        /* Print system call result */
        fprintf(stderr, " = %ld\n", (long)regs.regs[0]);
        if(syscall_!=-1) {
            count[syscall_]++;
        }

        if(syscall_ == -1){
            fprintf(stderr, "[ERROR] regs.regs[8] is -1\n");
            exit(EXIT_FAILURE);
            break;
        }
        else if(syscall_ == SYS_exit || syscall_ == SYS_exit_group){
            if((long)regs.regs[0]==0) {
                break;
            }
            else{
                fprintf(stderr, "[INFO] challenge exit code is %ld\n",(long)regs.regs[0]);
                break;
            }
        }
    }


    for(int i=0;i<10000;i++){
        if(count[i]>0){
            printf("%d\t%d\n", i, count[i]);
        }
    }

    return 0;
}