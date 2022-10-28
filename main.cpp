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
            char challenge_path[]="../../DPI_challenge/cmake-build-debug/DPI_challenge";
            char *args[]={challenge_path,argv[1], NULL};
            execvp(challenge_path,args);
            FATAL("%s", strerror(errno));
    }

    /* parent */
    waitpid(pid, 0, 0); // sync with execvp
    ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_EXITKILL);

    for (;;) {
        /* Enter next system call */
        if (ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1)
            FATAL("%s", strerror(errno));
        if (waitpid(pid, 0, 0) == -1)
            FATAL("%s", strerror(errno));

        /* Gather system call arguments */
        struct user_regs_struct regs;
        if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1)
            FATAL("%s", strerror(errno));



        long syscall_ = (long)regs.orig_rax;

        /* Print a representation of the system call */
       // if(syscall_!=-1)
       fprintf(stderr, "%ld(%ld, %ld, %ld, %ld, %ld, %ld)",
                    syscall_,
                    (long)regs.rdi, (long)regs.rsi, (long)regs.rdx,
                    (long)regs.r10, (long)regs.r8,  (long)regs.r9);


        /* Run system call and stop on exit */
        if (ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1)
            FATAL("%s", strerror(errno));
        if (waitpid(pid, 0, 0) == -1)
            FATAL("%s", strerror(errno));

        /* Get system call result */
        if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1) {

            // fputs(" = ?\n", stderr);
            if (errno == ESRCH && !(syscall_ == SYS_exit || syscall_ == SYS_exit_group))
                exit(regs.rdi); // system call was _exit(2) or similar
            if(!(syscall_ == SYS_exit || syscall_ == SYS_exit_group))
                FATAL("%s", strerror(errno));
        }

        /* Print system call result */
        fprintf(stderr, " = %ld\n", (long)regs.rax);
        if(syscall_!=-1) {
            count[syscall_]++;
        }

        if(syscall_ == -1){
            fprintf(stderr, "[ERROR] orig_rax is -1\n");
            exit(EXIT_FAILURE);
            break;
        }
        else if(syscall_ == SYS_exit || syscall_ == SYS_exit_group){
            if((long)regs.rdi==0) {
                break;
            }
            else{
                fprintf(stderr, "[INFO] challenge exit code is %ld\n",(long)regs.rdi);
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