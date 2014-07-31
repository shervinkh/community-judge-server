#include <sys/resource.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

#define MEGA 1000000

int main(int argc, char *argv[])
{
    int tl = atoll(argv[1]);
    int ml = atoll(argv[2]);
    
    pid_t pid = fork();
    
    if (!pid)
    {
        struct rlimit *tmp1 = (struct rlimit *) malloc(sizeof (struct rlimit));
        tmp1->rlim_cur = tmp1->rlim_max = tl;
        setrlimit(RLIMIT_CPU, tmp1);
        
        struct rlimit *tmp2 = (struct rlimit *) malloc(sizeof (struct rlimit));
        tmp2->rlim_cur = tmp2->rlim_max = ml;
        setrlimit(RLIMIT_AS, tmp2);
        setrlimit(RLIMIT_STACK, tmp2);

        struct rlimit *tmp3 = (struct rlimit *) malloc(sizeof (struct rlimit));
        tmp3->rlim_cur = tmp3->rlim_max = 1;
        setrlimit(RLIMIT_NPROC, tmp3);
        
        freopen(argv[4], "r", stdin);
        freopen("/dev/null", "w", stderr);
        
        char *agv[] = {argv[3], NULL};
        execv(argv[3], agv);
    }
    else
    {
        int status;
        wait(&status);

        struct rusage *info = (struct rusage *) malloc(sizeof (struct rusage));
        getrusage(RUSAGE_CHILDREN, info);
        
        int stat;
        if (status == 0)
            stat = 0;
        else if (status == 9 || status == 32512)
            stat = 1;
        else
            stat = 2;
        
        fprintf(stderr, "%d %lld %ld\n", stat, ((unsigned long long int) (info->ru_utime.tv_sec + info->ru_stime.tv_sec)) * MEGA
                                              + info->ru_utime.tv_usec + info->ru_stime.tv_usec, info->ru_maxrss);
        
        return 0;
    }
}