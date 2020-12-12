#include "threads/synch.h"
#include "threads/thread.h"

#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);
void exit_process (int status);
struct child_process_struct* find_child_process(int pid, struct thread * thread_parent);

struct child_process_struct {
    int child_pid;
    int load_status;
    struct list_elem child_elem;
    //struct semaphore load_semaphore;
    int is_waited_on;
    int exit_status;
    int is_exited;
};

#endif /* userprog/syscall.h */
