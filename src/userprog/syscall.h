#include "threads/synch.h"
#include "threads/thread.h"

#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);
void exit_process (int status);

struct child_process_struct {
    int child_pid;
    int load_status;
    struct list_elem child_elem;
    struct semaphore load_semaphore;
};

#endif /* userprog/syscall.h */
