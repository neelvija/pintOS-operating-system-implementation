#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"



//#include "../lib/kernel/console.c"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

void exit_process (int status){
 // printf("%d",status);
  printf("%s: exit(%d)\n", thread_current()->name, status);
  //will be used in wait mostly. According to doc we need to return the exit status to the parent if any waiting for the thread
   thread_current()->exit_status = status;

  thread_exit();
}



void check_valid_pointer(void * ptr){
    if(ptr == NULL) {
       exit_process(-1);
    }

    bool is_above_phys_base = is_user_vaddr (ptr);
    if(!is_above_phys_base){
	    exit_process(-1);
    }
    void *is_mapped_ptr = pagedir_get_page(thread_current()->pagedir, ptr);
    if(ptr == NULL || !is_above_phys_base || is_mapped_ptr == NULL){
       exit_process(-1);
    }

}


int write (int fd, const void *buffer, unsigned length){
  
  if(fd==1){
     putbuf(buffer,length);
     return length;
  }
  return -1;  
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  int *esp_pointer = f->esp;
   //check if the pointer is valid
   check_valid_pointer(f->esp);
   
    //to redirect to the proper handler according to the system call number
    int syscall_number = *esp_pointer;  //chk for casting might throw error since esp is void* pointer.
                   
    switch (syscall_number)
    {
    case SYS_EXIT:
       check_valid_pointer(esp_pointer+1);
      //call exit function and pass arguments to it
      exit_process(*(esp_pointer+1));
      break;
    case SYS_WRITE: ;
      int *arg1 = esp_pointer + 1;
      int *arg2 = esp_pointer + 2;
      int *arg3 = esp_pointer + 3;
      
      check_valid_pointer(arg1);
      check_valid_pointer(arg2);
      check_valid_pointer(*arg2);
      check_valid_pointer(arg3);
      write(*(arg1),*(arg2),*(arg3));
      break;
    
    
    default:
      exit_process(-1);
      break;
    }



}
