#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "../lib/kernel/console.c"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

void check_valid_pointer(void * ptr){

    bool is_above_phys_base = is_user_vaddr (ptr);
    void *is_mapped_ptr = pagedir_get_page(thread_current()->pagedir, ptr);

    if(ptr==NULL || !is_above_phys_base || is_mapped_ptr== NULL){
       exit(-1);
    }

}

void read_arguments_from_stack(int *esp_pointer, int number_of_args, int *arguments){  //use this function to read value from the stack

  int *temp; 
  for(int i=1;i<=number_of_args;i++){
    temp = esp_pointer + i;  //base add in stack is call number. We need to start from above that
    check_valid_pointer(temp);  //validate pointer
    printf("%d temp:",*temp);
    arguments[i] = *temp;

  }


}

void exit (int status){

  printf("%s: exit(%d)\n", thread_current()->name, status);
  //will be used in wait mostly. According to doc we need to return the exit status to the parent if any waiting for the thread
   thread_current()->exit_status = status;

  thread_exit();
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
   check_valid_pointer(esp_pointer);
   
   //array to hold number of arguments according to syscall
    int arguments[3];

    //to redirect to the proper handler according to the system call number
    int syscall_number = *esp_pointer;  //chk for casting might throw error since esp is void* pointer.
                         
    switch (syscall_number)
    {
    case SYS_EXIT:
      read_arguments_from_stack(esp_pointer, 1, &arguments); //exit takes 1 argument 
      //call exit function and pass arguments to it
      exit(arguments[0]);
      break;
    case SYS_WRITE:
      read_arguments_from_stack(esp_pointer,3,&arguments);
      check_valid_pointer(arguments[1]);
      f->eax =  write(arguments[0],arguments[1],arguments[2]);
      break;
    
    
    default:
      break;
    }


  printf ("system call!\n");
  thread_exit ();
}
