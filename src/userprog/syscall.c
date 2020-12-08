#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "devices/shutdown.h"
#include "filesys/filesys.h"
#include "threads/synch.h"



//#include "../lib/kernel/console.c"

static void syscall_handler (struct intr_frame *);

/* To synchronise file operations */
struct lock filesys_lock;

/* descriptor for each open file to be added in open file list in threads */
struct file_descriptor {
  int fd;
  struct list_elem file_elem;
  struct file *file_struct;
};

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&filesys_lock);
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

struct file* thread_get_file_struct (int fd) {
  struct thread *current_thread = thread_current();
	struct list_elem *current_file_descriptor;

  for(current_file_descriptor = list_begin (&current_thread->open_files); current_file_descriptor != list_end (&current_thread->open_files); current_file_descriptor = list_next (current_file_descriptor))
	{
		struct file_descriptor *f_desc = list_entry (current_file_descriptor, struct file_descriptor, file_elem);
		if (fd == f_desc->fd)
		{
			return f_desc->file_struct;
		}
	}
	return NULL;
}

int write (int fd, const void *buffer, unsigned length){
  
  int size;
  if(fd==1){
     lock_acquire(&filesys_lock);
     putbuf(buffer,length);
     lock_release(&filesys_lock);
     return length;
  } else {
    lock_acquire(&filesys_lock);

    struct file *file = thread_get_file_struct(fd);
    if(file) {
      size = file_write(file,buffer,length);
    } else {
      size = -1;
    }
    lock_release(&filesys_lock);
  }
  return size;  
}

int read (int fd, void *buffer, unsigned length) {
  int size;
  if(fd == 0) {
    lock_acquire(&filesys_lock);
    int i;
    for(i = 0; i < size; ++i) {
      *(char*)(buffer + i) = input_getc();
    }
    lock_release(&filesys_lock);
    return i;
  } else {
    lock_acquire(&filesys_lock);
    struct file *file = thread_get_file_struct(fd);
    if(file){
      size = file_read(file,buffer,length);
    } else {
      size = -1;
    }
    lock_release(&filesys_lock);
  }
  return size;
}

int file_open_syscall (const char *file) {
  int status;
  lock_acquire(&filesys_lock);

  struct file *f_struct = filesys_open(file);
  if(!f_struct) {
    status = -1;  
  } else {
    struct file_descriptor *f_descriptor;
    f_descriptor = calloc (1, sizeof *f_descriptor);
    f_descriptor->file_struct = f_struct;
    f_descriptor->fd = thread_current()->fd;
    thread_current()->fd++;
    list_push_back(&thread_current()->open_files, &f_descriptor->file_elem);
    status = f_descriptor->fd;
  }
  lock_release(&filesys_lock);
  return status;
}

void file_close_syscall(int fd) {
  lock_acquire(&filesys_lock);

  struct thread *current_thread = thread_current();
	struct list_elem *current_file_descriptor;

  for(current_file_descriptor = list_begin (&current_thread->open_files); current_file_descriptor != list_end (&current_thread->open_files); current_file_descriptor = list_next (current_file_descriptor))
	{
		struct file_descriptor *f_desc = list_entry (current_file_descriptor, struct file_descriptor, file_elem);
		if (fd == f_desc->fd)
		{
			file_close(f_desc->file_struct);
      list_remove(&f_desc->file_elem);
      free(f_desc);
      break;
		}
	}
  lock_release(&filesys_lock);
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
      case SYS_HALT:
        shutdown_power_off();
        break;

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
        f->eax = write(*(arg1),*(arg2),*(arg3));
        break;

      case SYS_READ:
        int *arg1 = esp_pointer + 1;
        int *arg2 = esp_pointer + 2;
        int *arg3 = esp_pointer + 3;
    
        check_valid_pointer(arg1);
        check_valid_pointer(arg2);
        //check_valid_pointer(*arg2);
        check_valid_pointer(arg3);
        f->eax = write(*(arg1),*(arg2),*(arg3));
        break;

      case SYS_FILESIZE:
        int *arg1 = esp_pointer + 1;
        check_valid_pointer(arg1);
        int fd = *(esp_pointer + 1);
        
        lock_acquire(&filesys_lock);
        struct file *file = thread_get_file_struct(fd);
        if(file){
          f->eax = file_length(file);
        } else {
          f->eax = -1;
        }
        lock_release(&filesys_lock);
        break;      
      
      case SYS_REMOVE:
        int *arg1 = esp_pointer + 1;
        check_valid_pointer(arg1);
        char *file_name = (char *) *(esp_pointer + 1);
        check_valid_pointer (file_name);
        
        lock_acquire(&filesys_lock); 
        f->eax = filesys_remove (file_name);
        lock_release(&filesys_lock);
        break;

      case SYS_CREATE:
        int *arg1 = esp_pointer + 1;
        int *arg2 = esp_pointer + 2;
        check_valid_pointer(arg1);
        check_valid_pointer(arg2);
        char *file_name = (char *) *(esp_pointer + 1);
        check_valid_pointer (file_name);
        
        lock_acquire(&filesys_lock); 
        f->eax = filesys_create (file_name,*(esp_pointer + 2));
        lock_release(&filesys_lock);
        break;

      case SYS_OPEN:
        int *arg1 = esp_pointer + 1;
        check_valid_pointer(arg1);
        const char *file = (char *) *(esp_pointer + 1);
        check_valid_pointer (file);
        f->eax = file_open_syscall(file);
        break;

      case SYS_CLOSE:
        int *arg1 = esp_pointer + 1;
        check_valid_pointer(arg1);
        int fd = *(esp_pointer + 1);
        file_close_syscall(fd);
        break;

      case SYS_TELL:
        int *arg1 = esp_pointer + 1;
        check_valid_pointer(arg1);
        int fd = *(esp_pointer + 1);
        lock_acquire(&filesys_lock);
        struct file *file = thread_get_file_struct(fd);
        if(file){
          f->eax = file_tell(file);
        } else {
          f->eax = -1;
        }
        lock_release(&filesys_lock);
        break;
      
      case SYS_SEEK:
        int *arg1 = esp_pointer + 1;
        int *arg2 = esp_pointer + 2;
        check_valid_pointer(arg1);
        check_valid_pointer(arg2);
        int fd = *(esp_pointer + 1);

        lock_acquire(&filesys_lock);
        struct file *file = thread_get_file_struct(fd);
        if(file){
          //unsigned position = (unsigned) *(esp_pointer + 2);
          file_seek(fd,*(esp_pointer + 2));
        }
        lock_release(&filesys_lock);
        break;

      default:
        exit_process(-1);
        break;
    }



}
