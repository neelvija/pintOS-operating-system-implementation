#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "devices/shutdown.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/synch.h"
#include "userprog/process.h"
#include "devices/input.h"
#include "threads/malloc.h"
#include "user/syscall.h"




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
    uint8_t *buf = (uint8_t *) buffer;
    for(i = 0; i < size; i++) {
      buf[i] = input_getc();
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

struct child_process_struct* find_child_process(int pid)
{
  struct child_process_struct *cp = NULL;
  struct thread *current_thread = thread_current();  
  for (struct list_elem *e = list_begin(&current_thread->child_threads_list); e != list_end(&current_thread->child_threads_list); e = list_next(e))
  {
    cp = list_entry(e, struct child_process_struct, child_elem);
    if (pid == cp->child_pid)
    {
      break;
    }
  }
  return cp;
}

pid_t
syscall_exec(const char* cmdline)
{
    pid_t pid = process_execute(cmdline);
    struct child_process_struct *child_process = find_child_process(pid);
    if (child_process)
    {
      /* check if process if loaded */
      if (child_process->load_status == 0)
      {
        sema_down(&child_process->load_semaphore);
      }
      /* check if process failed to load */
      if (child_process->load_status == -1)
      {
        list_remove(&child_process->child_elem);
        free(child_process);
        pid = -1;
      }
    } else {
      pid = -1;
    }
    return pid;
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
        int *arg1_write = esp_pointer + 1;
        int *arg2_write = esp_pointer + 2;
        int *arg3_write = esp_pointer + 3;
    
        check_valid_pointer(arg1_write);
        check_valid_pointer(arg2_write);
        check_valid_pointer(*arg2_write);
        check_valid_pointer(arg3_write);
        f->eax = write(*(arg1_write),*(arg2_write),*(arg3_write));
        break;

      case SYS_READ: ;
        int *arg1_read = esp_pointer + 1;
        int *arg2_read = esp_pointer + 2;
        int *arg3_read = esp_pointer + 3;
    
        check_valid_pointer(arg1_read);
        check_valid_pointer(arg2_read);
        check_valid_pointer(*arg2_read);
        check_valid_pointer(arg3_read);
        f->eax = read(*(arg1_read),(void *)*(esp_pointer + 2),*(arg3_read));
        break;

      case SYS_FILESIZE: ;
        int *arg1_filesize = esp_pointer + 1;
        check_valid_pointer(arg1_filesize);
        int fd_filesize = *(esp_pointer + 1);
        
        lock_acquire(&filesys_lock);
        struct file *file_filesize = thread_get_file_struct(fd_filesize);
        if(file_filesize){
          f->eax = file_length(file_filesize);
        } else {
          f->eax = -1;
        }
        lock_release(&filesys_lock);
        break;      
      
      case SYS_REMOVE: ;
        int *arg1_remove = esp_pointer + 1;
        check_valid_pointer(arg1_remove);
        char *file_name_remove = (char *) *(esp_pointer + 1);
        check_valid_pointer (file_name_remove);
        
        lock_acquire(&filesys_lock); 
        f->eax = filesys_remove (file_name_remove);
        lock_release(&filesys_lock);
        break;

      case SYS_CREATE: ;
        int *arg1_create = esp_pointer + 1;
        int *arg2_create = esp_pointer + 2;
        check_valid_pointer(arg1_create);
        check_valid_pointer(arg2_create);
        char *file_name_create = (char *) *(esp_pointer + 1);
        check_valid_pointer (file_name_create);
        
        lock_acquire(&filesys_lock); 
        f->eax = filesys_create (file_name_create,*(esp_pointer + 2));
        lock_release(&filesys_lock);
        break;

      case SYS_OPEN: ;
        int *arg1_open = esp_pointer + 1;
        check_valid_pointer(arg1_open);
        const char *file_name_open = (char *) *(esp_pointer + 1);
        check_valid_pointer (file_name_open);
        f->eax = file_open_syscall(file_name_open);
        break;

      case SYS_CLOSE: ;
        int *arg1_close = esp_pointer + 1;
        check_valid_pointer(arg1_close);
        int fd_close = *(esp_pointer + 1);
        file_close_syscall(fd_close);
        break;

      case SYS_TELL: ;
        int *arg1_tell = esp_pointer + 1;
        check_valid_pointer(arg1_tell);
        int fd_tell = *(esp_pointer + 1);
        lock_acquire(&filesys_lock);
        struct file *file_struct_tell = thread_get_file_struct(fd_tell);
        if(file_struct_tell){
          f->eax = file_tell(file_struct_tell);
        } else {
          f->eax = -1;
        }
        lock_release(&filesys_lock);
        break;
      
      case SYS_SEEK: ;
        int *arg1_seek = esp_pointer + 1;
        int *arg2_seek = esp_pointer + 2;
        check_valid_pointer(arg1_seek);
        check_valid_pointer(arg2_seek);
        int fd_seek = *(esp_pointer + 1);

        lock_acquire(&filesys_lock);
        struct file *file_struct_seek = thread_get_file_struct(fd_seek);
        if(file_struct_seek){
          //unsigned position = (unsigned) *(esp_pointer + 2);
          file_seek(fd_seek,*(esp_pointer + 2));
        }
        lock_release(&filesys_lock);
        break;

      default:
        exit_process(-1);
        break;
    }



}
