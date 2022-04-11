#include "userprog/syscall.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "lib/user/syscall.h"
#include "lib/string.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "devices/input.h"

static void syscall_handler (struct intr_frame *);

int open (const char *file)  // TODO: now we assume all files are executables.
{
  struct file* f = filesys_open(file);
  struct thread* cur = thread_current();
  if (f == NULL) // File opening failed.
    return -1;
  else
  {
    struct opened_file* of = malloc(sizeof(struct opened_file));
    of->fd = cur->fd_to_alloc;
    cur->fd_to_alloc += 1;
    of->f = f;
    list_push_back(&cur->all_files, &of->elem);
    return of->fd;
  }
}
void close (int fd)
{
  if (fd < 2)  // Try to close stdin or stdout.
    return;
  struct opened_file* of = get_of_by_fd(fd);
  if (of != NULL)
  {
    list_remove(&of->elem);
    file_close(of->f);
  }
}

int read (int fd, void *buffer, unsigned size)
{
  if (fd == 0)  // Read from stdin. TODO: what if number of characters less than size?
  {
    for (unsigned i = 0; i < size; i++)
      *((char*)buffer + i) = input_getc();
  }
  else if (fd == 1 || fd < 0 || get_of_by_fd(fd) == NULL) // Try to read from stdout, or an invalid fd.
    exit(-1);
  return file_read(get_of_by_fd(fd)->f, buffer, size);
}

int write (int fd, const void *buffer, unsigned size)
{
  if (fd == 1) // Writes to the console.
  {
    putbuf(buffer, size);
    return size;    
  }
  else if (fd <= 0 || get_of_by_fd(fd) == NULL)
    exit(-1);
  else
  {
    return file_write(get_of_by_fd(fd)->f, buffer, size);
  }
}

bool create (const char *file, unsigned initial_size)
{
  return filesys_create(file, initial_size);
}

bool remove (const char *file)
{
  return filesys_remove(file);
}

int filesize (int fd)
{
  return file_length(get_of_by_fd(fd)->f);
}

void seek (int fd, unsigned position)
{
  return file_seek(get_of_by_fd(fd)->f, position);
}

unsigned tell (int fd)
{
  return file_tell(get_of_by_fd(fd)->f);
}


/* Terminates the current user program, returning status to the kernel. */
void exit (int status)
{
  struct thread* cur = thread_current();
  printf ("%s: exit(%d)\n", cur->name, status); // Print termination message. 

  /* 1. If parent is alive, record exit status. */
  enum intr_level old_level;
  old_level = intr_disable ();
  struct thread* parent = cur->parent_proc;
  if (in_all_list(parent))
  {
    if (parent->status != THREAD_DYING)  // Parent is alive.
    {
      struct list_elem *e;      
      struct child_record* rec;
      bool found = false;
      for (e = list_begin (&parent->child_list); e != list_end (&parent->child_list); e = list_next (e))
      {
        rec = list_entry (e, struct child_record, elem);
        if (rec->tid == cur->tid)
        {
          found = true;
          break; 
        }
      }
      ASSERT(found);      
      rec->exit_status = status;
      sema_up(&rec->sema_finish);
    }
  }  
  intr_set_level (old_level);  

  /* 2. Free remaining children's records. */
  if (list_size(&cur->child_list) > 0)
  {
    struct list_elem *e;
    struct child_record* rec;
    for (e = list_begin (&cur->child_list); e != list_end (&cur->child_list); )
    {
      rec = list_entry (e, struct child_record, elem);
      e = list_next (e);
      list_remove(&rec->elem);
      free(rec);
    }
  }

  /* 3. Close all files and free the all_files list. */
  if (list_size(&cur->all_files) > 0)
  {
    struct list_elem *e;
    struct opened_file* of;
    for (e = list_begin (&cur->all_files); e != list_end (&cur->all_files); )
    {
      of = list_entry (e, struct opened_file, elem);
      e = list_next (e);
      list_remove(&of->elem);
      file_close(of->f);
      free(of);
    }
  }

  thread_exit ();
}

/* Runs the executable whose name is given in cmd_line, passing 
   any given arguments, and returns the new process's program id (pid). 
   If the program cannot load or run for any reason, must return pid -1. */
pid_t exec (const char *cmd_line)
{
  struct thread* cur = thread_current();
  cur->load_success = false;
  sema_init(&cur->sema_load, 0);
  
  tid_t tid = process_execute(cmd_line);
  sema_down(&cur->sema_load);
  if (cur->load_success == false) // Child failed to load the ELF.
    return -1;
  else
    return tid;
}

/* Waits for a child process pid and retrieves the child's exit status. */
int wait (pid_t pid)
{
  return process_wait(pid);  
}

/* Terminates Pintos by calling shutdown_power_off(). */
void halt (void)
{
  shutdown_power_off();
}

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

/* Check if address in [addr, addr + size) is legal. */
bool check_user_addr(const void* addr, unsigned size)
{
  if (!is_user_vaddr(addr + size - 1))
    exit(-1);
  for (unsigned i = 0; i < size; i++)
    if (pagedir_get_page(thread_current()->pagedir, addr + i) == NULL)
      exit(-1);
  return true;  
}

/* Check if a string starting from addr is under legal address. */
bool check_valid_string(const char* str_start)
{
  const char* addr = str_start;
  while (true)
  {
    check_user_addr(addr, 4);
    char c = *addr;
    if (c == '\0')  // End of string.
      return true;
    addr += 1;    
  }
  return false;
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  check_user_addr(f->esp, 4);
  switch (*(int*)f->esp)
  {
    case SYS_HALT:
    {
      halt();  
      break;    
    }
    case SYS_EXIT:
    {
      check_user_addr((int*)f->esp + 1, 4);
      int status = *((int*)f->esp + 1);
      exit(status);
      break;      
    }
    case SYS_EXEC:
    {
      check_user_addr((int*)f->esp + 1, 4);
      char* cmd_line = (char*)*((int*)f->esp + 1);
      check_valid_string(cmd_line);
      f->eax = exec(cmd_line);
      break;
    }
    case SYS_WAIT:
    {
      check_user_addr((int*)f->esp + 1, 4);
      pid_t pid = *((int*)f->esp + 1);
      f->eax = wait(pid);
      break;
    }
    case SYS_CREATE:
    {
      check_user_addr((int*)f->esp + 1, 4);
      char* file = (char*)*((int*)f->esp + 1);
      check_valid_string(file);
      check_user_addr((int*)f->esp + 2, 4);
      unsigned initial_size = *((int*)f->esp + 2);
      lock_acquire(&file_lock);
      f->eax = create(file, initial_size);
      lock_release(&file_lock);
      break;
    }
    case SYS_REMOVE:
    {
      check_user_addr((int*)f->esp + 1, 4);
      char* file = (char*)*((int*)f->esp + 1);
      check_valid_string(file);
      lock_acquire(&file_lock);
      f->eax = remove(file);
      lock_release(&file_lock);
      break;
    }
    case SYS_OPEN:
    {
      check_user_addr((int*)f->esp + 1, 4);
      char* file = (char*)*((int*)f->esp + 1);
      check_valid_string(file);
      lock_acquire(&file_lock);
      f->eax = open(file);
      lock_release(&file_lock);
      break;
    }
    case SYS_FILESIZE:
    {
      check_user_addr((int*)f->esp + 1, 4);
      int fd = *((int*)f->esp + 1);
      lock_acquire(&file_lock);
      f->eax = filesize(fd);
      lock_release(&file_lock);
      break;
    }
    case SYS_READ:
    {
      check_user_addr((int*)f->esp + 1, 12);
      int fd = *((int*)f->esp + 1);
      void* buf = (void*)*((int*)f->esp + 2);
      unsigned size = *((int*)f->esp + 3);
      check_user_addr(buf, size);
      lock_acquire(&file_lock);
      f->eax = read(fd, buf, size);
      lock_release(&file_lock);
      break;
    }
    case SYS_WRITE:
    {
      check_user_addr((int*)f->esp + 1, 12);
      int fd = *((int*)f->esp + 1);
      void* buf = (void*)*((int*)f->esp + 2);
      unsigned size = *((int*)f->esp + 3);
      check_user_addr(buf, size);
      lock_acquire(&file_lock);
      f->eax = write(fd, buf, size);
      lock_release(&file_lock);
      break;  
    }
    case SYS_SEEK:
    {
      check_user_addr((int*)f->esp + 1, 8);
      int fd = *((int*)f->esp + 1);
      unsigned position = *((int*)f->esp + 2);
      lock_acquire(&file_lock);
      seek(fd, position);
      lock_release(&file_lock);
      break;
    }
    case SYS_TELL:
    {
      check_user_addr((int*)f->esp + 1, 4);
      int fd = *((int*)f->esp + 1);
      lock_acquire(&file_lock);
      f->eax = tell(fd);
      lock_release(&file_lock);
      break;
    }
    case SYS_CLOSE:
    {
      check_user_addr((int*)f->esp + 1, 4);
      int fd = *((int*)f->esp + 1);
      lock_acquire(&file_lock);
      close(fd);
      lock_release(&file_lock);
      break;
    }    
    default:
      break;
  }
  
}
