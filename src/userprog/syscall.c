#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "devices/timer.h"
#include "filesys/file.h"
#include "threads/synch.h"


#define max(x, y) (x) > (y) ? (x) : (y)

struct lock filesys_lock;

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&filesys_lock);
}

static void
syscall_handler (struct intr_frame *f) 
{
  switch(*(uint32_t *)(f->esp)){
    case SYS_HALT:
      halt();
      break;
    case SYS_EXIT:
      is_valid_addr(f->esp + 4);
      exit(*(uint32_t *)(f->esp + 4));
      break;
    case SYS_EXEC:
      is_valid_addr(f->esp + 4);
      f->eax = exec((const char *) *(uint32_t *)(f->esp + 4));
      break;
    case SYS_WAIT:
      is_valid_addr(f->esp + 4);
      f->eax = wait((pid_t) *(uint32_t *)(f->esp + 4));
      break;
    case SYS_CREATE:
      is_valid_addr(f->esp+4);
      is_valid_addr(f->esp+8);
      f->eax = create((const char *) *(uint32_t *)(f->esp + 4), (unsigned) *(uint32_t *)(f->esp + 8));
      break;
    case SYS_REMOVE:
      is_valid_addr(f->esp+4);
      f->eax = remove((const char *) *(uint32_t *)(f->esp + 4));
      break;
    case SYS_OPEN:
      is_valid_addr(f->esp+4);
      f->eax = open((const char *) *(uint32_t *)(f->esp + 4));
      break;
    case SYS_FILESIZE:
      is_valid_addr(f->esp+4);
      f->eax = filesize((int) *(uint32_t *)(f->esp + 4));
      break;
    case SYS_READ:
      is_valid_addr(f->esp + 4);
      is_valid_addr(f->esp + 8);
      is_valid_addr(f->esp + 12);
      f->eax = read((int) *(uint32_t *)(f->esp + 4), (void *) *(uint32_t *)(f->esp + 8), (unsigned) *(uint32_t *)(f->esp + 12));
      break;  
    case SYS_WRITE:
      is_valid_addr(f->esp + 4);
      is_valid_addr(f->esp + 8);
      is_valid_addr(f->esp + 12);
      f->eax = write((int) *(uint32_t *)(f->esp + 4), (const void *) *(uint32_t *)(f->esp + 8), (unsigned) *(uint32_t *)(f->esp + 12));
      break;
    case SYS_SEEK:
      is_valid_addr(f->esp+4);
      is_valid_addr(f->esp+8);
      seek((int) *(uint32_t *)(f->esp + 4), (unsigned) *(uint32_t *)(f->esp + 8));
      break;
    case SYS_TELL:
      is_valid_addr(f->esp+4);
      f->eax = tell((int) *(uint32_t *)(f->esp + 4));
      break;
    case SYS_CLOSE:
      is_valid_addr(f->esp+4);
      close((int) *(uint32_t *)(f->esp + 4));
      break;
    case SYS_FIBO:
      is_valid_addr(f->esp + 4);
      f->eax = fibonacci((int) *(uint32_t *)(f->esp + 4));
      break;
    case SYS_MAX:
      is_valid_addr(f->esp + 4);
      is_valid_addr(f->esp + 8);
      is_valid_addr(f->esp + 12);
      is_valid_addr(f->esp + 16);
      f->eax = max_of_four_int((int) *(uint32_t *)(f->esp + 4), (int) *(uint32_t *)(f->esp + 8), (int) *(uint32_t *)(f->esp + 12), (int) *(uint32_t *)(f->esp + 16));
      break;
  }

  //thread_exit ();
}

void halt (void) 
{
  shutdown_power_off();
}

void exit (int status) 
{
  thread_current()->exit_status = status;
  printf("%s: exit(%d)\n", thread_name(), status);
	for(int i = 2; i < 128; i++){
		if(thread_current()->fd_table[i] != NULL) {
			close(i);
		}
	}
  thread_exit();
}

pid_t exec (const char *cmd_line)
{
  return process_execute(cmd_line);
}

int wait (pid_t pid)
{ 
  return process_wait(pid);
}

int read (int fd, void *buffer, unsigned size)
{
  is_valid_addr(buffer);
  if(fd < 0 || fd >= 128) exit(-1);

  lock_acquire(&filesys_lock);

  unsigned cnt = 0;
  if(fd == 0) {
    for(cnt = 0; cnt < size; cnt++){
      uint8_t tmp = input_getc();
      if(tmp == '\0') break;
      *(uint8_t *)(buffer + cnt) = tmp;
    }
    lock_release(&filesys_lock);
    return cnt;
  }
  
  struct file * f = get_file_with_fd(fd);
  if(f == NULL) {
    lock_release(&filesys_lock);
    return -1;
  }

  int ret = file_read(f, buffer, size);
  lock_release(&filesys_lock);

  return ret;
}

int write (int fd, const void *buffer, unsigned size)
{
  is_valid_addr(buffer);
  if(fd < 0 || fd >= 128) exit(-1);

  lock_acquire(&filesys_lock);

  if(fd == 1) {
    putbuf(buffer, size);
    lock_release(&filesys_lock);
    return size;
  }

  struct file * f = get_file_with_fd(fd);
  if(f == NULL) {
    lock_release(&filesys_lock);
    return -1;
  }

  int ret = file_write(f, buffer, size);
  lock_release(&filesys_lock);

  return ret;
}

int fibonacci (int n)
{ 
  int ret = 0;
  for(int i = 1; i <= n; i++){
    ret += i;
  }
  return ret;
}

int max_of_four_int (int a, int b, int c, int d)
{
  int maxv = max(a, b);
  maxv = max(maxv, c);
  maxv = max(maxv, d);
  return maxv;
}

void is_valid_addr (const void *vaddr)
{
  if(vaddr == NULL) exit(-1);
  if(is_kernel_vaddr(vaddr)) exit(-1);
  if(pagedir_get_page(thread_current()->pagedir, vaddr) == NULL) exit(-1);
}

bool create(const char *file, unsigned initial_size)
{
  if(file == NULL) exit(-1);

  lock_acquire(&filesys_lock);
	bool ret = filesys_create(file, initial_size);
	lock_release(&filesys_lock);

  return ret;
}

bool remove (const char *file)
{	
	if(file == NULL) exit(-1);

	lock_acquire(&filesys_lock);
	bool ret = filesys_remove(file);
	lock_release(&filesys_lock);

  return ret;
}

int open (const char *file)
{
  if(file == NULL) exit(-1);

  lock_acquire(&filesys_lock);
  struct file * f = filesys_open(file);
  
  if(f == NULL) {
    lock_release(&filesys_lock);
    return -1;
  }

  struct thread *t = thread_current();
 
  if(!strcmp(thread_name(), file)) file_deny_write(f);

  for(int fd = 2; fd < 128; fd++){
    if(t->fd_table[fd] == NULL) {
      t->fd_table[fd] = f;
      lock_release(&filesys_lock);
      return fd;
    }
  }
  
  file_close(f);
  lock_release(&filesys_lock);
  return -1;
}

int filesize (int fd)
{
	lock_acquire(&filesys_lock);	
  struct file * f = get_file_with_fd(fd);
  if(f == NULL) {
		lock_release(&filesys_lock);
		return -1;
	}
	
	int ret = file_length(f);
	lock_release(&filesys_lock);	

  return file_length(f);
}

void seek (int fd, unsigned position)
{	
	lock_acquire(&filesys_lock);
  struct file * f = get_file_with_fd(fd);
  if(f == NULL) {
		lock_release(&filesys_lock);
		return;
	}

  file_seek(f, position);
	lock_release(&filesys_lock);
}

unsigned tell (int fd)
{
	lock_acquire(&filesys_lock);
  struct file * f = get_file_with_fd(fd);
  if(f == NULL) {
		lock_release(&filesys_lock);
		return; 
	}
	
	unsigned ret = file_tell(f);
	lock_release(&filesys_lock);

  return ret;
}

void close (int fd)
{
  lock_acquire(&filesys_lock);
  struct file * f = get_file_with_fd(fd);
  if(f == NULL) {
    lock_release(&filesys_lock);
    return;
  }

  thread_current()->fd_table[fd] = NULL;
  file_close(f);
  lock_release(&filesys_lock);
}

struct file * get_file_with_fd(int fd)
{
  if(fd < 2 || fd >= 128) return NULL;
  return thread_current()->fd_table[fd];
}
