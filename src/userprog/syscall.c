#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

#define max(x, y) (x) > (y) ? (x) : (y)

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
  switch(*(uint32_t *)(f->esp)){
    case SYS_HALT:
      halt();
      break;
    case SYS_EXIT:
      // printf("esp : %p\n", f->esp);
      // printf("[%d]\n", *(uint32_t *)(f->esp + 4));
      // hex_dump(f->esp, f->esp, 100, 1);
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
      break;
    case SYS_REMOVE:
      break;
    case SYS_OPEN:
      break;
    case SYS_FILESIZE:
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
      break;
    case SYS_TELL:
      break;
    case SYS_CLOSE:
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
  unsigned cnt = 0;
  if(fd == 0) {
    for(cnt = 0; cnt < size; cnt++){
      uint8_t tmp = input_getc();
      if(tmp == '\0') break;
      *(uint8_t *)(buffer + cnt) = tmp;
    }
    return cnt;
  }
  return -1;
}

int write (int fd, const void *buffer, unsigned size)
{
  if(fd == 1) {
    putbuf(buffer, size);
    return size;
  }
  return -1;
}

int fibonacci(int n)
{ 
  int ret = 0;
  for(int i = 1; i <= n; i++){
    ret += i;
  }
  return ret;
}

int max_of_four_int(int a, int b, int c, int d)
{
  int maxv = max(a, b);
  maxv = max(maxv, c);
  maxv = max(maxv, d);
  return maxv;
}

void is_valid_addr(const void *vaddr)
{
  if(vaddr == NULL) exit(-1);
  if(is_kernel_vaddr(vaddr)) exit(-1);
  if(pagedir_get_page(thread_current()->pagedir, vaddr) == NULL) exit(-1);
}