#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "lib/user/syscall.h"


void syscall_init (void);
void halt (void);
void exit (int);
pid_t exec (const char *);
int wait (pid_t);
int read (int, void *, unsigned);
int write (int, const void *, unsigned);
int fibonacci (int);
int max_of_four_int (int, int, int, int);
void is_valid_addr(const void *);

bool create(const char *, unsigned);
bool remove(const char *);
int open(const char *);
int filesize(int);
void seek(int, unsigned);
unsigned tell(int);
void close(int);
struct file * get_file_with_fd(int);


#endif /* userprog/syscall.h */
