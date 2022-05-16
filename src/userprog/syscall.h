#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "lib/user/syscall.h"
#include "lib/stdbool.h"

#ifdef VM
#include "vm/tables.h"
#endif

bool check_user_addr(const void* addr, unsigned size);
bool check_valid_string(const char* str_start);

void halt (void);
void exit (int status);
pid_t exec (const char *cmd_line);
int wait (pid_t pid);
int write (int fd, const void *buffer, unsigned size);
int open (const char *file);

/* Not implemented yet. */
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned size);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);



void syscall_init (void);

#endif /**< userprog/syscall.h */
