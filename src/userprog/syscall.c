#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/shutdown.h"
#include "userprog/process.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "lib/string.h"

typedef int pid_t;
#define PID_ERROR ((pid_t) -1)



static void syscall_handler (struct intr_frame *);

void halt( void );
void exit( int status);
pid_t exec (const char *cmd_line);
int wait (pid_t pid);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned size);
int write(int fd, const void *buffer, unsigned size);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);


void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{

  //printf("syscall number: %d\n", *(uint32_t *)(f->esp));
  //printf ("system call!\n");
  //hex_dump(f->esp, f->esp, 100, 1);
 
  if(!is_user_vaddr(f->esp) || (f->esp) < 0x08048000)
	exit(-1);

  switch (*(uint32_t *)(f->esp)) {
	case SYS_HALT:
		halt();
		break;

	case SYS_EXIT:
		if(!is_user_vaddr(f->esp + 4))
			exit(-1);

		exit(*(uint32_t *)(f->esp + 4));
		break;
	
	case SYS_EXEC:
		if(!is_user_vaddr(f->esp + 4) || !is_user_vaddr(f->esp + 4 + strlen((f->esp + 4))))
			exit(-1);

		f->eax = exec(*(uint32_t *)(f->esp + 4));
		break;

	case SYS_WAIT:
		if(!is_user_vaddr(f->esp + 4))
			exit(-1);

		f->eax = wait(*(uint32_t *)(f->esp + 4));
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
		break;

	case SYS_WRITE:
		if(!is_user_vaddr(f->esp + 4) || !is_user_vaddr(f->esp + 8) || !is_user_vaddr(f->esp + 12))
			exit(-1);

		f->eax = write(*(uint32_t *)(f->esp + 4), *(uint32_t *)(f->esp + 8), *(uint32_t *)(f->esp + 12));
		break;

	case SYS_SEEK:
		break;

 	case SYS_TELL:
		break;

	case SYS_CLOSE: 
		break;
  }
  

}


int
c(){
}


void halt( void ){
  shutdown_power_off();
}

void exit( int status){
  printf("%s: exit(%d)\n", thread_name(), status);
  thread_current()->thread_exit_status = status;
  thread_exit();
}

pid_t exec (const char *cmd_line){
	return process_execute(cmd_line);
}


int wait (pid_t pid){
	
	return process_wait(pid);
}
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned size);
int write(int fd, const void *buffer, unsigned size){

  if (fd == 1){
	putbuf(buffer,size);
	return size;
  }

  return -1;
}
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);

































