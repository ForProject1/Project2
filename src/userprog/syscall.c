#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <string.h>
#include <list.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/shutdown.h"
#include "userprog/process.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "filesys/filesys.h"
#include "filesys/file.h"

typedef int pid_t;
#define PID_ERROR ((pid_t) -1)



struct file_descripter {
	struct list_elem elem;
	struct file* file;
	int fd;
};


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
struct file_descripter* search_fd(int fd);


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
		if (!is_user_vaddr(f->esp + 4) || !is_user_vaddr(f->esp + 4) || !is_user_vaddr(f->esp + 4 + strlen((f->esp + 4))))
			exit(-1);

		f->eax = create(*(char *)(f->esp + 4), *(uint32_t *)(f->esp + 8));
		break;

	case SYS_REMOVE:
		if (!is_user_vaddr(f->esp + 4))
			exit(-1);

		f->eax = remove(*(uint32_t *)(f->esp + 4));
		break;

	case SYS_OPEN:
		if (!is_user_vaddr(f->esp + 4))
			exit(-1);

		f->eax = open(*(uint32_t *)(f->esp + 4));
		break;

	case SYS_FILESIZE:
		if (!is_user_vaddr(f->esp + 4))
			exit(-1);

		f->eax = filesize(*(uint32_t *)(f->esp + 4));
		break;

	case SYS_READ:
		if (!is_user_vaddr(f->esp + 4) || !is_user_vaddr(f->esp + 8) || !is_user_vaddr(f->esp + 12))
			exit(-1);

		f->eax = read(*(uint32_t *)(f->esp + 4), *(uint32_t *)(f->esp + 8), *(uint32_t *)(f->esp + 12));
		break;

	case SYS_WRITE:
		if(!is_user_vaddr(f->esp + 4) || !is_user_vaddr(f->esp + 8) || !is_user_vaddr(f->esp + 12))
			exit(-1);

		f->eax = write(*(uint32_t *)(f->esp + 4), *(uint32_t *)(f->esp + 8), *(uint32_t *)(f->esp + 12));
		break;

	case SYS_SEEK:
		f(!is_user_vaddr(f->esp + 4) || !is_user_vaddr(f->esp + 8))
			exit(-1);
		seek(*(uint32_t *)(f->esp + 4), *(uint32_t *)(f->esp + 8));
		break;

 	case SYS_TELL:
		if (!is_user_vaddr(f->esp + 4))
			exit(-1);

		f->eax = tell(*(uint32_t *)(f->esp + 4));
		break;

	case SYS_CLOSE: 
		break;
  }
  

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
bool create(const char *file, unsigned initial_size) {
	return filesys_create(file,initial_size);
}

bool remove(const char *file) {
	return filesys_remove(file);
}

int open(const char *file) {
	struct file* f;
	struct file_descripter* fd_ptr;

	f = filesys_open(file);

	if (f == NULL){
		return -1;
	} else {
		fd_ptr = malloc(sizeof(struct file_descripter));
		fd_ptr->fd = thread_current()->fd_count++;
		fd_ptr->file = f;
		list_push_back(&thread_current()->fd_list, &fd_ptr->elem);
		return fd_ptr->fd;
	}
}

int filesize (int fd) {
	struct file_descripter* f;
	f = search_fd(fd);
 
	if (f == NULL) {
		return -1;
	}
	else {
		return file_length(f->file);
	}
}

int read(int fd, void *buffer, unsigned size) {
	struct file_descripter* f;
	f = search_fd(fd);

	if (f == NULL) {
		return -1;
	}
	else {
		return file_read(f->file,buffer,size);
	}
}

int write(int fd, const void *buffer, unsigned size){
	struct file_descripter* f;
	f = search_fd(fd);

	if (f == NULL) {
		return -1;
	}
	else {
		return file_write(f->file, buffer, size);
	}
}
void seek(int fd, unsigned position) {
	struct file_descripter* f;
	f = search_fd(fd);
    file_seek(f->file, position);
}

unsigned tell(int fd) {
	struct file_descripter* f;
	f = search_fd(fd);
	return file_tell(f->file);
}

void close(int fd) {
	struct file_descripter* f;
	f = search_fd(fd);
	list_remove(&f->elem);
	file_close(f->file);
	free(f);
}



struct file_descripter*
search_fd(int fd) {
	struct list_elem *e;
	struct list *fd_list;

	fd_list = &thread_current()->fd_list;


	for (e = list_begin(fd_list); e != list_end(fd_list); e = list_next(e))
	{
		struct file_descripter *fd_ptr = list_entry(e, struct file_descripter, elem);
		if (fd_ptr->fd == fd) {
			return fd_ptr;
		}
	}
	return NULL;
}































