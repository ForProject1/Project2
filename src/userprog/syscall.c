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
#include "userprog/pagedir.h"

typedef int pid_t;
#define PID_ERROR ((pid_t) -1)



struct file_descripter {
	struct list_elem elem;
	struct file* file;
	int fd;
};


struct semaphore* file_sema;

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
bool is_valid_addr(void * esp);
bool is_valid_filename(const char * file_name);


void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  init_sema(&file_sema, 1);
}

bool is_valid_addr(void * esp){


	void * pt;

	if( (uint32_t *)(esp + 3) > PHYS_BASE)
		return false;
	
	else if( (uint32_t *)(esp) < 0x08048000)
		return false;

	else if((pt = pagedir_get_page (thread_current()->pagedir, esp)) == NULL) 
		return false;

	else
		return true;
}

bool is_valid_filename(const char * file_name){

	if ( strlen(file_name) > 14 || strlen(file_name) == 0)
		return false;

	return true;
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{

  //printf("syscall number: %d\n", *(uint32_t *)(f->esp));
  //printf ("system call!\n");
  //hex_dump(f->esp, f->esp, 100, 1);
 
  if(!is_valid_addr(f->esp))
	exit(-1);

  switch (*(uint32_t *)(f->esp)) {
	case SYS_HALT:
		halt();
		break;

	case SYS_EXIT:
		if(!is_valid_addr(f->esp + 4))
			exit(-1);

		exit(*(uint32_t *)(f->esp + 4));
		break;
	
	case SYS_EXEC:
		if(!is_valid_addr(f->esp + 4))
			exit(-1);

		if(!is_valid_addr(*(uint32_t *)(f->esp + 4)))
			exit(-1);

		f->eax = exec(*(uint32_t *)(f->esp + 4));
		break;

	case SYS_WAIT:
		if(!is_valid_addr(f->esp + 4))
			exit(-1);

		f->eax = wait(*(uint32_t *)(f->esp + 4));
		break;

	case SYS_CREATE:	
		if (!is_valid_addr(f->esp + 4) || !is_valid_addr(f->esp + 8))
			exit(-1);

		if(!is_valid_addr(*(uint32_t *)(f->esp + 4)) )
			exit(-1);

		f->eax = create(*(uint32_t*)(f->esp+4), *(uint32_t*)(f->esp+8));
		
		break;

	case SYS_REMOVE:
		if (!is_valid_addr(f->esp + 4))
			exit(-1);

		if(!is_valid_addr(*(uint32_t *)(f->esp + 4)) )
			exit(-1);

		f->eax = remove(*(uint32_t *)(f->esp + 4));
		break;

	case SYS_OPEN:
		if (!is_valid_addr(f->esp + 4))
			exit(-1);

		if(!is_valid_addr(*(uint32_t *)(f->esp + 4)) )
			exit(-1);

		f->eax = open(*(uint32_t *)(f->esp + 4));
		break;

	case SYS_FILESIZE:
		if (!is_valid_addr(f->esp + 4))
			exit(-1);

		f->eax = filesize(*(uint32_t *)(f->esp + 4));
		break;

	case SYS_READ:
		if (!is_valid_addr(f->esp + 4) || !is_valid_addr(f->esp + 8) || !is_valid_addr(f->esp + 12))
			exit(-1);

		if(!is_valid_addr(*(uint32_t *)(f->esp + 8)))
			exit(-1);

		f->eax = read(*(uint32_t *)(f->esp + 4), *(uint32_t *)(f->esp + 8), *(uint32_t *)(f->esp + 12));
		break;

	case SYS_WRITE:
		if(!is_valid_addr(f->esp + 4) || !is_valid_addr(f->esp + 8) || !is_valid_addr(f->esp + 12))
			exit(-1);

		if(!is_valid_addr(*(uint32_t *)(f->esp + 8)))
			exit(-1);

		f->eax = write(*(uint32_t *)(f->esp + 4), *(uint32_t *)(f->esp + 8), *(uint32_t *)(f->esp + 12));
		break;

	case SYS_SEEK:
		if(!is_valid_addr(f->esp + 4) || !is_valid_addr(f->esp + 8))
			exit(-1);
		seek(*(uint32_t *)(f->esp + 4), *(uint32_t *)(f->esp + 8));
		break;

 	case SYS_TELL:
		if (!is_valid_addr(f->esp + 4))
			exit(-1);

		f->eax = tell(*(uint32_t *)(f->esp + 4));
		break;

	case SYS_CLOSE: 
		if (!is_valid_addr(f->esp + 4))
			exit(-1);

		close(*(uint32_t *)(f->esp + 4));
		break;


	default:
		exit(-1);
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

	if(file == NULL){
		return false;
	}

	return filesys_create(file,initial_size);
}

bool remove(const char *file) {
	return filesys_remove(file);
}

int open(const char *file) {
	struct file* f;
	struct file_descripter* fd_ptr;

	f = filesys_open(file);

	if (f == NULL ||  !is_valid_filename (file) ){
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

	if (fd == 1){
		putbuf(buffer, size);
		return size;
	}

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
	if ((f = search_fd(fd))  == NULL)
		exit(-1);
	else {
		list_remove(&f->elem);
		file_close(f->file);
		free(f);
	}
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































