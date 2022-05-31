#include <stdio.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <unistd.h>

void main(int argc, char* argv[]){
	unsigned int file_class;
	if (access(argv[1], F_OK) != 0)
		 return; //invalid path - file doesn't exist
	int get_res = getxattr(argv[1], "security.compsec", &file_class, sizeof(unsigned int));
	if (get_res < 0) { //error from getxattr
		file_class = 0;
	}
	printf("%x\n", file_class);
}

