#include <string.h>
#include <stdio.h>
#include <ftw.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <stdlib.h>
#include <unistd.h>

unsigned int new_class ;
const struct stst *s;
struct FTW *ft;

//static unsigned int new_class;
void change_class(const char* path, const struct stst *s, int tflag, struct FTW *ft){
	 setxattr(path, "security.compsec", &new_class, sizeof(unsigned int), 0);
}

void main(int argc, char* argv[]){
	if (argc > 5 || argc < 4) return; //invalid values.
	new_class = strtoul(argv[2],NULL,10);
	if (new_class < 0 || new_class > 3) return; //invalid values.
	int f_index = 3;
	unsigned int file_class;
	if (argc > 4) // with/without the flag -r 
		f_index = 4;
	if (access(argv[f_index], F_OK) != 0)
		 return; //invalid path - file doesn't exist
	int get_res = getxattr(argv[f_index], "security.compsec", &file_class, sizeof(unsigned int));
	if (get_res < 0)
		file_class=0;
	if (file_class == new_class) {
		return;
		} /// changing to the same class does nothing.
	if (file_class > new_class){
		printf("If you want to lower the class type y(es):\n");
		char res = getchar(); 
		if (res != 'y' && res != 'Y') return; //if user doesn't want to lower the class
	}
	if (f_index == 4 && (strcmp(argv[3], "-r") == 0)){ ///change class for all files in subtree
		nftw(argv[f_index], &change_class, 15, 0);	
	} else {
		int set_res = setxattr(argv[f_index], "security.compsec", &new_class, sizeof(unsigned int), 0);
	}
}









