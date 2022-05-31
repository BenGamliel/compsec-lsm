# compsec-lsm Debian7
simplified mandatory access control module using the LSM framework 

the module is an implementation of the MLS policy working mimicing Bel-Lapadula metholodgy 
a process with C clearense level could read files with C clearense and blow, and write to
files with C clearense and above (0<=C<=3)
file propertiy is stored as an extended attribute in the security name space
a forked process will inherit his "father" clearense 

use setfclass,getfclass to control the module 
the module is using lsm hooks and extendad attributes to implement the Bell-Lapadula module

its recommended to backup the kernel image before making any changes, with make bzimage
the new image will be saved under arch/x86/boot/bzimage
load you new image to boot/vmlinuz-x.x.xx/ and reboot the system
