#include <linux/init.h>
#include <linux/kd.h>
#include <linux/kernel.h>
#include <linux/tracehook.h>
#include <linux/errno.h>
#include <linux/ext2_fs.h>
#include <linux/sched.h>
#include <linux/security.h>
#include <linux/xattr.h>
#include <linux/capability.h>
#include <linux/unistd.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <linux/proc_fs.h>
#include <linux/swap.h>
#include <linux/spinlock.h>
#include <linux/syscalls.h>
#include <linux/dcache.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/namei.h>
#include <linux/mount.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/tty.h>
#include <net/icmp.h>
#include <net/ip.h>		/* for local_port_range[] */
#include <net/tcp.h>		/* struct or_callable used in sock_rcv_skb */
#include <net/inet_connection_sock.h>
#include <net/net_namespace.h>
#include <net/netlabel.h>
#include <linux/uaccess.h>
#include <asm/ioctls.h>
#include <linux/atomic.h>
#include <linux/bitops.h>
#include <linux/interrupt.h>
#include <linux/netdevice.h>	/* for network interface checks */
#include <linux/netlink.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/dccp.h>
#include <linux/quota.h>
#include <linux/un.h>		/* for Unix socket types */
#include <net/af_unix.h>	/* for Unix socket types */
#include <linux/parser.h>
#include <linux/nfs_mount.h>
#include <net/ipv6.h>
#include <linux/hugetlb.h>
#include <linux/personality.h>
#include <linux/audit.h>
#include <linux/string.h>
#include <linux/selinux.h>
#include <linux/mutex.h>
#include <linux/posix-timers.h>
#include <linux/syslog.h>
#include <linux/user_namespace.h>
#include <linux/export.h>


#ifdef CONFIG_SECURITY_COMPSEC 


struct file_class {
  unsigned int class;
};


////________________________________________________________________________________________

/* binprm security operations - function-* ours */ 
static int compsec_bprm_set_creds(struct linux_binprm *bprm){
	struct file_class* cls = bprm->cred->security;
	unsigned int class;
	int cap_res = cap_bprm_set_creds(bprm);
    if (cap_res != 0) return cap_res;
    if (bprm->cred_prepared) return 0;
	int get_res = vfs_getxattr(bprm->file->f_path.dentry, "security.compsec", &class, sizeof(unsigned int));
	if (get_res < 0)
	    class = 0;

    cls->class = class;//changed cred to bprm
	return 0;
}



/* file security operations ours */

static int compsec_file_permission(struct file *file, int mask){
	//unsigned int* file_class_res=NULL;
	unsigned int classificationlevel=0;
	struct inode *inode = file->f_path.dentry->d_inode;
	struct file_class* user_class;
	char* fname=NULL;
	int get_res;
	fname = file->f_path.dentry->d_name.name;//not the full file name

	user_class = (struct file_class*)current_security();

	if (task_tgid_nr(current) == 1 || task_pid_nr(current) == 1) return 0;
	if(inode->i_rdev) return 0; // we are not enforcing on char/block devices, rdev will tell as what kind of file this is
	
	get_res = vfs_getxattr(file->f_path.dentry, "security.compsec", &classificationlevel, sizeof(unsigned int));
	if (get_res < 0){
		classificationlevel = 0;
	}
	if (mask & MAY_READ){
		if(classificationlevel > user_class->class){
			printk("compsec: Illegal reading! User %d with classificationlevel %u can't read file %s with classificationlevel %u\n", current_uid(), user_class->class, fname, classificationlevel);
			return -EACCES;
		}
	}
	else if(mask & MAY_WRITE){
		if(classificationlevel < user_class->class){
			printk("compsec: Illegal writing! User %d with classificationlevel %u can't write to file %s with classificationlevel %u\n", current_uid(), user_class->class, fname, classificationlevel);
			return -EACCES;
		}
	}
	return 0;
}

/*
 * allocate the SELinux part of blank credentials
 ours
 */

static int compsec_cred_alloc_blank(struct cred *cred, gfp_t gfp){
	struct file_class* file_data;
    file_data = (struct file_class*)kzalloc(sizeof(struct file_class), gfp);
	if(!file_data){
		return -ENOMEM;
	}
	file_data->class = 0;
	cred->security=file_data;
	return 0;
}

/*
 * detach and free the LSM part of a set of credentials
														ours
 */

static void compsec_cred_free(struct cred *cred){
    if (!cred) return;
    kfree(cred->security);
	}

/*Selinux
struct file_class *tsec = cred->security;

BUG_ON(cred->security && (unsigned long) cred->secuirty < PAGE_SIZE);
cred->security = (void *) 0x7UL;
kfree(tsec);

*/

/*
 * prepare a new set of credentials for modification
 ours
 */
static int compsec_cred_prepare(struct cred *new, const struct cred *old,
				gfp_t gfp){
    /*
        if(!new||!old) return 0;
        new->security = kzalloc(sizeof(struct file_class),gfp);
        if(!new->security)
			return -ENOMEM;
        if (!old->security)
            new->security->class = 0;
         else
             new->security->class =  old->security->class;
    return 0;
    }
*/
	const struct file_class *old_tsec = old->security;
	struct file_class *tsec = kzalloc(sizeof(struct file_class), gfp);
	if(!tsec)
			return -ENOMEM;
    if (!old_tsec)
        tsec->class = 0;
    else
	    tsec->class = old_tsec->class;
	new->security = tsec;
    return 0;
}


/*
 * transfer the SELinux data to a blank set of creds
 ours
 */
static void compsec_cred_transfer(struct cred *new, const struct cred *old) {
    if (new == NULL) return;
    if(old == NULL) return;
    struct file_class *old_tsec = old->security;
	struct file_class *tsec = new->security;
	tsec->class = old_tsec->class;

}


/**
 * compsec_skb_peerlbl_sid - Determine the peer label of a packet
 * @skb: the packet
 * @family: protocol family
 * @sid: the packet's peer label SID
 *
 * Description:
 * Check the various different forms of network peer labeling and determine
 * the peer label/SID for the packet; most of the magic actually occurs in
 * the security server function security_net_peersid_cmp().  The function
 * returns zero if the value in @sid is valid (although it may be SECSID_NULL)
 * or -EACCES if @sid is invalid due to inconsistencies with the different
 * peer labels.
 *
 */


/**
 * compsec_conn_sid - Determine the child socket label for a connection
 * @sk_sid: the parent socket's SID
 * @skb_sid: the packet's SID
 * @conn_sid: the resulting connection SID
 *
 * If @skb_sid is valid then the user:role:type information from @sk_sid is
 * combined with the MLS information from @skb_sid in order to create
 * @conn_sid.  If @skb_sid is not valid then then @conn_sid is simply a copy
 * of @sk_sid.  Returns zero on success, negative values on failure.
 *
 */








static struct security_operations compsec_ops = {
  .name =				"compsec",
  .bprm_set_creds =		compsec_bprm_set_creds,
  .file_permission =		compsec_file_permission,
  .cred_alloc_blank =		compsec_cred_alloc_blank,
  .cred_free =			compsec_cred_free,
  .cred_prepare =			compsec_cred_prepare,
  .cred_transfer =		compsec_cred_transfer

};

static __init int compsec_init(void)
{
	struct cred *cred;
	struct file_class* fc = kzalloc(sizeof(struct file_class*),0); 
  if (!security_module_enable(&compsec_ops)) {
    printk("compsec: disabled at boot.\n");
    return 0;
  }
    ///changed to dynamic allocation din
     fc->class = 0;
     //current_cred()->security = fc;//changed from cred->security
	cred = (struct cred *) current->cred;
	cred->security = fc;
  if (register_security(&compsec_ops))
    panic("compsec: Unable to register compsec with kernel.\n");
  else 
    printk("compsec: registered with the kernel\n");

  return 0;
}

static void __exit compsec_exit (void)
{	
  return;
}



module_init (compsec_init);
module_exit (compsec_exit);

/* MODULE_DESCRIPTION("compsec");
   MODULE_LICENSE("GPL"); */
#endif /* CONFIG_SECURITY_compsec */

