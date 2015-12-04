#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include <linux/unistd.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/delay.h>
#include <linux/fs.h>
#include <asm/uaccess.h>
#include <linux/slab.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/kthread.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <net/sock.h>
#include <linux/netlink.h>
#include <linux/time.h>

#include "myargs.h"
#define CRYPTO_TFM_MODE_CBC 0x00000002
#define CRYPTO_ALG_ASYNC 0x00000080
#define AES_BLOCK_SIZE 16
#define PG_SIZE 4096
asmlinkage extern long (*sysptr)(void *arg);

struct job_node {
	//just add int job by one and store the result.
	char *			infile;
	int 			infile_len;
	char *			outfile;
	int 			outfile_len;
	//job_type: 1.encrypt, 2.decrypt, 3.compress, 4.decompress, 5.checksum
	int			job_type;
	int			cancel;
	// token include job_id and pid
	long		job_id;
	int			pid;
	int			err_number;
	int remove_flag;
	unsigned char *		keybuf;
	unsigned int		keylen;
	struct list_head	list;
};

struct error_node {
	long		job_id;
	int			pid;
	int			err_number;
	struct list_head	list;
};

struct mutex *job_queue_lock;
struct mutex *error_queue_lock;

//global job queue
struct job_node *job_head;
struct error_node *error_head;
int threadNum;
static struct task_struct *global_task;
struct sock *netlinkfd;


int send_to_user(char *info, struct sk_buff *__skb, int pid)
{
	int size;
	struct sk_buff *skb;
	unsigned char *old_tail;
	struct nlmsghdr *nlh;

	int ret;

	size = NLMSG_SPACE(strlen(info)) + 1;
	skb = alloc_skb(size, GFP_ATOMIC);

	nlh = nlmsg_put(skb, 0, 0, 0, NLMSG_SPACE(strlen(info) + 1) - sizeof(struct nlmsghdr), 0);
	old_tail = skb->tail;
	memcpy(NLMSG_DATA(nlh), info, strlen(info) + 1);
	nlh->nlmsg_len = skb->tail - old_tail;


	NETLINK_CB(skb).portid = 0;
	NETLINK_CB(skb).dst_group = 0;

	//printk("send_to_user:skb->data:%s\n", (char *)NLMSG_DATA((struct nlmsghdr *)skb->data));


	ret = netlink_unicast(__skb->sk, skb, pid, MSG_DONTWAIT);
	//printk("send_to_user: netlink_unicast return: %d\n", ret);
	return 0;
}

void kernel_receive(struct sk_buff *__skb)
{
	struct sk_buff *skb;
	struct nlmsghdr *nlh = NULL;
	struct request *req;
	struct job_node *a_node, *tmp_node;
	struct error_node *e_node, *tmp_e_node;
	int found = 0;
	char *response, *tmp_string;

	response = kmalloc(40000, GFP_KERNEL);

	//printk("kernel_receive: begin kernel_receive\n");
	skb = skb_get(__skb);

	if (skb->len >= sizeof(struct nlmsghdr)) {

		nlh = (struct nlmsghdr *)skb->data;
		if ((nlh->nlmsg_len >= sizeof(struct nlmsghdr)) && (__skb->len >= nlh->nlmsg_len)) {
			req = (struct request *)NLMSG_DATA(nlh);
			printk("job request:%d\n",req->type);

			if (req->type == 1) { // check a job


				found = 0;
				//printk("kernel_receive: type, pid, job_id receive from user are:%d,%d,%ld\n", req->type, req->pid, req->job_id);

				if (!list_empty(&job_head->list)) {
					list_for_each_entry_safe(a_node, tmp_node, &job_head->list, list) {
						if (a_node->pid == req->pid && a_node->job_id == req->job_id && a_node->cancel == 0) {
							found = 1;
							send_to_user("not finished", skb, nlh->nlmsg_pid);
							break;
						}
					}
				}
				if (!list_empty(&error_head->list)) {
					list_for_each_entry_safe(e_node, tmp_e_node, &error_head->list, list) {
						printk("e_node->pid:%d,req->pid:%d,e_node->job_id:%ld, req->job_id:%ld\n",e_node->pid,req->pid,e_node->job_id, req->job_id);
						if (e_node->pid == req->pid && e_node->job_id == req->job_id) {
							found = 1;
							tmp_string = kmalloc(40000, GFP_KERNEL);
							memcpy(tmp_string, "error occured in doing this task, error number:", strlen("error occured in doing this task, error number:"));
							sprintf(tmp_string + strlen("error occured in doing this task, error number:"), "%d", e_node->err_number);
							memcpy(tmp_string + strlen("error occured in doing this task, error number:")+sizeof(int), "", 1);
							send_to_user(tmp_string, skb, nlh->nlmsg_pid);
							mutex_lock(error_queue_lock);
							list_del(&e_node->list);
							mutex_unlock(error_queue_lock);
							kfree(e_node);
							break;
						}
					}
				}
				if (found == 0)
					send_to_user("finished", skb, nlh->nlmsg_pid);
			} else if (req->type == 2) {// cancel a job
				found = 0;
				//printk("kernel_receive: type, pid, job_id receive from user are:%d,%d,%ld\n", req->type, req->pid, req->job_id);

				if (!list_empty(&job_head->list)) {
					list_for_each_entry_safe(a_node, tmp_node, &job_head->list, list) {
						if (a_node->pid == req->pid && a_node->job_id == req->job_id && a_node->cancel == 0) {
							a_node->cancel = 1;
							found = 1;
							//send_to_user("cancel requested", skb, nlh->nlmsg_pid);
							//break;
						}
					}
				}
				if (found == 0)
					send_to_user("not found", skb, nlh->nlmsg_pid);
				else
					send_to_user("canceled", skb, nlh->nlmsg_pid);
			} else if (req->type == 3) {// cancel all jobs
				found = 0;
				if (!list_empty(&job_head->list)) {
					list_for_each_entry_safe(a_node, tmp_node, &job_head->list, list) {
						if (a_node->cancel == 0) {
							a_node->cancel = 1;
							found += 1;
						}
					}
				}
				if (found == 0)
					send_to_user("empty queue", skb, nlh->nlmsg_pid);
				else
					send_to_user("cancel all requested", skb, nlh->nlmsg_pid);
			} else if (req->type == 4) {// list all job
				found = 0;
				if (!list_empty(&job_head->list)) {
					list_for_each_entry_safe(a_node, tmp_node, &job_head->list, list) {
						if (a_node->cancel == 0) {

							if (a_node->infile != NULL) {
								if (found + strlen("IN:") >= 39999)
									break;
								if (a_node->infile != NULL) {
									memcpy(response + found, "IN:", strlen("IN:"));
									found += strlen("IN:");

									if (found + a_node->infile_len >= 39999)
										break;
									memcpy(response + found, a_node->infile, a_node->infile_len - 1);
									found += a_node->infile_len - 1;
								}
							}

							if (a_node->outfile != NULL) {

								if (found + strlen("\nOUT:") >= 39999)
									break;
								memcpy(response + found, "\nOUT:", strlen("\nOUT:"));
								found += strlen("\nOUT:");

								if (found + a_node->outfile_len >= 39999)
									break;
								memcpy(response + found, a_node->outfile, a_node->outfile_len - 1);
								found += a_node->outfile_len - 1;
							}

							if (found + 50 >= 39999)
								break;
							if (a_node->job_type == 1) {
								memcpy(response + found, "\nINFO:encrypt", strlen("\nTYPE:encrypt"));
								found += strlen("\nTYPE:encrypt");
							}
							if (a_node->job_type == 2) {
								memcpy(response + found, "\nINFO:decrypt", strlen("\nTYPE:decrypt"));
								found += strlen("\nTYPE:decrypt");
							}
							if (a_node->job_type == 3) {
								memcpy(response + found, "\nINFO:compress", strlen("\nTYPE:compress"));
								found += strlen("\nTYPE:compress");
							}
							if (a_node->job_type == 4) {
								memcpy(response + found, "\nINFO:decompress", strlen("\nTYPE:decompress"));
								found += strlen("\nTYPE:decompress");
							}
							if (a_node->job_type == 5) {
								memcpy(response + found, "\nINFO:checksum", strlen("\nTYPE:checksum"));
								found += strlen("\nTYPE:checksum");
							}
							found += sprintf(response + found, ",pid=%d", a_node->pid);
							found += sprintf(response + found, ",job id=%ld", a_node->job_id);
							memcpy(response + found, "\n\n", 2);
							found += 2;
						}
					}
				}
				if (!list_empty(&error_head->list)) {
					memcpy(response + found, "ERROR LIST:\n", strlen("ERROR LIST:\n"));
					found += strlen("ERROR LIST:\n");
					list_for_each_entry_safe(e_node, tmp_e_node, &error_head->list, list) {
						//printk("here----here,e_node->job_id:%ld\n",e_node->job_id);
						if (found + 50 >= 39999)
							break;
						found += sprintf(response + found, "pid=%d", e_node->pid);
						found += sprintf(response + found, ",job id=%ld", e_node->job_id);
						found += sprintf(response + found, ",err=%d", e_node->err_number);
						memcpy(response + found, "\n\n", 2);
						found += 2;
					}
				}
				if (found > 0) {
					memcpy(response + found, "\0", 1);
					found += 1;
					send_to_user(response, skb, nlh->nlmsg_pid);
				} else {
					send_to_user("empty queue", skb, nlh->nlmsg_pid);
				}
			} else {
				//printk("kernel_receive data, but cannot recgonize\n");
				send_to_user("error", skb, nlh->nlmsg_pid);
			}
		} else {
			//printk("kernel_receive data, but cannot recgonize\n");
			send_to_user("error", skb, nlh->nlmsg_pid);
		}
	}
	kfree(response);
	kfree_skb(skb);
}


static int encrypt(struct job_node *job)
{
	int ret = 0;
	mm_segment_t oldfs;


	struct scatterlist sg_in[2];
	struct scatterlist sg_out[2];
	struct crypto_blkcipher *tfm = crypto_alloc_blkcipher("cbc(aes)", 0, CRYPTO_ALG_ASYNC);
	int bytes = PG_SIZE;

	struct file *inf;
	struct file *outf;

	char *buf = (char *)kmalloc(PG_SIZE, GFP_KERNEL);
	char *obuf = (char *)kmalloc(PG_SIZE, GFP_KERNEL);
	// add suffix ".tmp" in file name
	char *tmp_file_name = (char *)kmalloc(job->outfile_len + 4, GFP_KERNEL);

	size_t zero_padding;
	long long write_off = 0;
	long long read_off = 0;

	//store file size
	long original_file_size;
	char pad[16];
	struct blkcipher_desc desc = { .tfm = tfm, .flags = 0 };

	memset(pad, 0 , 16);

#if BITS_PER_LONG != 32
	flags |= O_LARGEFILE;
#endif
	oldfs = get_fs();
	set_fs(KERNEL_DS);

	printk("----encrypt, job_id:%ld\n", job->job_id);
	// do some check
	if (
	    job->infile == NULL ||
	    job->infile_len <= 0 ||
	    job->outfile == NULL ||
	    job->outfile_len <= 0 ||
	    job->keybuf == NULL ||
	    job->keylen != 16
	) {
		job->err_number = -EINVAL;
		printk("encrypt function: invalid parameters\n");
		ret = -EINVAL;
		goto out;
	}
	// must check if cancel == 1 && !kthread_should_stop() in every begin of loops

	if (IS_ERR(memcpy(tmp_file_name, job->outfile, job->outfile_len - 1))) {
		printk("encrypt function: memcpy failed1\n");
		ret = -ENOMEM;
		goto out;
	}
	if (IS_ERR(memcpy(tmp_file_name + job->outfile_len - 1, ".tmp", 5))) {
		printk("encrypt function: memcpy failed2\n");
		ret = -ENOMEM;
		goto out;
	}

	inf = filp_open(job->infile, O_RDWR, 0644);
	outf = filp_open(tmp_file_name, O_RDWR | O_TRUNC | O_CREAT, 0644);
	if (IS_ERR(outf)) {
		printk("failed to open output file !\n");
		ret = -EACCES;
		goto out;
	}
	if (IS_ERR(inf)) {
		printk("failed to open input file %s\n", job->infile);
		mutex_lock(&outf->f_path.dentry->d_parent->d_inode->i_mutex);
		vfs_unlink (outf->f_path.dentry->d_parent->d_inode,outf->f_path.dentry,NULL);
		mutex_unlock(&outf->f_path.dentry->d_parent->d_inode->i_mutex);
		ret = -EACCES;
		goto out;
	}


	ret = crypto_blkcipher_setkey(tfm, job->keybuf, job->keylen);
	if (ret < 0) {
		printk("failed to setkey \n");
		printk("len: %d, key: %s\n", job->keylen, job->keybuf);
		mutex_lock(&outf->f_path.dentry->d_parent->d_inode->i_mutex);
		vfs_unlink (outf->f_path.dentry->d_parent->d_inode,outf->f_path.dentry,NULL);
		mutex_unlock(&outf->f_path.dentry->d_parent->d_inode->i_mutex);
		ret = -EFAULT;
		goto close_n_out;
	}

	original_file_size = (long)inf->f_inode->i_size;
	vfs_write(outf, (const char*)&original_file_size , sizeof(long), &write_off);
	vfs_write(outf, (const char*)job->keybuf , job->keylen, &write_off);
	bytes = vfs_read(inf, buf, bytes, &read_off);
	while (bytes == PG_SIZE) {
		//printk("job->cancel:%d",job->cancel);
		if(kthread_should_stop() || job->cancel != 0){
			mutex_lock(&outf->f_path.dentry->d_parent->d_inode->i_mutex);
			printk("thread_function:deleting %s\n", tmp_file_name);
			vfs_unlink (outf->f_path.dentry->d_parent->d_inode,outf->f_path.dentry,NULL);
			mutex_unlock(&outf->f_path.dentry->d_parent->d_inode->i_mutex);

			filp_close(inf, NULL);
			filp_close(outf, NULL);

			kfree(buf);
			kfree(obuf);
			kfree(tmp_file_name);
			crypto_free_blkcipher(tfm);
			mutex_lock(&outf->f_path.dentry->d_parent->d_inode->i_mutex);
			vfs_unlink (outf->f_path.dentry->d_parent->d_inode,outf->f_path.dentry,NULL);
			mutex_unlock(&outf->f_path.dentry->d_parent->d_inode->i_mutex);
			ret = 0;
			goto exit;
		}
		//encrypt one block
		sg_init_table(sg_in, 1);
		sg_init_table(sg_out, 1);
		sg_set_buf(sg_in, buf, bytes);
		sg_set_buf(sg_out, obuf, bytes);
		ret = crypto_blkcipher_encrypt(&desc, sg_out, sg_in, bytes);
		ret = sg_copy_to_buffer(sg_out, 1, obuf, bytes);
		vfs_write(outf, obuf, bytes, &write_off);
		bytes = vfs_read(inf, buf, bytes, &read_off);
	}
	if (bytes != 0) {
		zero_padding = (bytes % 16) == 0 ? 0 : 16 - (bytes % 16);
		//printk("encrpty:padding size is: %d\n", zero_padding);
		sg_init_table(sg_out, 1);
		if (zero_padding > 0) {
			sg_init_table(sg_in, 2);
		} else {
			sg_init_table(sg_in, 1);
		}
		sg_set_buf(&sg_in[0], buf, bytes);
		if (zero_padding > 0) {
			sg_set_buf(&sg_in[1], pad, zero_padding);
		}
		sg_set_buf(sg_out, obuf, bytes + zero_padding);
		ret = crypto_blkcipher_encrypt(&desc, sg_out, sg_in, bytes + zero_padding);
		ret = sg_copy_to_buffer(sg_out, 1, obuf, bytes + zero_padding);
		vfs_write(outf, obuf, ret , &write_off);
	}
	ret = 0;
	filp_close(inf, NULL);
	filp_close(outf, NULL);

	inf = filp_open(tmp_file_name, O_RDWR, 0644);
	outf = filp_open(job->outfile, O_RDWR | O_TRUNC | O_CREAT, 0644);
	write_off = read_off = 0;
	bytes = vfs_read(inf, buf, bytes, &read_off);

	while (bytes != 0) {
		if(kthread_should_stop() || job->cancel != 0){
			mutex_lock(&inf->f_path.dentry->d_parent->d_inode->i_mutex);
			printk("thread_function:deleting %s\n", tmp_file_name);
			vfs_unlink (inf->f_path.dentry->d_parent->d_inode,inf->f_path.dentry,NULL);
			mutex_unlock(&inf->f_path.dentry->d_parent->d_inode->i_mutex);

			mutex_lock(&outf->f_path.dentry->d_parent->d_inode->i_mutex);
			printk("thread_function:deleting %s\n", job->outfile);
			vfs_unlink (outf->f_path.dentry->d_parent->d_inode,outf->f_path.dentry,NULL);
			mutex_unlock(&outf->f_path.dentry->d_parent->d_inode->i_mutex);

			filp_close(inf, NULL);
			filp_close(outf, NULL);

			kfree(buf);
			kfree(obuf);
			kfree(tmp_file_name);
			crypto_free_blkcipher(tfm);
			ret = 0;
			goto exit;
		}
		vfs_write(outf, buf, bytes, &write_off);
		bytes = vfs_read(inf, buf, bytes, &read_off);
	}
	mutex_lock(&inf->f_path.dentry->d_parent->d_inode->i_mutex);
	vfs_unlink (inf->f_path.dentry->d_parent->d_inode,inf->f_path.dentry,NULL);
	mutex_unlock(&inf->f_path.dentry->d_parent->d_inode->i_mutex);

	if(job->remove_flag != 0){
		filp_close(inf, NULL);
		inf = filp_open(job->infile, O_RDWR, 0644);
		mutex_lock(&inf->f_path.dentry->d_parent->d_inode->i_mutex);
		vfs_unlink (inf->f_path.dentry->d_parent->d_inode,inf->f_path.dentry,NULL);
		mutex_unlock(&inf->f_path.dentry->d_parent->d_inode->i_mutex);
	}

close_n_out:
	filp_close(inf, NULL);
	filp_close(outf, NULL);
out:

	kfree(buf);
	kfree(obuf);
	kfree(tmp_file_name);
	crypto_free_blkcipher(tfm);

exit:
	set_fs(oldfs);
	return ret;
}


static int decrypt(struct job_node *job)
{
	int ret = 0;
	mm_segment_t oldfs;


	struct scatterlist sg_in[1];
	struct scatterlist sg_out[1];
	struct crypto_blkcipher *tfm = crypto_alloc_blkcipher("cbc(aes)", 0, CRYPTO_ALG_ASYNC);
	int bytes = PG_SIZE;

	struct file *inf;
	struct file *outf;

	char *buf = (char *)kmalloc(PG_SIZE, GFP_KERNEL);
	char *obuf = (char *)kmalloc(PG_SIZE, GFP_KERNEL);
	// add suffix ".tmp" in file name
	char *tmp_file_name = (char *)kmalloc(job->outfile_len + 4, GFP_KERNEL);
	unsigned char * tmp_key_buf = (unsigned char *)kmalloc(job->keylen,GFP_KERNEL);

	long long write_off = 0;
	long long read_off = 0;

	//store file size
	long original_file_size;
	struct blkcipher_desc desc = { .tfm = tfm, .flags = 0 };


#if BITS_PER_LONG != 32
	flags |= O_LARGEFILE;
#endif
	oldfs = get_fs();
	set_fs(KERNEL_DS);

	printk("----decrypt, job_id:%ld\n", job->job_id);
	// do some check
	if (
	    job->infile == NULL ||
	    job->infile_len <= 0 ||
	    job->outfile == NULL ||
	    job->outfile_len <= 0 ||
	    job->keybuf == NULL ||
	    job->keylen != 16
	) {
		job->err_number = -EINVAL;
		printk("encrypt function: invalid parameters\n");
		ret = -EINVAL;
		printk("error1\n");
		goto out;
	}
	// must check if cancel == 1 && !kthread_should_stop() in every begin of loops

	if (IS_ERR(memcpy(tmp_file_name, job->outfile, job->outfile_len - 1))) {
		printk("encrypt function: memcpy failed1\n");
		ret = -ENOMEM;
		goto out;
	}
	if (IS_ERR(memcpy(tmp_file_name + job->outfile_len - 1, ".tmp", 5))) {
		printk("encrypt function: memcpy failed2\n");
		ret = -ENOMEM;
		goto out;
	}

	inf = filp_open(job->infile, O_RDWR, 0644);
	outf = filp_open(tmp_file_name, O_RDWR | O_TRUNC | O_CREAT, 0644);
	if (IS_ERR(outf)) {
		printk("failed to open output file !\n");
		ret = -EACCES;
		goto out;
	}
	if (IS_ERR(inf)) {
		printk("failed to open input file %s\n", job->infile);
		mutex_lock(&outf->f_path.dentry->d_parent->d_inode->i_mutex);
		vfs_unlink (outf->f_path.dentry->d_parent->d_inode,outf->f_path.dentry,NULL);
		mutex_unlock(&outf->f_path.dentry->d_parent->d_inode->i_mutex);
		ret = -EACCES;
		goto out;
	}


	ret = crypto_blkcipher_setkey(tfm, job->keybuf, job->keylen);
	if (ret < 0) {
		printk("failed to setkey \n");
		printk("len: %d, key: %s\n", job->keylen, job->keybuf);

		mutex_lock(&outf->f_path.dentry->d_parent->d_inode->i_mutex);
		vfs_unlink (outf->f_path.dentry->d_parent->d_inode,outf->f_path.dentry,NULL);
		mutex_unlock(&outf->f_path.dentry->d_parent->d_inode->i_mutex);


		ret = -EFAULT;
		goto close_n_out;
	}

	vfs_read(inf , (void *)&original_file_size, sizeof(long), &read_off);
	printk("size: %ld\n",original_file_size);
	printk("size in inode: %ld\n",(long)inf->f_inode->i_size);

	vfs_read(inf , (void *)&tmp_key_buf, job->keylen, &read_off);

	if(memcmp(job->keybuf, &tmp_key_buf, job->keylen) != 0){
		mutex_lock(&outf->f_path.dentry->d_parent->d_inode->i_mutex);
		vfs_unlink (outf->f_path.dentry->d_parent->d_inode,outf->f_path.dentry,NULL);
		mutex_unlock(&outf->f_path.dentry->d_parent->d_inode->i_mutex);
		ret = -EINVAL;
		printk("invalid input file\n");
		goto close_n_out;
	}

	if((long)inf->f_inode->i_size < original_file_size || (long)inf->f_inode->i_size > original_file_size + 4096){
		mutex_lock(&outf->f_path.dentry->d_parent->d_inode->i_mutex);
		vfs_unlink (outf->f_path.dentry->d_parent->d_inode,outf->f_path.dentry,NULL);
		mutex_unlock(&outf->f_path.dentry->d_parent->d_inode->i_mutex);
		ret = -EINVAL;
		printk("invalid input file\n");
		goto close_n_out;
	}
	if( original_file_size <0){
		mutex_lock(&outf->f_path.dentry->d_parent->d_inode->i_mutex);
		vfs_unlink (outf->f_path.dentry->d_parent->d_inode,outf->f_path.dentry,NULL);
		mutex_unlock(&outf->f_path.dentry->d_parent->d_inode->i_mutex);
		ret = -EINVAL;
		goto close_n_out;
	}
	bytes = vfs_read(inf, buf, bytes, &read_off);
	printk("bytes: %d\n",bytes);
	printk("here0\n");
	while (bytes == PG_SIZE) {
		printk("bytes1: %d\n",bytes);
		printk("here1\n");
		if(kthread_should_stop() || job->cancel != 0){
			mutex_lock(&outf->f_path.dentry->d_parent->d_inode->i_mutex);
			printk("thread_function:deleting %s\n", tmp_file_name);
			vfs_unlink (outf->f_path.dentry->d_parent->d_inode,outf->f_path.dentry,NULL);
			mutex_unlock(&outf->f_path.dentry->d_parent->d_inode->i_mutex);

			filp_close(inf, NULL);
			filp_close(outf, NULL);

			kfree(buf);
			kfree(obuf);
			kfree(tmp_file_name);
			crypto_free_blkcipher(tfm);
			ret = 0;
			goto exit;
		}
		//decrypt one block
		sg_init_table(sg_in, 1);
		sg_init_table(sg_out, 1);
		sg_set_buf(sg_in, buf, bytes);
		sg_set_buf(sg_out, obuf, bytes);
		ret = crypto_blkcipher_decrypt(&desc, sg_out, sg_in, bytes);
		ret = sg_copy_to_buffer(sg_out, 1, obuf, bytes);
		//printk("temp out string %s",obuf);
		if(original_file_size - bytes >= 0){
			vfs_write(outf, obuf, bytes, &write_off);
			original_file_size -= bytes;
		}else{
			vfs_write(outf, obuf, original_file_size, &write_off);
			original_file_size = 0;
		}
		bytes = vfs_read(inf, buf, bytes, &read_off);
	}
	printk("bytes2: %d\n",bytes);
	if (bytes != 0) {
		printk("bytes3: %d\n",bytes);
		printk("here1\n");
		sg_init_table(sg_out, 1);
		sg_init_table(sg_in, 1);
		sg_set_buf(&sg_in[0], buf, bytes);
		sg_set_buf(sg_out, obuf, bytes);
		ret = crypto_blkcipher_decrypt(&desc, sg_out, sg_in, bytes);
		ret = sg_copy_to_buffer(sg_out, 1, obuf, bytes);
		//printk("temp out string %s",obuf);
		if(original_file_size - bytes >= 0){
			vfs_write(outf, obuf, bytes, &write_off);
			original_file_size -= bytes;
		}else{
			vfs_write(outf, obuf, original_file_size, &write_off);
			original_file_size = 0;
		}
	}else{
		printk("bytes: %d",bytes);
	}
	printk("bytes4: %d\n",bytes);
	ret = 0;
	filp_close(inf, NULL);
	filp_close(outf, NULL);

	inf = filp_open(tmp_file_name, O_RDWR, 0644);
	outf = filp_open(job->outfile, O_RDWR | O_TRUNC | O_CREAT, 0644);
	write_off = read_off = 0;
	bytes = vfs_read(inf, buf, bytes, &read_off);

	while (bytes != 0) {
		//printk("copying %d bytes\n",bytes);
		if(kthread_should_stop() || job->cancel != 0){
			mutex_lock(&inf->f_path.dentry->d_parent->d_inode->i_mutex);
			printk("thread_function:deleting %s\n", tmp_file_name);
			vfs_unlink (inf->f_path.dentry->d_parent->d_inode,inf->f_path.dentry,NULL);
			mutex_unlock(&inf->f_path.dentry->d_parent->d_inode->i_mutex);

			mutex_lock(&outf->f_path.dentry->d_parent->d_inode->i_mutex);
			printk("thread_function:deleting %s\n", job->outfile);
			vfs_unlink (outf->f_path.dentry->d_parent->d_inode,outf->f_path.dentry,NULL);
			mutex_unlock(&outf->f_path.dentry->d_parent->d_inode->i_mutex);

			filp_close(inf, NULL);
			filp_close(outf, NULL);

			kfree(buf);
			kfree(obuf);
			kfree(tmp_file_name);
			crypto_free_blkcipher(tfm);
			ret = 0;
			goto exit;
		}
		vfs_write(outf, buf, bytes, &write_off);
		bytes = vfs_read(inf, buf, bytes, &read_off);
	}
	mutex_lock(&inf->f_path.dentry->d_parent->d_inode->i_mutex);
	vfs_unlink (inf->f_path.dentry->d_parent->d_inode,inf->f_path.dentry,NULL);
	mutex_unlock(&inf->f_path.dentry->d_parent->d_inode->i_mutex);

	if(job->remove_flag != 0){
		filp_close(inf, NULL);
		inf = filp_open(job->infile, O_RDWR, 0644);
		mutex_lock(&inf->f_path.dentry->d_parent->d_inode->i_mutex);
		vfs_unlink (inf->f_path.dentry->d_parent->d_inode,inf->f_path.dentry,NULL);
		mutex_unlock(&inf->f_path.dentry->d_parent->d_inode->i_mutex);
	}

close_n_out:
	filp_close(inf, NULL);
	filp_close(outf, NULL);
out:

	kfree(buf);
	kfree(obuf);
	kfree(tmp_file_name);
	crypto_free_blkcipher(tfm);

exit:
	set_fs(oldfs);
	return ret;
}



static int compress(struct job_node *job)
{
	//check if cancel != 0 in every beginning of loops, end loop and list_del the job if it was been canceled.
	printk("----compress, job_id:%ld\n", job->job_id);
	return 0;
}

static int decompress(struct job_node *job)
{
	//check if cancel != 0 in every beginning of loops, end loop and list_del the job if it was been canceled.
	printk("----decompress, job_id:%ld\n", job->job_id);
	return 0;
}

static int checksum(struct job_node *job)
{
	//check if cancel != 0 in every beginning of loops, end loop and list_del the job if it was been canceled.
	printk("----checksum, job_id:%ld\n", job->job_id);
	return 0;
}

static int thread_function(void *data)
{
	int ret = 0;
	struct job_node *gotten_job, *tmp_node;
	struct error_node *e_node;
	printk("thread_function:in\n");

	// ------------- while -----------------------
	// while (!list_empty(&job_head->list)) {

	// 	printk("thread_function:job queue is not empty, working now....\n");
	// 	// need to lock job queue?
	// 	gotten_job = list_entry((job_head->list).next, struct job_node, list);
	// 	// simple job, add job by 1 and store the result
	// 	if (gotten_job->cancel == 0 ) {
	// 		if (gotten_job->job_type == 1)
	// 			ret = encrypt(gotten_job);
	// 		else if (gotten_job->job_type == 2)
	// 			ret = decrypt(gotten_job);
	// 		else if (gotten_job->job_type == 3)
	// 			ret = compress(gotten_job);
	// 		else if (gotten_job->job_type == 4)
	// 			ret = decompress(gotten_job);
	// 		else if (gotten_job->job_type == 5)
	// 			ret = checksum(gotten_job);

	// 		if (ret == 0) {
	// 			mutex_lock(job_queue_lock);
	// 			//list_del(&gotten_job->list);
	// 			mutex_unlock(job_queue_lock);
	// 			kfree(gotten_job);
	// 		} else {
	// 			gotten_job->err_number = ret;
	// 			mutex_lock(job_queue_lock);
	// 			//list_del(&gotten_job->list);
	// 			mutex_unlock(job_queue_lock);
	// 			list_add_tail(&gotten_job->list, &error_head->list);
	// 		}
	// 		printk("thread_function:job %ld in queue is fnished\n", gotten_job->job_id);
	// 	} else {
	// 		printk("thread_function:job %ld in queue is canceled\n", gotten_job->job_id);
	// 		mutex_lock(job_queue_lock);
	// 		//list_del(&gotten_job->list);
	// 		mutex_unlock(job_queue_lock);
	// 		kfree(gotten_job);
	// 	}
	// }
	// ------------- while -----------------------


	if (!list_empty(&job_head->list)) {
		list_for_each_entry_safe(gotten_job, tmp_node, &job_head->list, list) {
			if (kthread_should_stop()) {
				return 0;
			}
			printk("thread_function:in job queue, job type:%d\n", gotten_job->job_type);

			if (gotten_job->cancel == 0 ) {
				if (gotten_job->job_type == 1)
					ret = encrypt(gotten_job);
				else if (gotten_job->job_type == 2)
					ret = decrypt(gotten_job);
				else if (gotten_job->job_type == 3)
					ret = compress(gotten_job);
				else if (gotten_job->job_type == 4)
					ret = decompress(gotten_job);
				else if (gotten_job->job_type == 5)
					ret = checksum(gotten_job);
			}



			if (ret != 0) {
				printk("thread_function:error number:%d\n", ret);

				e_node = (struct error_node*)kmalloc(sizeof(struct error_node), GFP_KERNEL);
				e_node->pid = gotten_job->pid;
				e_node->job_id = gotten_job->job_id;
				e_node->err_number = ret;
				printk("error in kthread,pid:%d,jobid:%ld\n",e_node->pid,e_node->job_id);

				mutex_lock(job_queue_lock);
				list_del(&gotten_job->list);
				mutex_unlock(job_queue_lock);

				mutex_lock(error_queue_lock);
				list_add_tail(&e_node->list, &error_head->list);
				mutex_unlock(error_queue_lock);
			} else {

				mutex_lock(job_queue_lock);
				list_del(&gotten_job->list);
				mutex_unlock(job_queue_lock);
				kfree(gotten_job);

			}
		}
	}

	threadNum = 0;
	return ret;
}

asmlinkage long submitjob(void *args)
{
	long ret = 0;
	int i;
	struct myargs *argList = kmalloc(sizeof(struct myargs), GFP_KERNEL);
	struct job_node *new_job_node = (struct job_node *)kmalloc(sizeof(struct job_node), GFP_KERNEL);
	struct timespec now = current_kernel_time();


	if (!access_ok(VERIFY_READ, (void *)args, sizeof(struct myargs))) {
		ret = -EACCES;
		goto out;
	}
	ret = copy_from_user(argList, args, sizeof(struct myargs));
	if (ret) {
		ret = -ENOMEM;
		goto out;
	}

	// --------- copy values
	new_job_node->job_type = argList->job_type;
	new_job_node->cancel = 0;
	new_job_node->job_id = now.tv_nsec;
	new_job_node->pid = argList->pid;
	new_job_node->remove_flag = argList->remove_flag;
	// --------- copy values
	//
	// file path should be absolute path

	// ------ infile ------
	new_job_node->infile_len = argList->infile_len;
	if (new_job_node->infile_len <= 1) {
		ret = -ENOENT;
		goto out;
	}
	new_job_node->infile = (char *)kmalloc(argList->infile_len, GFP_KERNEL);
	ret = copy_from_user(new_job_node->infile, argList->infile, argList->infile_len);
	if (ret) {
		ret = -ENOMEM;
		goto out;
	}
	// ------ infile ------

	// ------ outfile ------
	new_job_node->outfile_len = argList->outfile_len;

	if (argList->outfile_len > 1) {
		new_job_node->outfile = (char *)kmalloc(argList->outfile_len, GFP_KERNEL);
		ret = copy_from_user(new_job_node->outfile, argList->outfile, argList->outfile_len);
		if (ret) {
			ret = -ENOMEM;
			goto out;
		}
	} else {
		if (argList->job_type == 1 || argList->job_type == 2 || argList->job_type == 3 || argList->job_type == 4) {
			// outfile not specified
			ret = -ENOENT;
			goto out;
		} else {
			new_job_node->outfile = NULL;
		}
	}
	// ------ outfile ------


	// ------ keybuf and keylen ------
	// 1 encrypt
	// 2 decrypt
	// 3 compress
	// 4 decompress
	// 5 checksum

	// keylen must be 16 after md5
	new_job_node->keylen = argList->keylen;
	if (new_job_node->keylen == 16) {
		new_job_node->keybuf = (char *)kmalloc(argList->keylen, GFP_KERNEL);
		ret = copy_from_user(new_job_node->keybuf, argList->keybuf, 16);
		if (ret) {
			ret = -ENOMEM;
			goto out;
		}
	} else {
		goto out;
	}
	// ------ keybuf and keylen ------


	for (i = 0; i < 16; i++) {
		printk("%x", new_job_node->keybuf[i]);
	}
	printk("<---- cipher\n");

	// add a new job to tail
	mutex_lock(job_queue_lock);
	list_add_tail(&new_job_node->list, &job_head->list);
	mutex_unlock(job_queue_lock);

	printk("submitjob:a new job added(job id%ld, pid: %d)\n", new_job_node->job_id, new_job_node->pid);
	if (threadNum == 0) {
		threadNum = 1;
		global_task = kthread_run(thread_function, NULL, "mythread%d", 1);
	}

	ret = new_job_node->job_id;


out:
	return ret;
}

static int __init init_sys_submitjob(void)
{
	int ret = 0;
	struct netlink_kernel_cfg cfg = {
		.groups = 0,
		.input	= &kernel_receive,
	};

	if (sysptr == NULL)
		sysptr = submitjob;

	// two queue
	job_head = (struct job_node *)kmalloc(sizeof(struct job_node), GFP_KERNEL);
	error_head = (struct error_node *)kmalloc(sizeof(struct error_node), GFP_KERNEL);
	INIT_LIST_HEAD(&job_head->list);
	INIT_LIST_HEAD(&error_head->list);

	// two mutex lock
	job_queue_lock = (struct mutex *)kmalloc(sizeof(struct mutex), GFP_KERNEL);
	error_queue_lock = (struct mutex *)kmalloc(sizeof(struct mutex), GFP_KERNEL);
	mutex_init(job_queue_lock);
	mutex_init(error_queue_lock);

	//try to lock/unlock
	mutex_lock(job_queue_lock);
	mutex_unlock(job_queue_lock);
	mutex_lock(error_queue_lock);
	mutex_unlock(error_queue_lock);

	threadNum = 0;

	// initialize netlink
	// define out socket protocal id = 22
	netlinkfd = netlink_kernel_create(&init_net, 22, &cfg);
	if (!netlinkfd) {
		printk(KERN_ERR "can not create a netlink socket\n");
		ret = -EIO;
		goto out;
	}
	printk("installed new sys_submitjob module\n");
out:
	return ret;
}
static void __exit exit_sys_submitjob(void)
{
	struct job_node *a_node, *tmp_node;
	struct error_node *e_node, *etmp_node;

	if (threadNum > 0) {
		kthread_stop(global_task);
	}

	kfree(job_queue_lock);
	kfree(error_queue_lock);


	// ----------- free job queue ------------
	if (list_empty(&job_head->list)) {
		printk("exit_sys_submitjob:job queue is empty .\n");
	} else {
		printk("exit_sys_submitjob:job queue is not empty .\n");
		//free all unfinished jobs
		list_for_each_entry_safe(a_node, tmp_node, &job_head->list, list) {
			printk("exit_sys_submitjob:in job queue, job type:%d\n", a_node->job_type);
			list_del(&a_node->list);
			kfree(a_node);
		}
	}
	kfree(job_head);
	// ----------- free job queue ------------


	// ----------- free error queue ------------
	if (list_empty(&error_head->list)) {
		printk("exit_sys_submitjob:error queue is empty .\n");
	} else {
		printk("exit_sys_submitjob:error queue is not empty .\n");
		list_for_each_entry_safe(e_node, etmp_node, &error_head->list, list) {
			list_del(&e_node->list);
			kfree(e_node);
		}
	}

	kfree(error_head);
	// ----------- free error queue ------------



	sock_release(netlinkfd->sk_socket);
	printk("removed sys_submitjob module\n");
	if (sysptr != NULL)
		sysptr = NULL;
}
module_init(init_sys_submitjob);
module_exit(exit_sys_submitjob);
MODULE_LICENSE("GPL");
