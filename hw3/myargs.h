struct myargs {
	char *infile;
    int infile_len;
	char *outfile;
    int outfile_len;
	int job_type;
    int pid;
    int remove_flag;
	unsigned char * keybuf;
	unsigned int keylen;
};

// pass a request to netlink
//type:
//1:check a job
//2:cancel a job
//3:cancel all jobs
//4:list all jobs
struct request{
  int type;
  long job_id;
  int pid;
};
