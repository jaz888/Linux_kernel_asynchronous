#include <asm/unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <openssl/md5.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>

#include "myargs.h"

//type:
//1:check a job
//2:cancel a job
//3:cancel all jobs
//4:list all jobs

struct u_packet_info
{
    struct nlmsghdr hdr;
    char msg[40000];
};
int qctl(struct request *req) {
    struct sockaddr_nl local;
    struct sockaddr_nl kpeer;
    int skfd, kpeerlen = sizeof(struct sockaddr_nl);
    struct nlmsghdr *message;
    struct u_packet_info info;
    char *retval;
    int ret;
    message = (struct nlmsghdr *)malloc(1);

    skfd = socket(PF_NETLINK, SOCK_RAW, 22);
    if (skfd < 0) {
        printf("can not create a netlink socket\n");
        return -1;
    }

    memset(&local, 0, sizeof(local));
    local.nl_family = AF_NETLINK;
    local.nl_pid = getpid();
    local.nl_groups = 0;
    if (bind(skfd, (struct sockaddr *)&local, sizeof(local)) != 0) {
        printf("bind() error\n");
        return -1;
    }
    memset(&kpeer, 0, sizeof(kpeer));
    kpeer.nl_family = AF_NETLINK;
    kpeer.nl_pid = 0;
    kpeer.nl_groups = 0;

    memset(message, '\0', sizeof(struct nlmsghdr));
    message->nlmsg_len = NLMSG_SPACE(sizeof(struct request));
    message->nlmsg_flags = 0;
    message->nlmsg_type = 0;
    message->nlmsg_seq = 0;
    message->nlmsg_pid = local.nl_pid;

    retval = memcpy(NLMSG_DATA(message), req, sizeof(struct request));
    //printf("message sendto kernel are:%s, len:%d\n", (char *)NLMSG_DATA(message), message->nlmsg_len);
    ret = sendto(skfd, message, message->nlmsg_len, 0, (struct sockaddr *)&kpeer, sizeof(kpeer));
    if (!ret) {
        printf("send message failed\n");
        return -1;
    }

    ret = recvfrom(skfd, &info, sizeof(struct u_packet_info), 0, (struct sockaddr *)&kpeer, (socklen_t *)&kpeerlen);
    if (!ret) {
        printf("receive message failed\n");
        return -1;
    }

    printf("message receive from kernel:\n%s\n", (char *)info.msg);
    close(skfd);
    if (((char *)info.msg)[0]=='f' && ((char *)info.msg)[1]=='i' && ((char *)info.msg)[2]=='n') {
        return 1;//finished
    } else if (((char *)info.msg)[0]=='e' && ((char *)info.msg)[1]=='r' && ((char *)info.msg)[2]=='r') {
        return 2;//error
    } else {
        return 0;//not finished
    }
}
int main(int argc, char **argv)
{
    struct myargs *dummy = (struct myargs *)malloc(sizeof(struct myargs));
    long job_id = 0L;
    struct request *req = malloc(sizeof(struct request));
    int ret = 0;
    int c = 0;
    char a;
    int hflag = 0;
    int eflag = 0;
    int dflag = 0;
    int oflag = 0;
    int rflag = 0;
    int kflag = 0;
    char * keybuf;
    int job_type = 0;
    long dummyLong = 0L;

    int index = 0;
    char * infile = malloc(4096);
    char * outfile = malloc(4096);

    if (argc <= 1) {
        printf("use -h to see help document\n");
        exit(-1);
    }


    // process en/decrypt, (de)compress or checksum
    while ((c = getopt (argc, argv, "hedork:")) != -1){
        switch (c)
        {
        case 'h':
            hflag = 1;
            printf("-e : encrypt\n\
                -d : decrypt\n\
                -k : specify cipher\n\
                -o : overwite\n\
                -r : remove input file\n\
                sample usage:\n\
                ./encrypt -e -k RandomKEY inputFile encryptedFile\n\
                ./encrypt -e -k RandomKEY inputFile outputFile -r\n\
                ./encrypt -d -k RandomKEY inputFile decryptedFile\n\
                ./encrypt -e -k RandomKEY inputFile -o\n");
            goto out;
            break;
        case 'e':
            eflag = 1;
            job_type = 1;
            break;
        case 'd':
            dflag = 1;
            job_type = 2;
            break;
        case 'o':
            oflag = 1;
            break;
        case 'r':
            rflag = 1;
            break;
        case 'k':
            kflag = 1;
            keybuf = optarg;
            break;
        default:
            printf("wrong parameters, use -h to see help document\n");
            goto out;
        }
    }

    index = optind; 

    // check all input parameters
    if(eflag == 0 && dflag == 0){
        printf("wrong parameter\n");
        goto out;
    }
    if(kflag == 0){
        printf("wrong parameter\n");
        goto out;
    }
    if(oflag == 0 && index > argc - 2){
        printf("missing input or output file, %d, %d\n",index, argc);
        goto out;
    }
    //printf("%d, %d, %d, %s, %d\n",oflag,index,argc, argv[argc - 1], access(argv[argc - 1], F_OK));
    if(oflag == 0 && index <= argc - 2 && access(argv[argc - 1], F_OK) != -1){
        printf("do you want to overwite output file? [y/n]:");
        scanf("%c", &a);
        if (a != 'y')
        {
            goto out;
        }
        
    }
    if(oflag == 1 && index > argc - 1){
        printf("missing input or output file, %d, %d\n",index, argc);
        goto out;
    }

    if(oflag == 1){
        if(access( argv[index], F_OK ) != -1) {
            realpath(argv[index], infile);
            realpath(argv[index], outfile);
        }else{
            printf("access denied\n");
            goto out;
        }
        
    }else{
        realpath(argv[index], infile);
        index ++;
        realpath(argv[index], outfile);
    }

    printf("input:%s,output:%s\n", infile,outfile);

    //type:
    //1:check a job
    //2:cancel a job
    //3:cancel all jobs
    //4:list all jobs

    dummy->pid = getpid();
    dummy->infile = infile;
    dummy->infile_len = strlen(infile)+1;
    dummy->outfile = outfile;
    dummy->outfile_len = strlen(outfile)+1;
    dummy->remove_flag = rflag;
    dummy->job_type = job_type;

    MD5_CTX ctx;
    unsigned char md5key[16];
    MD5_Init(&ctx);
    MD5_Update(&ctx, keybuf, strlen(keybuf));
    MD5_Final(md5key, &ctx);

    dummy->keybuf = md5key;
    dummy->keylen = 16;

    job_id = syscall(359, (void *)dummy);

    //printf("list queue:\n");
    req->type = 4;
    req->pid = 0;
    req->job_id = 0;
    ret = qctl(req);

    do{
        req->type = 1;
        req->pid = dummy->pid;
        req->job_id = job_id;
        ret = qctl(req);
        printf("\nincrease counter:%ld\n\n",dummyLong);
        dummyLong += 1;
        sleep(1);
    }while(ret == 0);

out:
    free(dummy);
    return 0;
}
