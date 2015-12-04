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
    int ret;
    char c;
    struct request *req = malloc(sizeof(struct request));
    int pid = 0;
    long job_id = 0L;
    //4 list all
    //2 remove one
    //3 cancel all
    //1 query one
    int type = 0;
    int index;
    
    if(argc <= 1){
        printf("use -h to see help infomation\n");
        goto out;
    }

    // process en/decrypt, (de)compress or checksum
    while ((c = getopt (argc, argv, "hlrcq")) != -1){
        switch (c)
        {
        case 'h':
            printf("-q : check status of a job, following pid and job id\n\
                -l : list all jobs, includes errors\n\
                -r : remove a job, following pid and job id\n\
                -c : cancel all jobs, empty error list\n");
            goto out;
            break;
        case 'l':
            type = 4;
            break;
        case 'r':
            type = 2;
            break;
        case 'c':
            type = 3;
            break;
        case 'q':
            type = 1;
            break;
        default:
            printf("wrong parameters, use -h to see help document\n");
            goto out;
        }
    }

    index = optind; 

    //4 list all
    //2 remove one
    //3 cancel all
    //1 query one
    if((type == 1 || type == 2) && index > argc - 2){
        printf("wrong parameter, please specify pid and job id to check/remove a job\n");
        goto out;
    }
    if(type == 1 || type == 2){
        pid = atoi(argv[index]);
        index ++;
        job_id = atol(argv[index]);
        index ++;
    }

    req->type = type;
    req->pid = pid;
    req->job_id = job_id;
    ret = qctl(req);

out:
    return 0;


}
