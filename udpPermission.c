/*
 Copyright (c) 2013, 2014     CROW - Cybersecurity Researchers of Waikato

 All rights reserved.

 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions are met:
 	* Redistributions of source code must retain the above copyright
 		notice, this list of conditions and the following disclaimer.
 	* Redistributions in binary form must reproduce the above copyright
 		notice, this list of conditions and the following disclaimer in the
 		documentation and/or other materials provided with the distribution.
 	* Neither the name of the organization nor the
	  names of its contributors may be used to endorse or promote products
 		derived from this software without specific prior written permission.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 DISCLAIMED. IN NO EVENT SHALL ANTHONY M. BLAKE BE LIABLE FOR ANY
 DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

#include <sys/socket.h>
#include <linux/netlink.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#define NETLINK_USER 31
#define NUM_THREADS 10
#define MAX_PAYLOAD 1024  /* maximum payload size*/
struct threadData{
        int threadID;
        struct nlmsghdr *nlh2;
};
struct msg_data{
        struct msg_data *next;
        struct nlmsghdr *nlh2;
};
struct msg_data *head = NULL;
struct threadData threadDatas[NUM_THREADS];
struct sockaddr_nl src_addr, dest_addr;
struct nlmsghdr *nlh = NULL;
struct iovec iov;
struct msghdr msg;
int sock_fd;
void add_to_end(struct msg_data *newData){
        struct msg_data *temp1;
        if (head==NULL)
                head = newData;
        else{
                temp1 = (struct msg_data *)malloc(sizeof(struct msg_data));
                temp1 = head;
                while(temp1->next!=NULL) {
                        temp1 = temp1->next;
                }
                temp1->next = newData;
        }
}
void *CheckingThread(void *data){
        struct threadData *tdata;
        int threadID,length;
        int i,j,c;
        struct nlmsghdr *nlh3;
        char *filename;
        FILE *f;
        FILE *fp;
        char *filetype;
        char *datatype = " data";
        char check;
        int status;
        char path[1035];
        char *command;
        struct iovec iov2;
        struct msghdr msg2;
        tdata = (struct threadData *)data;
        nlh3 = tdata->nlh2;
        threadID = tdata->threadID;
        filename = "testfile0";
      f = fopen(filename,"wb");
        fclose(f);
        f = fopen(filename, "ab");
        if (f == NULL){
                printf("Error opening file!\n");
        }
        fwrite(NLMSG_DATA(nlh3), nlh3->nlmsg_len-16, 1, f);
        fclose(f);
      command = "file /home/sandbox/Desktop/testfile0 2>&1";
      fp = popen(command, "r");
        if (fp == NULL) {
                printf("Failed to run command\n" );
                exit(1);
        }
      while (fgets(path, sizeof(path)-1, fp) != NULL) {
                printf("%s\n", path);
        }
        pclose(fp);
        strtok_r (path, ":", &filetype);
        nlh3 = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
        memset(nlh3, 0, NLMSG_SPACE(MAX_PAYLOAD));
        nlh3->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
        nlh3->nlmsg_pid = getpid();
        nlh3->nlmsg_flags = 0;
        if(! strncmp(filetype, datatype, 5)){
                printf("unknown file type\n");
        }
                printf("resume the process?y/n?\n");
                scanf("%c",&check);
                while ((c=getchar())!='\n' && c!=EOF);
        strcpy(NLMSG_DATA(nlh3), &check);
      iov2.iov_base = (void *)nlh3;
        iov2.iov_len = nlh3->nlmsg_len;
        msg2.msg_name = (void *)&dest_addr;
        msg2.msg_namelen = sizeof(dest_addr);
        msg2.msg_iov = &iov2;
        msg2.msg_iovlen = 1;
        printf("Sending message to kernel\n");
        sendmsg(sock_fd,&msg2,0);
        printf("after send,thread finished %d\n",threadID);
      pthread_exit((void *) data);
}
void *AssignWork(void *notUsing){
        pthread_t threads[NUM_THREADS];
        pthread_attr_t attr;
        int rc;
        void *status;
        printf("Assign work starts working\n");
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
        while(1){
                if (head ==NULL) {
                        sleep(1);
                } else {
                        threadDatas[0].threadID = 0;
                        threadDatas[0].nlh2 = head->nlh2;
                        rc = pthread_create(&threads[0], &attr, CheckingThread, 
                                                (void *)&threadDatas[0]);
                        if (rc){
                                printf("ERROR; return code from pthread_create() is %d\n", rc);
                        }
                        rc = pthread_join(threads[0], &status);
                        if (rc) {
                                printf("ERROR; return code from pthread_join() is %d\n", rc);
                        }
                        head = head->next;
                }
        }
}
int main(void) {
        int i,j,length,currentThread;
        int rc=0;
        char check;
        struct msg_data *temp;
        pthread_t thread[1];
        sock_fd=socket(PF_NETLINK, SOCK_RAW, NETLINK_USER);
        if(sock_fd<0)
                return -1;
        memset(&src_addr, 0, sizeof(src_addr));
        src_addr.nl_family = AF_NETLINK;
        src_addr.nl_pid = getpid();  
         bind(sock_fd, (struct sockaddr*)&src_addr,sizeof(src_addr));
      memset(&dest_addr, 0, sizeof(dest_addr));
        memset(&dest_addr, 0, sizeof(dest_addr));
        dest_addr.nl_family = AF_NETLINK;
        dest_addr.nl_pid = 0;  
        dest_addr.nl_groups = 0; 
       nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
        memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
        nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
        nlh->nlmsg_pid = getpid();
        nlh->nlmsg_flags = 0;
        strcpy(NLMSG_DATA(nlh), "Hello");
        iov.iov_base = (void *)nlh;
        iov.iov_len = nlh->nlmsg_len;
        msg.msg_name = (void *)&dest_addr;
        msg.msg_namelen = sizeof(dest_addr);
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
      printf("Sending message to kernel\n");
        sendmsg(sock_fd,&msg,0);
        printf("Waiting for message from kernel\n");
        recvmsg(sock_fd, &msg, 0);
        printf(" Received: %s\n", NLMSG_DATA(nlh));
        printf("Everything works fine\n");
        rc = pthread_create(&thread[0], NULL, AssignWork, (void *)rc);
        if (rc){
                printf("ERROR; return code from pthread_create() is %d\n", rc);
        }
        while(1){
                printf("waiting for kernel\n");
                recvmsg(sock_fd, &msg, 0);
                printf("Received one \n");
                temp = (struct msg_data *)malloc(sizeof(struct msg_data));
                temp->next = NULL;
                temp->nlh2 = nlh;
                add_to_end(temp);
                
                
        }
        close(sock_fd);
}
