/*

 Copyright (c) 2013, 2014    
 
 Authors: Ryan K.L. Ko, Alan Y.S. Tan, Ting Gao
 CROW - Cybersecurity Researchers of Waikato

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

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/kprobes.h>
#include <linux/socket.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <linux/kallsyms.h>
#define NETLINK_USER 31
struct sock *nl_sk_tcp = NULL;
int pid=0;
bool gotPid=false;
extern void letItResumeTcp(bool destory);
extern void gotUserOrNotTcp(bool found);
static void printmsg(struct msghdr *msg){
        int i;
        printk("start printing msg\n");
        for (i=0;i<(msg->msg_iov[0]).iov_len;i=i+1){
                printk("%c\n",((char *)(msg->msg_iov[0]).iov_base)[i]);
        }
        printk("finish printing msg\n");
}
static int my_tcp_sendmsg(struct kiocb *iocb,
                        struct sock *sk,
                        struct msghdr *msg,
                        size_t len)
{
        struct sk_buff *skb_out;
        struct nlmsghdr *nlh;
        int length;
        int res=-1;
        printk("tcp_sendmsg from %s,%d\n", current->comm,(msg->msg_iov[0]).iov_len);        
        length = (int)(msg->msg_iov[0].iov_len);
        skb_out = nlmsg_new(length,0);
        if(!skb_out)
        {
                printk(KERN_ERR "Failed to allocate new skb\n");
                jprobe_return();
        }
        nlh=nlmsg_put(skb_out,0,0,NLMSG_DONE,length,0);

        NETLINK_CB(skb_out).dst_group = 0; /* not in mcast group */
        memcpy(nlmsg_data(nlh),(msg->msg_iov[0]).iov_base,length);
        if (gotPid){
                res=nlmsg_unicast(nl_sk_tcp,skb_out,pid);
                if(res<0){
                        printk(KERN_INFO "Error while sending bak to user\n");
                        gotPid=false;
                        gotUserOrNotTcp(false);
                }else {
                        
                        printk("send to user\n");
                }
        }else {
                printk("no pid got\n");
                gotUserOrNotTcp(false);
        }        
        jprobe_return();
       return 0;
}
static struct jprobe my_jprobe_tcp = {
        .entry = (kprobe_opcode_t *) my_tcp_sendmsg
};
static void nl_recv_msg_tcp(struct sk_buff *skb)
{
        struct nlmsghdr *nlh;
        struct sk_buff *skb_out;
        int msg_size;
        char *msg="Hello from kernel tcp";
        int res;
      printk(KERN_INFO "Entering: %s\n", __FUNCTION__);
       msg_size=strlen(msg);
       nlh=(struct nlmsghdr*)skb->data;
        if (!gotPid) {
                pid = nlh->nlmsg_pid; /*pid of sending process */
                gotPid=true;
                gotUserOrNotTcp(true);
                skb_out = nlmsg_new(msg_size,0);
                printk(KERN_INFO "Netlink received msg payload: %s\n",(char*)nlmsg_data(nlh));
            if(!skb_out)
                {
                        printk(KERN_ERR "Failed to allocate new skb\n");
                        return;
                }
                nlh = nlmsg_put(skb_out,0,0,NLMSG_DONE,msg_size,0);
                NETLINK_CB(skb_out).dst_group = 0;
                strncpy(nlmsg_data(nlh),msg,msg_size);
            res=nlmsg_unicast(nl_sk_tcp,skb_out,pid);
            if (res<0){
                        printk(KERN_INFO "Error while sending back to user\n");
                        gotPid=false;
                        gotUserOrNotTcp(false);
                } else {
                }
        }else {
                printk(KERN_INFO "Netlink received msg payload: %s\n",(char*)nlmsg_data(nlh));
            skb_out = nlmsg_new(msg_size,0);
            if(!skb_out)
                {
                        printk(KERN_ERR "Failed to allocate new skb\n");
                        return;
                } 
                if (((char*)nlmsg_data(nlh))[0] == 'y'){
                                letItResumeTcp(false);
                }else{
                        letItResumeTcp(true);
                }
        }
}
int init_module(void)
{
        int ret;
        printk("Entering: %s\n",__FUNCTION__);
        nl_sk_tcp=netlink_kernel_create(&init_net, NETLINK_USER, 0, nl_recv_msg_tcp, NULL, THIS_MODULE);
        my_jprobe_tcp.kp.addr = 
                (kprobe_opcode_t *) kallsyms_lookup_name("tcp_sendmsg");
        if (!my_jprobe_tcp.kp.addr) {
                 printk("Couldn't find %s to plant jprobe\n", "tcp_sendmsg");
                 return -1;
         }
      if ((ret = register_jprobe(&my_jprobe_tcp)) <0) {
                 printk("register_jprobe failed, returned %d\n", ret);
                 return -1;
         }
        printk("Planted jprobe at %p, handler addr %p\n",
                 my_jprobe_tcp.kp.addr, my_jprobe_tcp.entry);

        return 0;
}
void cleanup_module(void)
{         
        unregister_jprobe(&my_jprobe_tcp);
        netlink_kernel_release(nl_sk_tcp);
        printk("jprobe unregistered\n");
 }
 MODULE_LICENSE("GPL");
