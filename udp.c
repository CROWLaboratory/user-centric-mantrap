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

#include <linux/delay.h>
#include <linux/list.h>
struct waitingList{
        struct list_head list;
        bool resume;
        bool destory;
        int id;
};
struct list_head myListHeadUdp;
int idCountUdp=0;
bool foundUserUdp = false;
LIST_HEAD(myListHeadUdp);
void letItResumeUdp(bool destory){
        struct waitingList *ptr;
        if (myListHeadUdp.next == &myListHeadUdp){
                printk("trying to resume a thing with empty waiting list");
        } else {
                printk("called by LKM");
                ptr = list_entry(myListHeadUdp.next, struct waitingList, list);
                ptr->resume = true;
                ptr->destory = destory;
        }
}
EXPORT_SYMBOL(letItResumeUdp);
void gotUserOrNotUdp(bool found){
        foundUserUdp = found;
}
EXPORT_SYMBOL(gotUserOrNotUdp);
int udp_sendmsg(struct kiocb *iocb, struct sock *sk, struct msghdr *msg,
                size_t len)
{
        struct inet_sock *inet = inet_sk(sk);
        struct udp_sock *up = udp_sk(sk);
        struct flowi4 fl4_stack;
        struct flowi4 *fl4;
        int ulen = len;
        struct ipcm_cookie ipc;
        struct rtable *rt = NULL;
        int free = 0;
        int connected = 0;
        __be32 daddr, faddr, saddr;
        __be16 dport;
        u8  tos;
        int err, is_udplite = IS_UDPLITE(sk);
        int corkreq = up->corkflag || msg->msg_flags&MSG_MORE;
        int (*getfrag)(void *, char *, int, int, int, struct sk_buff *);
        struct sk_buff *skb;
        struct ip_options_data opt_copy;
//my part
        struct waitingList node;
        struct waitingList *ptr;
        int myId;
        printk("got a udp_sendmsg\n");
        if (foundUserUdp == false){
                printk("no user found, direct pass\n");
        } else {
                node.resume = false;
                node.destory = false;
                node.id = idCountUdp;
                myId = idCountUdp;
                list_add_tail(&node.list, &myListHeadUdp);
                idCountUdp = idCountUdp + 1;
              ptr = list_entry(myListHeadUdp.next, struct waitingList, list);
                while((foundUserUdp == true)&&
                        (myListHeadUdp.next != &myListHeadUdp && ((ptr->id == myId && ptr->resume == false) || ptr->id !=myId))){
                        msleep(1000);
                        printk("sleeping 1000\n");
                        ptr = list_entry(myListHeadUdp.next, struct waitingList, list);
                        printk("myId:%d, HeadId:%d\n",myId,ptr->id);
                }
                printk("get passed\n");
                if (myListHeadUdp.next == &myListHeadUdp){
                        printk("error empty list\n");
                } else {
                        if (ptr->destory == true){
                                list_del(myListHeadUdp.next);
                                printk("destoryed\n");
                                return -1;
                        }else {
                                list_del(myListHeadUdp.next);
                                printk("resumed\n");
                        }
                }
        }
//my part ends
        if (len > 0xFFFF)
                return -EMSGSIZE;
        if (msg->msg_flags & MSG_OOB) /* Mirror BSD error message compatibility */
                return -EOPNOTSUPP;
      ipc.opt = NULL;
        ipc.tx_flags = 0;
      getfrag = is_udplite ? udplite_getfrag : ip_generic_getfrag;
      fl4 = &inet->cork.fl.u.ip4;
        if (up->pending) {
                lock_sock(sk);
                if (likely(up->pending)) {
                        if (unlikely(up->pending != AF_INET)) {
                                release_sock(sk);
                                return -EINVAL;
                        }
                        goto do_append_data;
                }
                release_sock(sk);
        }
        ulen += sizeof(struct udphdr);
        if (msg->msg_name) {
                struct sockaddr_in * usin = (struct sockaddr_in *)msg->msg_name;
                if (msg->msg_namelen < sizeof(*usin))
                        return -EINVAL;
                if (usin->sin_family != AF_INET) {
                        if (usin->sin_family != AF_UNSPEC)
                                return -EAFNOSUPPORT;
                }
                daddr = usin->sin_addr.s_addr;
                dport = usin->sin_port;
                if (dport == 0)
                        return -EINVAL;
        } else {
                if (sk->sk_state != TCP_ESTABLISHED)
                        return -EDESTADDRREQ;
                daddr = inet->inet_daddr;
                dport = inet->inet_dport;
                connected = 1;
        }
        ipc.addr = inet->inet_saddr;
      ipc.oif = sk->sk_bound_dev_if;
        err = sock_tx_timestamp(sk, &ipc.tx_flags);
        if (err)
                return err;
        if (msg->msg_controllen) {
                err = ip_cmsg_send(sock_net(sk), msg, &ipc);
                if (err)
                        return err;
                if (ipc.opt)
                        free = 1;
                connected = 0;
        }
        if (!ipc.opt) {
                struct ip_options_rcu *inet_opt;
            rcu_read_lock();
                inet_opt = rcu_dereference(inet->inet_opt);
                if (inet_opt) {
                        memcpy(&opt_copy, inet_opt,
                               sizeof(*inet_opt) + inet_opt->opt.optlen);
                        ipc.opt = &opt_copy.opt;
                }
                rcu_read_unlock();
        }
      saddr = ipc.addr;
        ipc.addr = faddr = daddr;
      if (ipc.opt && ipc.opt->opt.srr) {
                if (!daddr)
                        return -EINVAL;
                faddr = ipc.opt->opt.faddr;
                connected = 0;
        }
        tos = RT_TOS(inet->tos);
        if (sock_flag(sk, SOCK_LOCALROUTE) ||
            (msg->msg_flags & MSG_DONTROUTE) ||
            (ipc.opt && ipc.opt->opt.is_strictroute)) {
                tos |= RTO_ONLINK;
                connected = 0;
        }
      if (ipv4_is_multicast(daddr)) {
                if (!ipc.oif)
                        ipc.oif = inet->mc_index;
                if (!saddr)
                        saddr = inet->mc_addr;
                connected = 0;
        }
      if (connected)
                rt = (struct rtable *)sk_dst_check(sk, 0);
        if (rt == NULL) {
                struct net *net = sock_net(sk);
            fl4 = &fl4_stack;
                flowi4_init_output(fl4, ipc.oif, sk->sk_mark, tos,
                                   RT_SCOPE_UNIVERSE, sk->sk_protocol,
                                   inet_sk_flowi_flags(sk)|FLOWI_FLAG_CAN_SLEEP,
                                   faddr, saddr, dport, inet->inet_sport);
            security_sk_classify_flow(sk, flowi4_to_flowi(fl4));
                rt = ip_route_output_flow(net, fl4, sk);
                if (IS_ERR(rt)) {
                        err = PTR_ERR(rt);
                        rt = NULL;
                        if (err == -ENETUNREACH)
                                IP_INC_STATS(net, IPSTATS_MIB_OUTNOROUTES);
                        goto out;
                }
            err = -EACCES;
                if ((rt->rt_flags & RTCF_BROADCAST) &&
                    !sock_flag(sk, SOCK_BROADCAST))
                        goto out;
                if (connected)
                        sk_dst_set(sk, dst_clone(&rt->dst));
        }
      if (msg->msg_flags&MSG_CONFIRM)
                goto do_confirm;
back_from_confirm:
      saddr = fl4->saddr;
        if (!ipc.addr)
                daddr = ipc.addr = fl4->daddr;
      if (!corkreq) {
                skb = ip_make_skb(sk, fl4, getfrag, msg->msg_iov, ulen,
                                  sizeof(struct udphdr), &ipc, &rt,
                                  msg->msg_flags);
                err = PTR_ERR(skb);
                if (skb && !IS_ERR(skb))
                        err = udp_send_skb(skb, fl4);
                goto out;
        }
      lock_sock(sk);
        if (unlikely(up->pending)) {
                release_sock(sk);
            LIMIT_NETDEBUG(KERN_DEBUG "udp cork app bug 2\n");
                err = -EINVAL;
                goto out;
        }
        fl4 = &inet->cork.fl.u.ip4;
        fl4->daddr = daddr;
        fl4->saddr = saddr;
        fl4->fl4_dport = dport;
        fl4->fl4_sport = inet->inet_sport;
        up->pending = AF_INET;
do_append_data:
        up->len += ulen;
        err = ip_append_data(sk, fl4, getfrag, msg->msg_iov, ulen,
                             sizeof(struct udphdr), &ipc, &rt,
                             corkreq ? msg->msg_flags|MSG_MORE : msg->msg_flags);
        if (err)
                udp_flush_pending_frames(sk);
        else if (!corkreq)
                err = udp_push_pending_frames(sk);
        else if (unlikely(skb_queue_empty(&sk->sk_write_queue)))
                up->pending = 0;
        release_sock(sk);
out:
        ip_rt_put(rt);
        if (free)
                kfree(ipc.opt);
        if (!err)
                return len;
       if (err == -ENOBUFS || test_bit(SOCK_NOSPACE, &sk->sk_socket->flags)) {
                UDP_INC_STATS_USER(sock_net(sk),
                                UDP_MIB_SNDBUFERRORS, is_udplite);
        }
        return err;
do_confirm:
        dst_confirm(&rt->dst);
        if (!(msg->msg_flags&MSG_PROBE) || len)
                goto back_from_confirm;
        err = 0;
        goto out;
}
EXPORT_SYMBOL(udp_sendmsg);
