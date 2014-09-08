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
struct list_head myListHeadTcp;
int idCountTcp=0;
bool foundUserTcp = false;
LIST_HEAD(myListHeadTcp);
void letItResumeTcp(bool destory){
        struct waitingList *ptr;
        if (myListHeadTcp.next == &myListHeadTcp){
                printk("trying to resume a thing with empty waiting list");
        } else {
                printk("called by LKM");
                ptr = list_entry(myListHeadTcp.next, struct waitingList, list);
                ptr->resume = true;
                ptr->destory = destory;
        }
}
EXPORT_SYMBOL(letItResumeTcp);
void gotUserOrNotTcp(bool found){
        foundUserTcp = found;
}
EXPORT_SYMBOL(gotUserOrNotTcp);
int tcp_sendmsg(struct kiocb *iocb, struct sock *sk, struct msghdr *msg, size_t size)
{
        struct iovec *iov;
        struct tcp_sock *tp = tcp_sk(sk);
        struct sk_buff *skb;
        int iovlen, flags;
        int mss_now, size_goal;
        int sg, err, copied;
        long timeo;
//my part
        struct waitingList node;
        struct waitingList *ptr;
        int myId;
        
        printk("got a udp_sendmsg\n");
        if (foundUserTcp == false){
                printk("no user found, direct pass\n");
        } else {
                node.resume = false;
                node.destory = false;
                node.id = idCountTcp;
                myId = idCountTcp;
                list_add_tail(&node.list, &myListHeadTcp);
                idCountTcp = idCountTcp + 1;
              ptr = list_entry(myListHeadTcp.next, struct waitingList, list);
                while((foundUserTcp == true)&&
                        (myListHeadTcp.next != &myListHeadTcp && ((ptr->id == myId && ptr->resume == false) || ptr->id !=myId))){
                        msleep(1000);
                        printk("sleeping 1000\n");
                        ptr = list_entry(myListHeadTcp.next, struct waitingList, list);
                        printk("myId:%d, HeadId:%d\n",myId,ptr->id);
                }
                printk("get passed\n");
                if (myListHeadTcp.next == &myListHeadTcp){
                        printk("error empty list\n");
                } else {
                        if (ptr->destory == true){
                                list_del(myListHeadTcp.next);
                                printk("destoryed\n");
                                return -1;
                        }else {
                                list_del(myListHeadTcp.next);
                                printk("resumed\n");
                        }
                }
        }
//my part finished
        lock_sock(sk);
      flags = msg->msg_flags;
        timeo = sock_sndtimeo(sk, flags & MSG_DONTWAIT);
      if ((1 << sk->sk_state) & ~(TCPF_ESTABLISHED | TCPF_CLOSE_WAIT))
                if ((err = sk_stream_wait_connect(sk, &timeo)) != 0)
                        goto out_err;
      clear_bit(SOCK_ASYNC_NOSPACE, &sk->sk_socket->flags);
      mss_now = tcp_send_mss(sk, &size_goal, flags);
      iovlen = msg->msg_iovlen;
        iov = msg->msg_iov;
        copied = 0;
      err = -EPIPE;
        if (sk->sk_err || (sk->sk_shutdown & SEND_SHUTDOWN))
                goto out_err;
      sg = sk->sk_route_caps & NETIF_F_SG;
      while (--iovlen >= 0) {
                size_t seglen = iov->iov_len;
                unsigned char __user *from = iov->iov_base;
            iov++;
            while (seglen > 0) {
                        int copy = 0;
                        int max = size_goal;
                  skb = tcp_write_queue_tail(sk);
                        if (tcp_send_head(sk)) {
                                if (skb->ip_summed == CHECKSUM_NONE)
                                        max = mss_now;
                                copy = max - skb->len;
                        }
                  if (copy <= 0) {
new_segment:
                                if (!sk_stream_memory_free(sk))
                                        goto wait_for_sndbuf;
                        skb = sk_stream_alloc_skb(sk,
                                                          select_size(sk, sg),
                                                          sk->sk_allocation);
                                if (!skb)
                                        goto wait_for_memory;
                        if (sk->sk_route_caps & NETIF_F_ALL_CSUM)
                                        skb->ip_summed = CHECKSUM_PARTIAL;
                        skb_entail(sk, skb);
                                copy = size_goal;
                                max = size_goal;
                        }
                  if (copy > seglen)
                                copy = seglen;
                  if (skb_availroom(skb) > 0) {
                                copy = min_t(int, copy, skb_availroom(skb));
                                err = skb_add_data_nocache(sk, skb, from, copy);
                                if (err)
                                        goto do_fault;
                        } else {
                                int merge = 0;
                                int i = skb_shinfo(skb)->nr_frags;
                                struct page *page = TCP_PAGE(sk);
                                int off = TCP_OFF(sk);
                        if (skb_can_coalesce(skb, i, page, off) &&
                                    off != PAGE_SIZE) {
                                        merge = 1;
                                } else if (i == MAX_SKB_FRAGS || !sg) {
                                        tcp_mark_push(tp, skb);
                                        goto new_segment;
                                } else if (page) {
                                        if (off == PAGE_SIZE) {
                                                put_page(page);
                                                TCP_PAGE(sk) = page = NULL;
                                                off = 0;
                                        }
                                } else
                                        off = 0;
                        if (copy > PAGE_SIZE - off)
                                        copy = PAGE_SIZE - off;
                        if (!sk_wmem_schedule(sk, copy))
                                        goto wait_for_memory;
                        if (!page) {
                                        if (!(page = sk_stream_alloc_page(sk)))
                                                goto wait_for_memory;
                                }
                        err = skb_copy_to_page_nocache(sk, from, skb,
                                                               page, off, copy);
                                if (err) {
                                        if (!TCP_PAGE(sk)) {
                                                TCP_PAGE(sk) = page;
                                                TCP_OFF(sk) = 0;
                                        }
                                        goto do_error;
                                }
                        if (merge) {
                                        skb_frag_size_add(&skb_shinfo(skb)->frags[i - 1], copy);
                                } else {
                                        skb_fill_page_desc(skb, i, page, off, copy);
                                        if (TCP_PAGE(sk)) {
                                                get_page(page);
                                        } else if (off + copy < PAGE_SIZE) {
                                                get_page(page);
                                                TCP_PAGE(sk) = page;
                                        }
                                }

                                TCP_OFF(sk) = off + copy;
                        }
                  if (!copied)
                                TCP_SKB_CB(skb)->tcp_flags &= ~TCPHDR_PSH;
                  tp->write_seq += copy;
                        TCP_SKB_CB(skb)->end_seq += copy;
                        skb_shinfo(skb)->gso_segs = 0;
                  from += copy;
                        copied += copy;
                        if ((seglen -= copy) == 0 && iovlen == 0)
                                goto out;
                  if (skb->len < max || (flags & MSG_OOB))
                                continue;
                  if (forced_push(tp)) {
                                tcp_mark_push(tp, skb);
                                __tcp_push_pending_frames(sk, mss_now, TCP_NAGLE_PUSH);
                        } else if (skb == tcp_send_head(sk))
                                tcp_push_one(sk, mss_now);
                        continue;
wait_for_sndbuf:
                        set_bit(SOCK_NOSPACE, &sk->sk_socket->flags);
wait_for_memory:
                        if (copied)
                                tcp_push(sk, flags & ~MSG_MORE, mss_now, TCP_NAGLE_PUSH);
                  if ((err = sk_stream_wait_memory(sk, &timeo)) != 0)
                                goto do_error;
                  mss_now = tcp_send_mss(sk, &size_goal, flags);
                }
        }
out:
        if (copied)
                tcp_push(sk, flags, mss_now, tp->nonagle);
        release_sock(sk);
        return copied;
do_fault:
        if (!skb->len) {
                tcp_unlink_write_queue(skb, sk);
                tcp_check_send_head(sk, skb);
                sk_wmem_free_skb(sk, skb);
        }
do_error:
        if (copied)
                goto out;
out_err:
        err = sk_stream_error(sk, flags, err);
        release_sock(sk);
        return err;
}
EXPORT_SYMBOL(tcp_sendmsg);
