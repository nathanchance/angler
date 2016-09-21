/* Copyright (C) 2015 Cisco Systems, Inc, 2015.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * Author: Hironori Okano <hokano@cisco.com>
 *
 * Fair Queue PIE discipline
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 *
 */

#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/jiffies.h>
#include <linux/string.h>
#include <linux/in.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/skbuff.h>
#include <linux/jhash.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <net/netlink.h>
#include <net/pkt_sched_compat.h>
#include <net/inet_ecn.h>
#include <net/flow_keys.h>
#include <net/pie.h>

/*	Fair Queue PIE.
 *
 * Principles :
 * Packets are classified (internal classifier or external) on flows.
 * This is a Stochastic model (as we use a hash, several flows
 *			       might be hashed on same slot)
 * Each flow has a PIE managed queue.
 * Flows are linked onto two (Round Robin) lists,
 * so that new flows have priority on old ones.
 *
 * For a given flow, packets are not reordered (PIE uses a FIFO)
 * head drops only.
 * ECN capability is on by default.
 * Low memory footprint (64 bytes per flow)
 */

struct fq_pie_flow {
	struct sk_buff	  *head;
	struct sk_buff	  *tail;
	struct list_head  flowchain;
	int		  deficit;
	u32		  dropped; /* number of drops (or ECN marks) on this flow */
}; /* please try to keep this structure <= 64 bytes */

struct fq_pie_sched_data {
	struct tcf_proto __rcu *filter_list; /* optional external classifier */
	struct fq_pie_flow *flows;	/* Flows table [flows_cnt] */
	u32		*backlogs;	/* backlog table [flows_cnt] */
	u32		flows_cnt;	/* number of flows */
	u32		perturbation;	/* hash perturbation */
	u32		quantum;	/* psched_mtu(qdisc_dev(sch)); */
	struct pie_vars vars;
	struct pie_params params;
	struct pie_stats stats;
	struct timer_list adapt_timer;
	u32		drop_overlimit;
	u32		new_flow_count;

	struct list_head new_flows;	/* list of new flows */
	struct list_head old_flows;	/* list of old flows */
};

static unsigned int fq_pie_hash(const struct fq_pie_sched_data *q,
				  const struct sk_buff *skb)
{
	struct flow_keys keys;
	unsigned int hash;

	skb_flow_dissect(skb, &keys);
	hash = jhash_3words((__force u32)keys.dst,
			    (__force u32)keys.src ^ keys.ip_proto,
			    (__force u32)keys.ports, q->perturbation);

	return reciprocal_scale(hash, q->flows_cnt);
}

static unsigned int fq_pie_classify(struct sk_buff *skb, struct Qdisc *sch,
				      int *qerr)
{
	struct fq_pie_sched_data *q = qdisc_priv(sch);
	struct tcf_proto *filter;
	struct tcf_result res;
	int result;

	if (TC_H_MAJ(skb->priority) == sch->handle &&
	    TC_H_MIN(skb->priority) > 0 &&
	    TC_H_MIN(skb->priority) <= q->flows_cnt)
		return TC_H_MIN(skb->priority);

	filter = rcu_dereference_bh(q->filter_list);
	if (!filter)
		return fq_pie_hash(q, skb) + 1;

	*qerr = NET_XMIT_SUCCESS | __NET_XMIT_BYPASS;
	result = tc_classify(skb, filter, &res);
	if (result >= 0) {
#ifdef CONFIG_NET_CLS_ACT
		switch (result) {
		case TC_ACT_STOLEN:
		case TC_ACT_QUEUED:
			*qerr = NET_XMIT_SUCCESS | __NET_XMIT_STOLEN;
		case TC_ACT_SHOT:
			return 0;
		}
#endif
		if (TC_H_MIN(res.classid) <= q->flows_cnt)
			return TC_H_MIN(res.classid);
	}
	return 0;
}

/* add skb to flow queue (tail add) */
static inline void flow_queue_add(struct fq_pie_flow *flow,
				  struct sk_buff *skb)
{
	if (flow->head == NULL)
		flow->head = skb;
	else
		flow->tail->next = skb;
	flow->tail = skb;
	skb->next = NULL;
}

static int fq_pie_enqueue(struct sk_buff *skb, struct Qdisc *sch)
{
	struct fq_pie_sched_data *q = qdisc_priv(sch);
	unsigned int idx;
	struct fq_pie_flow *flow;
	int uninitialized_var(ret);
	u32 max_queue_length=0;
	u32 tmp_prob = 0;
	int i;
	bool enqueue = false;

	idx = fq_pie_classify(skb, sch, &ret);
	if (idx == 0) {
		if (ret & __NET_XMIT_BYPASS)
			qdisc_qstats_drop(sch);
		kfree_skb(skb);
		return ret;
	}
	idx--;
	flow = &q->flows[idx];

	if (sch->q.qlen >= sch->limit){
		q->stats.overlimit++;
		q->stats.dropped++;
		return qdisc_drop(skb, sch);
	}
	sch->q.qlen++;

	/* PIE: drop early */
	tmp_prob = q->vars.prob;
	for (i = 0; i < q->flows_cnt; i++) {
		if ( q->backlogs[i] >= max_queue_length ) max_queue_length = q->backlogs[i];
	}
	if ( max_queue_length > 0 ) {
		q->vars.prob = q->vars.prob / max_queue_length * q->backlogs[idx];
	}
	if (!drop_early(sch, &q->params, &q->vars, skb->len)) {
		enqueue = true;
	} else if (q->params.ecn && (q->vars.prob <= MAX_PROB / 10) &&
		   INET_ECN_set_ce(skb)) {
		/* If packet is ecn capable, mark it if drop probability
		 * is lower than 10%, else drop it.
		 */
		q->stats.ecn_mark++;
		enqueue = true;
	}
	q->vars.prob = tmp_prob;

	/* we can enqueue the packet */
	if (enqueue) {
		q->stats.packets_in++;
		if (qdisc_qlen(sch) > q->stats.maxq)
			q->stats.maxq = qdisc_qlen(sch);
	}else{
		q->stats.dropped++;
		return qdisc_drop(skb, sch);
	}

	flow_queue_add(flow, skb);
	q->backlogs[idx] += qdisc_pkt_len(skb);
	qdisc_qstats_backlog_inc(sch, skb);

	if (list_empty(&flow->flowchain)) {
		list_add_tail(&flow->flowchain, &q->new_flows);
		q->new_flow_count++;
		flow->deficit = q->quantum;
		flow->dropped = 0;
	}
	return NET_XMIT_SUCCESS;
}

static inline struct sk_buff *dequeue_head(struct fq_pie_flow *flow)
{
	struct sk_buff *skb = flow->head;

	flow->head = skb->next;
	skb->next = NULL;
	return skb;
}

static struct sk_buff *fq_pie_dequeue(struct Qdisc *sch)
{
	struct fq_pie_sched_data *q = qdisc_priv(sch);
	struct sk_buff *skb;
	struct fq_pie_flow *flow;
	struct list_head *head;

begin:
	head = &q->new_flows;
	if (list_empty(head)) {
		head = &q->old_flows;
		if (list_empty(head))
			return NULL;
	}
	flow = list_first_entry(head, struct fq_pie_flow, flowchain);

	if (flow->deficit <= 0) {
		flow->deficit += q->quantum;
		list_move_tail(&flow->flowchain, &q->old_flows);
		goto begin;
	}

	if (flow->head) {
		skb = dequeue_head(flow);
		q->backlogs[flow - q->flows] -= qdisc_pkt_len(skb);
		sch->qstats.backlog -= qdisc_pkt_len(skb);
		sch->q.qlen--;
	}

	if (!skb) {
		/* force a pass through old_flows to prevent starvation */
		if ((head == &q->new_flows) && !list_empty(&q->old_flows))
			list_move_tail(&flow->flowchain, &q->old_flows);
		else
			list_del_init(&flow->flowchain);
		goto begin;
	}
	qdisc_bstats_update(sch, skb);
	flow->deficit -= qdisc_pkt_len(skb);

	pie_process_dequeue(sch, &q->vars, skb);

	return skb;
}

static void fq_pie_timer(unsigned long arg)
{
	struct Qdisc *sch = (struct Qdisc *)arg;
	struct fq_pie_sched_data *q = qdisc_priv(sch);
	
	spinlock_t *root_lock = qdisc_lock(qdisc_root_sleeping(sch));

	spin_lock(root_lock);
	calculate_probability(sch, &q->params, &q->vars);
	if (q->params.tupdate)
		mod_timer(&q->adapt_timer, jiffies + q->params.tupdate);
	spin_unlock(root_lock);
}


static void fq_pie_reset(struct Qdisc *sch)
{
	struct sk_buff *skb;

	while ((skb = fq_pie_dequeue(sch)) != NULL)
		kfree_skb(skb);
}

static const struct nla_policy fq_pie_policy[TCA_FQ_PIE_MAX + 1] = {
	[TCA_FQ_PIE_TARGET]	= { .type = NLA_U32 },
	[TCA_FQ_PIE_LIMIT]	= { .type = NLA_U32 },
	[TCA_FQ_PIE_ECN]	= { .type = NLA_U32 },
	[TCA_FQ_PIE_FLOWS]	= { .type = NLA_U32 },
	[TCA_FQ_PIE_QUANTUM]	= { .type = NLA_U32 },
	[TCA_FQ_PIE_TUPDATE]    = { .type = NLA_U32 },
	[TCA_FQ_PIE_ALPHA]      = { .type = NLA_U32 },
	[TCA_FQ_PIE_BETA]       = { .type = NLA_U32 },
	[TCA_FQ_PIE_BYTEMODE]   = { .type = NLA_U32 },
};

static int fq_pie_change(struct Qdisc *sch, struct nlattr *opt)
{
	struct fq_pie_sched_data *q = qdisc_priv(sch);
	struct nlattr *tb[TCA_FQ_PIE_MAX + 1];
	int err;

	if (!opt)
		return -EINVAL;

	err = nla_parse_nested(tb, TCA_FQ_PIE_MAX, opt, fq_pie_policy);
	if (err < 0)
		return err;
	if (tb[TCA_FQ_PIE_FLOWS]) {
		if (q->flows)
			return -EINVAL;
		q->flows_cnt = nla_get_u32(tb[TCA_FQ_PIE_FLOWS]);
		if (!q->flows_cnt ||
		    q->flows_cnt > 65536)
			return -EINVAL;
	}
	sch_tree_lock(sch);

	if (tb[TCA_FQ_PIE_TARGET]) {
		u64 target = nla_get_u32(tb[TCA_FQ_PIE_TARGET]);

		q->params.target = PSCHED_NS2TICKS((u64)target * NSEC_PER_USEC);
	}

	/* tupdate is in jiffies */
	if (tb[TCA_FQ_PIE_TUPDATE])
		q->params.tupdate = usecs_to_jiffies(nla_get_u32(tb[TCA_FQ_PIE_TUPDATE]));

	if (tb[TCA_FQ_PIE_LIMIT])
		sch->limit = nla_get_u32(tb[TCA_FQ_PIE_LIMIT]);

	if (tb[TCA_FQ_PIE_ECN])
		q->params.ecn = nla_get_u32(tb[TCA_FQ_PIE_ECN]);

	if (tb[TCA_FQ_PIE_QUANTUM])
		q->quantum = max(256U, nla_get_u32(tb[TCA_FQ_PIE_QUANTUM]));

	if (tb[TCA_FQ_PIE_ALPHA])
		q->params.alpha = nla_get_u32(tb[TCA_FQ_PIE_ALPHA]);

	if (tb[TCA_FQ_PIE_BETA])
		q->params.beta = nla_get_u32(tb[TCA_FQ_PIE_BETA]);

	if (tb[TCA_FQ_PIE_BYTEMODE])
		q->params.bytemode = nla_get_u32(tb[TCA_FQ_PIE_BYTEMODE]);

	while (sch->q.qlen > sch->limit) {
		struct sk_buff *skb = fq_pie_dequeue(sch);

		kfree_skb(skb);
		qdisc_tree_decrease_qlen(sch, 1);
	}

	sch_tree_unlock(sch);
	return 0;
}

static void *fq_pie_zalloc(size_t sz)
{
	void *ptr = kzalloc(sz, GFP_KERNEL | __GFP_NOWARN);

	if (!ptr)
		ptr = vzalloc(sz);
	return ptr;
}

static void fq_pie_free(void *addr)
{
	kvfree(addr);
}

static void fq_pie_destroy(struct Qdisc *sch)
{
	struct fq_pie_sched_data *q = qdisc_priv(sch);

	tcf_destroy_chain(&q->filter_list);
	fq_pie_free(q->backlogs);
	fq_pie_free(q->flows);

	q->params.tupdate = 0;
	del_timer_sync(&q->adapt_timer);
}

static int fq_pie_init(struct Qdisc *sch, struct nlattr *opt)
{
	struct fq_pie_sched_data *q = qdisc_priv(sch);
	int i;

	sch->limit = 10*1024;
	q->flows_cnt = 1024;
	q->quantum = psched_mtu(qdisc_dev(sch));
	q->perturbation = prandom_u32();
	INIT_LIST_HEAD(&q->new_flows);
	INIT_LIST_HEAD(&q->old_flows);
	pie_vars_init(&q->vars);
	pie_params_init(&q->params);
	setup_timer(&q->adapt_timer,fq_pie_timer, (unsigned long)sch);
	mod_timer(&q->adapt_timer, jiffies + HZ / 2);
	q->params.ecn = true;

	if (opt) {
		int err = fq_pie_change(sch, opt);
		if (err)
			return err;
	}

	if (!q->flows) {
		q->flows = fq_pie_zalloc(q->flows_cnt *
					   sizeof(struct fq_pie_flow));
		if (!q->flows)
			return -ENOMEM;
		q->backlogs = fq_pie_zalloc(q->flows_cnt * sizeof(u32));
		if (!q->backlogs) {
			fq_pie_free(q->flows);
			return -ENOMEM;
		}
		for (i = 0; i < q->flows_cnt; i++) {
			struct fq_pie_flow *flow = q->flows + i;

			INIT_LIST_HEAD(&flow->flowchain);
		}
	}
	if (sch->limit >= 1)
		sch->flags |= TCQ_F_CAN_BYPASS;
	else
		sch->flags &= ~TCQ_F_CAN_BYPASS;
	return 0;
}

static int fq_pie_dump(struct Qdisc *sch, struct sk_buff *skb)
{
	struct fq_pie_sched_data *q = qdisc_priv(sch);
	struct nlattr *opts;

	opts = nla_nest_start(skb, TCA_OPTIONS);
	if (opts == NULL)
		goto nla_put_failure;

	if (nla_put_u32(skb, TCA_FQ_PIE_TARGET,
			((u32) PSCHED_TICKS2NS(q->params.target)) /
			NSEC_PER_USEC) ||
	    nla_put_u32(skb, TCA_FQ_PIE_LIMIT,
			sch->limit) ||
	    nla_put_u32(skb, TCA_FQ_PIE_TUPDATE,
			jiffies_to_usecs(q->params.tupdate)) ||
	    nla_put_u32(skb, TCA_FQ_PIE_ECN,
			q->params.ecn) ||
	    nla_put_u32(skb, TCA_FQ_PIE_QUANTUM,
			q->quantum) ||
	    nla_put_u32(skb, TCA_FQ_PIE_FLOWS,
			q->flows_cnt) ||
	    nla_put_u32(skb, TCA_FQ_PIE_ALPHA,
			q->params.alpha) ||
	    nla_put_u32(skb, TCA_FQ_PIE_BETA,
			q->params.beta) ||
	    nla_put_u32(skb, TCA_FQ_PIE_BYTEMODE,
			q->params.bytemode))
		goto nla_put_failure;

	return nla_nest_end(skb, opts);

nla_put_failure:
	return -1;
}

static int fq_pie_dump_stats(struct Qdisc *sch, struct gnet_dump *d)
{
	struct fq_pie_sched_data *q = qdisc_priv(sch);
	struct tc_fq_pie_xstats st = {
		.type				= TCA_FQ_PIE_XSTATS_QDISC,
	};
	struct list_head *pos;

	st.qdisc_stats.new_flow_count = q->new_flow_count;
	st.qdisc_stats.packets_in = q->stats.packets_in;
	st.qdisc_stats.drop_overlimit = q->drop_overlimit;
	st.qdisc_stats.maxq = q->stats.maxq;
	st.qdisc_stats.dropped = q->stats.dropped;
	st.qdisc_stats.ecn_mark = q->stats.ecn_mark;

	list_for_each(pos, &q->new_flows)
		st.qdisc_stats.new_flows_len++;

	list_for_each(pos, &q->old_flows)
		st.qdisc_stats.old_flows_len++;

	st.qdisc_stats.prob = q->vars.prob;
	st.qdisc_stats.delay = ((u32) PSCHED_TICKS2NS(q->vars.qdelay)) /
				   NSEC_PER_USEC;
	st.qdisc_stats.avg_dq_rate = q->vars.avg_dq_rate *
				   (PSCHED_TICKS_PER_SEC) >> PIE_SCALE;

	return gnet_stats_copy_app(d, &st, sizeof(st));
}

static struct Qdisc *fq_pie_leaf(struct Qdisc *sch, unsigned long arg)
{
	return NULL;
}

static unsigned long fq_pie_get(struct Qdisc *sch, u32 classid)
{
	return 0;
}

static unsigned long fq_pie_bind(struct Qdisc *sch, unsigned long parent,
			      u32 classid)
{
	/* we cannot bypass queue discipline anymore */
	sch->flags &= ~TCQ_F_CAN_BYPASS;
	return 0;
}

static void fq_pie_put(struct Qdisc *q, unsigned long cl)
{
}

static struct tcf_proto __rcu **fq_pie_find_tcf(struct Qdisc *sch,
						  unsigned long cl)
{
	struct fq_pie_sched_data *q = qdisc_priv(sch);

	if (cl)
		return NULL;
	return &q->filter_list;
}

static int fq_pie_dump_class(struct Qdisc *sch, unsigned long cl,
			  struct sk_buff *skb, struct tcmsg *tcm)
{
	tcm->tcm_handle |= TC_H_MIN(cl);
	return 0;
}

static int fq_pie_dump_class_stats(struct Qdisc *sch, unsigned long cl,
				     struct gnet_dump *d)
{
	struct fq_pie_sched_data *q = qdisc_priv(sch);
	u32 idx = cl - 1;
	struct gnet_stats_queue qs = { 0 };
	struct tc_fq_pie_xstats xstats;

	if (idx < q->flows_cnt) {
		const struct fq_pie_flow *flow = &q->flows[idx];
		const struct sk_buff *skb = flow->head;

		memset(&xstats, 0, sizeof(xstats));
		xstats.type = TCA_FQ_PIE_XSTATS_CLASS;

		xstats.class_stats.deficit = flow->deficit;
		while (skb) {
			qs.qlen++;
			skb = skb->next;
		}
		qs.backlog = q->backlogs[idx];
		qs.drops = flow->dropped;
	}
	if (gnet_stats_copy_queue(d, &qs) < 0)
		return -1;
	if (idx < q->flows_cnt)
		return gnet_stats_copy_app(d, &xstats, sizeof(xstats));
	return 0;
}

static void fq_pie_walk(struct Qdisc *sch, struct qdisc_walker *arg)
{
	struct fq_pie_sched_data *q = qdisc_priv(sch);
	unsigned int i;

	if (arg->stop)
		return;

	for (i = 0; i < q->flows_cnt; i++) {
		if (list_empty(&q->flows[i].flowchain) ||
		    arg->count < arg->skip) {
			arg->count++;
			continue;
		}
		if (arg->fn(sch, i + 1, arg) < 0) {
			arg->stop = 1;
			break;
		}
		arg->count++;
	}
}

static const struct Qdisc_class_ops fq_pie_class_ops = {
	.leaf		=	fq_pie_leaf,
	.get		=	fq_pie_get,
	.put		=	fq_pie_put,
	.tcf_chain	=	fq_pie_find_tcf,
	.bind_tcf	=	fq_pie_bind,
	.unbind_tcf	=	fq_pie_put,
	.dump		=	fq_pie_dump_class,
	.dump_stats	=	fq_pie_dump_class_stats,
	.walk		=	fq_pie_walk,
};

static struct Qdisc_ops fq_pie_qdisc_ops __read_mostly = {
	.cl_ops		=	&fq_pie_class_ops,
	.id		=	"fq_pie",
	.priv_size	=	sizeof(struct fq_pie_sched_data),
	.enqueue	=	fq_pie_enqueue,
	.dequeue	=	fq_pie_dequeue,
	.peek		=	qdisc_peek_dequeued,
	.init		=	fq_pie_init,
	.reset		=	fq_pie_reset,
	.destroy	=	fq_pie_destroy,
	.change		=	fq_pie_change,
	.dump		=	fq_pie_dump,
	.dump_stats =	fq_pie_dump_stats,
	.owner		=	THIS_MODULE,
};

static int __init fq_pie_module_init(void)
{
	return register_qdisc(&fq_pie_qdisc_ops);
}

static void __exit fq_pie_module_exit(void)
{
	unregister_qdisc(&fq_pie_qdisc_ops);
}

module_init(fq_pie_module_init)
module_exit(fq_pie_module_exit)
MODULE_AUTHOR("Hironori Okano");
MODULE_LICENSE("GPL");
