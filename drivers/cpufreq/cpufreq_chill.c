/*
 *  drivers/cpufreq/cpufreq_chill.c
 *
 *  Copyright (C)  2001 Russell King
 *            (C)  2003 Venkatesh Pallipadi <venkatesh.pallipadi@intel.com>.
 *                      Jun Nakajima <jun.nakajima@intel.com>
 *            (C)  2009 Alexander Clouter <alex@digriz.org.uk>
 *            (C)  2016 Joe Maples <joe@frap129.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/slab.h>
#include "cpufreq_chill.h"
#ifdef CONFIG_POWERSUSPEND
#include <linux/powersuspend.h>
#endif

/* Chill version macros */
#define CHILL_VERSION_MAJOR			(1)
#define CHILL_VERSION_MINOR			(3)

/* Chill governor macros */
#define DEF_FREQUENCY_UP_THRESHOLD		(80)
#define DEF_FREQUENCY_DOWN_THRESHOLD		(20)
#define DEF_FREQUENCY_DOWN_THRESHOLD_SUSPENDED	(20)
#define DEF_FREQUENCY_STEP			(5)
#define DEF_SLEEP_DEPTH				(1)
#define DEF_SAMPLING_RATE			(20000)
#define DEF_BOOST_ENABLED			(1)
#define DEF_BOOST_COUNT				(3)

static DEFINE_PER_CPU(struct cs_cpu_dbs_info_s, cs_cpu_dbs_info);

static unsigned int boost_counter = 0;

static inline unsigned int get_freq_target(struct chill_dbs_tuners *chill_tuners,
					   struct cpufreq_policy *policy)
{
	unsigned int freq_target = (chill_tuners->freq_step * policy->max) / 100;

	/* max freq cannot be less than 100. But who knows... */
	if (unlikely(freq_target == 0))
		freq_target = DEF_FREQUENCY_STEP;

	return freq_target;
}

/*
 * Every sampling_rate, we check, if current idle time is less than 20%
 * (default), then we try to increase frequency. Every sampling_rate,
 *  we check, if current idle time is more than 80%
 * (default), then we try to decrease frequency
 *
 * Any frequency increase takes it to the maximum frequency. Frequency reduction
 * happens at minimum steps of 5% (default) of maximum frequency
 */
static void chill_check_cpu(int cpu, unsigned int load)
{
	struct cs_cpu_dbs_info_s *dbs_info = &per_cpu(cs_cpu_dbs_info, cpu);
	struct cpufreq_policy *policy = dbs_info->cdbs.cur_policy;
	struct dbs_data *dbs_data = policy->governor_data;
	struct chill_dbs_tuners *chill_tuners = dbs_data->tuners;

	/*
	 * break out if we 'cannot' reduce the speed as the user might
	 * want freq_step to be zero
	 */
	if (chill_tuners->freq_step == 0)
		return;

	/* Check for frequency increase */
	if (load > chill_tuners->up_threshold) {

		/* if we are already at full speed then break out early */
		if (dbs_info->requested_freq == policy->max)
			return;

#ifdef CONFIG_POWERSUSPEND
		/* if power is suspended then break out early */
		if (power_suspended)
			return;
#endif

		/* Boost if count is reached, otherwise increase freq */
		if (chill_tuners->boost_enabled && boost_counter >= chill_tuners->boost_count)
			dbs_info->requested_freq = policy->max;
		else
			dbs_info->requested_freq += get_freq_target(chill_tuners, policy);

 		/* Make sure max hasn't been reached, otherwise increment boost_counter */
		if (dbs_info->requested_freq >= policy->max)
			dbs_info->requested_freq = policy->max;
		else
			boost_counter++;

		__cpufreq_driver_target(policy, dbs_info->requested_freq,
			CPUFREQ_RELATION_H);
		return;
	}

	/* Check for frequency decrease */
	if (load < chill_tuners->down_threshold) {
		unsigned int freq_target;
		/*
		 * if we cannot reduce the frequency anymore, break out early
		 */
		if (policy->cur == policy->min)
			return;

		freq_target = get_freq_target(chill_tuners, policy);
		if (dbs_info->requested_freq > freq_target)
			dbs_info->requested_freq -= freq_target;
		else
			dbs_info->requested_freq = policy->min;

		__cpufreq_driver_target(policy, dbs_info->requested_freq,
				CPUFREQ_RELATION_L);
		return;
	}
}

static void chill_dbs_timer(struct work_struct *work)
{
	struct cs_cpu_dbs_info_s *dbs_info = container_of(work,
			struct cs_cpu_dbs_info_s, cdbs.work.work);
	unsigned int cpu = dbs_info->cdbs.cur_policy->cpu;
	struct cs_cpu_dbs_info_s *core_dbs_info = &per_cpu(cs_cpu_dbs_info,
			cpu);
	struct dbs_data *dbs_data = dbs_info->cdbs.cur_policy->governor_data;
	struct chill_dbs_tuners *chill_tuners = dbs_data->tuners;
	int delay = delay_for_sampling_rate(chill_tuners->sampling_rate);
	bool modify_all = true;
	unsigned int sampling_rate_suspended = chill_tuners->sampling_rate * chill_tuners->sleep_depth;

	mutex_lock(&core_dbs_info->cdbs.timer_mutex);

	if (!need_load_eval(&core_dbs_info->cdbs, chill_tuners->sampling_rate))
		modify_all = false;
#ifdef CONFIG_POWERSUSPEND
	else if (power_suspended && need_load_eval(&core_dbs_info->cdbs, sampling_rate_suspended))
#else
	else
#endif
			dbs_check_cpu(dbs_data, cpu);

	gov_queue_work(dbs_data, dbs_info->cdbs.cur_policy, delay, modify_all);
	mutex_unlock(&core_dbs_info->cdbs.timer_mutex);
}

static int dbs_cpufreq_notifier(struct notifier_block *nb, unsigned long val,
		void *data)
{
	struct cpufreq_freqs *freq = data;
	struct cs_cpu_dbs_info_s *dbs_info =
					&per_cpu(cs_cpu_dbs_info, freq->cpu);
	struct cpufreq_policy *policy;

	if (!dbs_info->enable)
		return 0;

	policy = dbs_info->cdbs.cur_policy;

	/*
	 * we only care if our internally tracked freq moves outside the 'valid'
	 * ranges of frequency available to us otherwise we do not change it
	*/
	if (dbs_info->requested_freq > policy->max
			|| dbs_info->requested_freq < policy->min)
		dbs_info->requested_freq = freq->new;

	return 0;
}

/************************** sysfs interface ************************/
static struct common_dbs_data chill_dbs_cdata;

static ssize_t store_sampling_rate(struct dbs_data *dbs_data, const char *buf,
		size_t count)
{
	struct chill_dbs_tuners *chill_tuners = dbs_data->tuners;
	unsigned int input;
	int ret;
	ret = sscanf(buf, "%u", &input);

	if (ret != 1)
		return -EINVAL;

	chill_tuners->sampling_rate = max(input, dbs_data->min_sampling_rate);
	return count;
}

static ssize_t store_up_threshold(struct dbs_data *dbs_data, const char *buf,
		size_t count)
{
	struct chill_dbs_tuners *chill_tuners = dbs_data->tuners;
	unsigned int input;
	int ret;
	ret = sscanf(buf, "%u", &input);

	if (ret != 1 || input > 100 || input <= chill_tuners->down_threshold)
		return -EINVAL;

	chill_tuners->up_threshold = input;
	return count;
}

static ssize_t store_down_threshold(struct dbs_data *dbs_data, const char *buf,
		size_t count)
{
	struct chill_dbs_tuners *chill_tuners = dbs_data->tuners;
	unsigned int input;
	int ret;
	ret = sscanf(buf, "%u", &input);

	/* cannot be lower than 11 otherwise freq will not fall */
	if (ret != 1 || input < 11 || input > 100 ||
			input >= chill_tuners->up_threshold)
		return -EINVAL;

	chill_tuners->down_threshold = input;
	return count;
}

static ssize_t store_down_threshold_suspended(struct dbs_data *dbs_data, const char *buf,
		size_t count)
{
	struct chill_dbs_tuners *chill_tuners = dbs_data->tuners;
	unsigned int input;
	int ret;
	ret = sscanf(buf, "%u", &input);

	/* cannot be lower than 11 otherwise freq will not fall */
	if (ret != 1 || input < 11 || input > 100 ||
			input >= chill_tuners->up_threshold)
		return -EINVAL;

	chill_tuners->down_threshold = input;
	return count;
}

static ssize_t store_ignore_nice_load(struct dbs_data *dbs_data,
		const char *buf, size_t count)
{
	struct chill_dbs_tuners *chill_tuners = dbs_data->tuners;
	unsigned int input, j;
	int ret;

	ret = sscanf(buf, "%u", &input);
	if (ret != 1)
		return -EINVAL;

	if (input > 1)
		input = 1;

	if (input == chill_tuners->ignore_nice_load) /* nothing to do */
		return count;

	chill_tuners->ignore_nice_load = input;

	/* we need to re-evaluate prev_cpu_idle */
	for_each_online_cpu(j) {
		struct cs_cpu_dbs_info_s *dbs_info;
		dbs_info = &per_cpu(cs_cpu_dbs_info, j);
		dbs_info->cdbs.prev_cpu_idle = get_cpu_idle_time(j,
					&dbs_info->cdbs.prev_cpu_wall, 0);
		if (chill_tuners->ignore_nice_load)
			dbs_info->cdbs.prev_cpu_nice =
				kcpustat_cpu(j).cpustat[CPUTIME_NICE];
	}
	return count;
}

static ssize_t store_freq_step(struct dbs_data *dbs_data, const char *buf,
		size_t count)
{
	struct chill_dbs_tuners *chill_tuners = dbs_data->tuners;
	unsigned int input;
	int ret;
	ret = sscanf(buf, "%u", &input);

	if (ret != 1)
		return -EINVAL;

	if (input > 100)
		input = 100;

	/*
	 * no need to test here if freq_step is zero as the user might actually
	 * want this, they would be crazy though :)
	 */
	chill_tuners->freq_step = input;
	return count;
}

static ssize_t store_sleep_depth(struct dbs_data *dbs_data, const char *buf,
		size_t count)
{
	struct chill_dbs_tuners *chill_tuners = dbs_data->tuners;
	unsigned int input;
	int ret;
	ret = sscanf(buf, "%u", &input);

	if (ret != 1)
		return -EINVAL;

	if (input > 5)
		input = 5;

	chill_tuners->sleep_depth = input;
	return count;
}

static ssize_t store_boost_enabled(struct dbs_data *dbs_data, const char *buf,
		size_t count)
{
	struct chill_dbs_tuners *chill_tuners = dbs_data->tuners;
	unsigned int input;
	int ret;
	ret = sscanf(buf, "%u", &input);

	if (ret != 1)
		return -EINVAL;

	if (input >= 1)
		input = 1;
	else
		input = 0;

	chill_tuners->boost_enabled = input;
	return count;
}

static ssize_t store_boost_count(struct dbs_data *dbs_data, const char *buf,
		size_t count)
{
	struct chill_dbs_tuners *chill_tuners = dbs_data->tuners;
	unsigned int input;
	int ret;
	ret = sscanf(buf, "%u", &input);

	if (ret != 1)
		return -EINVAL;

	if (input >= 5)
		input = 5;

	if (input = 0)
		input = 0;

	chill_tuners->boost_count = input;
	return count;
}

show_store_one(chill, sampling_rate);
show_store_one(chill, up_threshold);
show_store_one(chill, down_threshold);
show_store_one(chill, down_threshold_suspended);
show_store_one(chill, ignore_nice_load);
show_store_one(chill, freq_step);
declare_show_sampling_rate_min(chill);
show_store_one(chill, sleep_depth);
show_store_one(chill, boost_enabled);
show_store_one(chill, boost_count);

gov_sys_pol_attr_rw(sampling_rate);
gov_sys_pol_attr_rw(up_threshold);
gov_sys_pol_attr_rw(down_threshold);
gov_sys_pol_attr_rw(down_threshold_suspended);
gov_sys_pol_attr_rw(ignore_nice_load);
gov_sys_pol_attr_rw(freq_step);
gov_sys_pol_attr_ro(sampling_rate_min);
gov_sys_pol_attr_rw(sleep_depth);
gov_sys_pol_attr_rw(boost_enabled);
gov_sys_pol_attr_rw(boost_count);

static struct attribute *dbs_attributes_gov_sys[] = {
	&sampling_rate_min_gov_sys.attr,
	&sampling_rate_gov_sys.attr,
	&up_threshold_gov_sys.attr,
	&down_threshold_gov_sys.attr,
	&down_threshold_suspended_gov_sys.attr,
	&ignore_nice_load_gov_sys.attr,
	&freq_step_gov_sys.attr,
	&sleep_depth_gov_sys.attr,
	&boost_enabled_gov_sys.attr,
	&boost_count_gov_sys.attr,
	NULL
};

static struct attribute_group chill_attr_group_gov_sys = {
	.attrs = dbs_attributes_gov_sys,
	.name = "chill",
};

static struct attribute *dbs_attributes_gov_pol[] = {
	&sampling_rate_min_gov_pol.attr,
	&sampling_rate_gov_pol.attr,
	&up_threshold_gov_pol.attr,
	&down_threshold_gov_pol.attr,
	&down_threshold_suspended_gov_pol.attr,
	&ignore_nice_load_gov_pol.attr,
	&freq_step_gov_pol.attr,
	&sleep_depth_gov_pol.attr,
	&boost_enabled_gov_pol.attr,
	&boost_count_gov_pol.attr,
	NULL
};

static struct attribute_group chill_attr_group_gov_pol = {
	.attrs = dbs_attributes_gov_pol,
	.name = "chill",
};

/************************** sysfs end ************************/

static int chill_init(struct dbs_data *dbs_data)
{
	struct chill_dbs_tuners *tuners;

	tuners = kzalloc(sizeof(*tuners), GFP_KERNEL);
	if (!tuners) {
		pr_err("%s: kzalloc failed\n", __func__);
		return -ENOMEM;
	}

	tuners->up_threshold = DEF_FREQUENCY_UP_THRESHOLD;
	tuners->down_threshold = DEF_FREQUENCY_DOWN_THRESHOLD;
	tuners->down_threshold_suspended = DEF_FREQUENCY_DOWN_THRESHOLD_SUSPENDED;
	tuners->ignore_nice_load = 0;
	tuners->freq_step = DEF_FREQUENCY_STEP;
	tuners->sleep_depth = DEF_SLEEP_DEPTH;
	tuners->boost_enabled = DEF_BOOST_ENABLED;
	tuners->boost_count = DEF_BOOST_COUNT;

	dbs_data->tuners = tuners;
	dbs_data->min_sampling_rate = DEF_SAMPLING_RATE;
	mutex_init(&dbs_data->mutex);
	return 0;
}

static void chill_exit(struct dbs_data *dbs_data)
{
	kfree(dbs_data->tuners);
}

define_get_cpu_dbs_routines(cs_cpu_dbs_info);

static struct notifier_block chill_cpufreq_notifier_block = {
	.notifier_call = dbs_cpufreq_notifier,
};

static struct cs_ops chill_ops = {
	.notifier_block = &chill_cpufreq_notifier_block,
};

static struct common_dbs_data chill_dbs_cdata = {
	.governor = 1,
	.attr_group_gov_sys = &chill_attr_group_gov_sys,
	.attr_group_gov_pol = &chill_attr_group_gov_pol,
	.get_cpu_cdbs = get_cpu_cdbs,
	.get_cpu_dbs_info_s = get_cpu_dbs_info_s,
	.gov_dbs_timer = chill_dbs_timer,
	.gov_check_cpu = chill_check_cpu,
	.gov_ops = &chill_ops,
	.init = chill_init,
	.exit = chill_exit,
};

static int chill_cpufreq_governor_dbs(struct cpufreq_policy *policy,
				   unsigned int event)
{
	return cpufreq_governor_dbs(policy, &chill_dbs_cdata, event);
}

#ifndef CONFIG_CPU_FREQ_DEFAULT_GOV_CHILL
static
#endif
struct cpufreq_governor cpufreq_gov_chill = {
	.name			= "chill",
	.governor		= chill_cpufreq_governor_dbs,
	.max_transition_latency	= TRANSITION_LATENCY_LIMIT,
	.owner			= THIS_MODULE,
};

static int __init cpufreq_gov_dbs_init(void)
{
	return cpufreq_register_governor(&cpufreq_gov_chill);
}

static void __exit cpufreq_gov_dbs_exit(void)
{
	cpufreq_unregister_governor(&cpufreq_gov_chill);
}

MODULE_AUTHOR("Alexander Clouter <alex@digriz.org.uk>");
MODULE_AUTHOR("Joe Maples <joe@frap129.org>");
MODULE_DESCRIPTION("'cpufreq_chill' - A dynamic cpufreq governor for "
		"Low Latency Frequency Transition capable processors "
		"optimised for use in a battery environment");
MODULE_LICENSE("GPL");

#ifdef CONFIG_CPU_FREQ_DEFAULT_GOV_CHILL
fs_initcall(cpufreq_gov_dbs_init);
#else
module_init(cpufreq_gov_dbs_init);
#endif
module_exit(cpufreq_gov_dbs_exit);
