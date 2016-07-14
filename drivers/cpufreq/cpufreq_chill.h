/*
 *  drivers/cpufreq/cpufreq_chill.h
 *
 *  Copyright (C)  2016 Joe Maples <joe@frap129.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef _CPUFREQ_CHILL_H
#define _CPUFREQ_CHILL_H

#include "cpufreq_governor.h"

#define GOV_CHILL	(2)

struct chill_dbs_tuners {
	unsigned int ignore_nice_load;
	unsigned int sampling_rate;
	unsigned int up_threshold;
	unsigned int down_threshold;
	unsigned int down_threshold_suspended;
	unsigned int freq_step;
	unsigned int sleep_depth;
	unsigned int boost_enabled;
	unsigned int boost_count;
};

#endif
