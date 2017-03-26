/* Copyright (C) 2016-2017 Tristan Marsell (tristan.marsell@t-online.de). All rights reserved.
 * Copyright (C) 2016-2017 Team DevElite. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include "wcd9xxx-resmgr.h"

extern void pdesireaudio_start(void);

extern void pdesireaudio_remove(void);

extern void pdesireaudio_init(void);

extern void pdesireaudio_api_static_mode_control(bool enable);

// Non API Methods
extern void pdesireaudio_advanced_mode_enable(struct snd_soc_codec *codec);
