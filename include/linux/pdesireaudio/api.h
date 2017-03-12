/* Copyright (C) 2017 Tristan Marsell (tristan.marsell@t-online.de). All rights reserved.
 * Copyright (C) 2017 Team DevElite. All rights reserved.
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

#include "../../../sound/soc/codecs/pdesireaudio.h"

extern void enable_pdesireaudio(void) {
	pdesireaudio_start();
	pdesireaudio_init();
}

extern void disable_pdesireaudio(void) {
	pdesireaudio_remove();
	pdesireaudio_init();
}

extern void reinit_pdesireaudio(void) {
	pdesireaudio_init();
}
