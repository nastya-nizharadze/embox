/*
 * Copyright (C) 2015 Etnaviv Project
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 */

//#include <linux/kernel.h>

#include <util/log.h>

#include "etnaviv_compat.h"
#include "etnaviv_gem.h"
#include "etnaviv_gpu.h"

#include <etnaviv_xml/cmdstream.xml.h>

#define EXTRACT(val, field) (((val) & field##__MASK) >> field##__SHIFT)

struct etna_validation_state {
	struct etnaviv_gpu *gpu;
	const struct drm_etnaviv_gem_submit_reloc *relocs;
	unsigned int num_relocs;
	uint32_t *start;
};

static const struct {
	uint16_t offset;
	uint16_t size;
} etnaviv_sensitive_states[] __initconst = {
#define ST(start, num) { (start) >> 2, (num) }
	/* 2D */
	ST(0x1200, 1),
	ST(0x1228, 1),
	ST(0x1238, 1),
	ST(0x1284, 1),
	ST(0x128c, 1),
	ST(0x1304, 1),
	ST(0x1310, 1),
	ST(0x1318, 1),
	ST(0x12800, 4),
	ST(0x128a0, 4),
	ST(0x128c0, 4),
	ST(0x12970, 4),
	ST(0x12a00, 8),
	ST(0x12b40, 8),
	ST(0x12b80, 8),
	ST(0x12ce0, 8),
	/* 3D */
	ST(0x0644, 1),
	ST(0x064c, 1),
	ST(0x0680, 8),
	ST(0x086c, 1),
	ST(0x1028, 1),
	ST(0x1410, 1),
	ST(0x1430, 1),
	ST(0x1458, 1),
	ST(0x1460, 8),
	ST(0x1480, 8),
	ST(0x1500, 8),
	ST(0x1520, 8),
	ST(0x1608, 1),
	ST(0x1610, 1),
	ST(0x1658, 1),
	ST(0x165c, 1),
	ST(0x1664, 1),
	ST(0x1668, 1),
	ST(0x16a4, 1),
	ST(0x16c0, 8),
	ST(0x16e0, 8),
	ST(0x1740, 8),
	ST(0x17c0, 8),
	ST(0x17e0, 8),
	ST(0x2400, 14 * 16),
	ST(0x10800, 32 * 16),
	ST(0x14600, 16),
	ST(0x14800, 8 * 8),
#undef ST
};

#define ETNAVIV_STATES_SIZE (VIV_FE_LOAD_STATE_HEADER_OFFSET__MASK + 1u)

static uint8_t cmd_length[32] = {
	[FE_OPCODE_DRAW_PRIMITIVES] = 4,
	[FE_OPCODE_DRAW_INDEXED_PRIMITIVES] = 6,
	[FE_OPCODE_DRAW_INSTANCED] = 4,
	[FE_OPCODE_NOP] = 2,
	[FE_OPCODE_STALL] = 2,
};

bool etnaviv_cmd_validate_one(struct etnaviv_gpu *gpu, uint32_t *stream,
		unsigned int size,
		struct drm_etnaviv_gem_submit_reloc *relocs,
		unsigned int reloc_size)
{
	struct etna_validation_state state;
	uint32_t *buf = stream;
	uint32_t *end = buf + size;

	state.gpu = gpu;
	state.relocs = relocs;
	state.num_relocs = reloc_size;
	state.start = stream;

	log_debug("gpu(%p) stream(%p) size(%d) relocs(%p) reloc_size(%d)",  gpu,
			stream, size, relocs, reloc_size);
	while (buf < end) {
		uint32_t cmd = *buf;
		unsigned int len, n, off;
		unsigned int op = cmd >> 27;
		log_debug("buf(%p) cmd(%x) op(%x)", buf, cmd, op);
#if 1
		if (cmd == 0x08020193) {
			uint32_t *a = *(buf + 1);
			a += 0x10000000 / 4;

			//			*(buf + 1) -= 12;

			log_debug("vertex buffer %p", a);
			log_debug("%08x %08x %08x %08x",
					a[0], a[1], a[2], a[3]);
			log_debug("%08x %08x %08x %08x",
					a[4], a[5], a[6], a[7]);
			log_debug("%08x %08x %08x %08x",
					a[8], a[9], a[10], a[11]);
			log_debug("%08x %08x %08x %08x",
					a[12], a[13], a[14], a[15]);
			log_debug("%08x %08x",
					a[16], a[17]);
			float *f = &a[0];
			f[0] = 0.000000;
			f[1] = -0.900000;
			f[2] = 0.000000;

			f[3] = 0.000000;
			f[4] = 0.000000;
			f[5] = 1.000000;

			f[6] = 1.000000;
			f[7] = 1.000000;
			f[8] = 0.000000;


			f[9] = -0.900000;
			f[10] = 0.900000;
			f[11] = 0.000000;

			f[12] = 0.000000;
			f[13] = 0.000000;
			f[14] = 1.000000;

			f[15] = 0.000000;
			f[16] = 1.000000;
			f[17] = 0.000000;


			f[18] = 0.900000;
			f[19] = 0.900000;
			f[20] = 0.000000;

			f[21] = 0.000000;
			f[22] = 0.000000;
			f[23] = 1.000000;

			f[24] = 0.000000;
			f[25] = 1.000000;
			f[26] = 1.000000;
	//		f[24] = 0.000000;



			//			a[15] = 0x3dcccccd;
			//			a[16] = 0x3e4ccccd;
			//			a[17] = 0x3e99999a;

			for (int i = -18; i < 30; i++) {
				float *f = &a[i];
				log_debug("[%3d]f=%f x=%8x", i, *f, a[i]);

				if (0 && *f > 0.01 && *f < 0.9) {
					a[i] = 0;
					//	((a[i] & 0xffff) << 16) | (a[i] >> 16);
					/*	((a[i] & 0xff) << 24) |
						(((a[i] >> 8)  & 0xff) << 16) |
						(((a[i] >> 16) & 0xff) << 8) |
						((a[i] >> 24) & 0xff); */
					log_debug("change to x=%8x", a[i]);
				}

				dcache_flush(f, 4);

				continue;
				if (*f > 0.01) {
					*f /= 2;
				} else {
					a[i] >>= 1;
				}

				a[i] = 0;

				dcache_flush(f, 4);
			}

		}
#if 0
		if (cmd == 0x08020193) {
			*(buf + 2) = 4 * 6;
		}

		if (cmd == 0x08020e07) {
			//		*(buf + 1) = *(buf + 2) = 4;
		}
#if 0
		if (cmd == 0x08010180) {
			uint32_t *a = buf + 1;

			log_debug("vertex config prev %x", a[0]);
			a[0] &= ~0xf0;
			log_debug("vertex config new %x", a[0]);
			dcache_flush(a, 4);
		}
#endif
#endif
#endif
		switch (op) {
			case FE_OPCODE_LOAD_STATE:
				n = EXTRACT(cmd, VIV_FE_LOAD_STATE_HEADER_COUNT);
				len = ALIGN(1 + n, 2);
				log_debug("FE_OPCODE_LOAD_STATE: n(%x) len(%x) end(%x)", n, len, end);
				if (buf + len > end)
					break;

				off = EXTRACT(cmd, VIV_FE_LOAD_STATE_HEADER_OFFSET);
				log_debug("FE_OPCODE_LOAD_STATE: n(%x) cmd(%x) off(%x)", n, len, off);
				break;

			case FE_OPCODE_DRAW_2D:
				n = EXTRACT(cmd, VIV_FE_DRAW_2D_HEADER_COUNT);
				if (n == 0)
					n = 256;
				len = 2 + n * 2;
				log_debug("FE_OPCODE_DRAW_2D: n(%x) len(%x)", n, len);
				break;

			default:
				len = cmd_length[op];
				log_debug("default: n(%x) len(%x) op(%x)", n, len, op);
				if (len == 0) {
					log_error("%s: op %u not permitted at offset %tu\n",
							__func__, op, buf - state.start);
					len = 0; /* Treat as NOP */
					buf = end;
				}
				break;
		}

		buf += len;
	}

	if (buf > end) {
		log_error("%s: commands overflow end of buffer: %tu > %u\n",
				__func__, buf - state.start, size);
		return false;
	}

	return true;
}
