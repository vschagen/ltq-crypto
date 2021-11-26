/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2021
 *
 * Richard van Schagen <vschagen@icloud.com>
 */
#ifndef _DEU_CORE_H_
#define _DEU_CORE_H_

#include <crypto/internal/hash.h>
#include <crypto/internal/skcipher.h>

#define DEU_CRA_PRIORITY	400
#define PMU_DEU			BIT(20)

union clk_control {
	u32	word;
	struct {
		u32 Res:26;
		u32 FSOE:1;
		u32 SBWE:1;
		u32 EDIS:1;
		u32 SPEN:1;
		u32 DISS:1;
		u32 DISR:1;
	} bits;
} __packed;

enum deu_alg_type {
	DEU_ALG_TYPE_AHASH,
	DEU_ALG_TYPE_SHASH,
	DEU_ALG_TYPE_SKCIPHER,
};

struct deu_alg_template {
	enum deu_alg_type	type;
	int			mode;
	union {
		struct ahash_alg	ahash;
		struct shash_alg	shash;
		struct skcipher_alg	skcipher;
	} alg;
};

#endif /* _DEU_CORE_H_ */
