// SPDX-License-Identifier: GPL-2.0
/*
 * Based on  the original ltq-deu driver
 *
 * DATE		: September 8, 2009
 * AUTHOR	: Mohammad Firdaus
 * DESCRIPTION  : Data Encryption Unit Driver for DES Algorithm
 * COPYRIGHT	: Copyright(c) 2009
 *		  Infineon Technologies AG
 *		  Am Campeon 1-12, 85579 Neubiberg, Germany
 *
 * Copyright (C) 2021 Richard van Schagen <vschagen@icloud.com>
 */

#include <crypto/ctr.h>
#include <crypto/scatterwalk.h>
#include <linux/spinlock.h>

#include "deu-core.h"
#include "deu-des.h"

static void __iomem *ltq_des_membase;
static DEFINE_SPINLOCK(ltq_des_lock);

// Init DES Engine (vr9) TODO!
void des_init_hw(__iomem void *base)
{
	ltq_des_membase = base + 0x10;

	if (base) {
		struct des_t *des = (struct des_t *)ltq_des_membase;

		// start crypto engine with write to ILR
		des->CTRL.bits.SM = 1;
		des->CTRL.bits.NDC = 1;
		wmb();
		des->CTRL.bits.ENDI = 1;
		wmb();
		des->CTRL.bits.ARS = 0;
		wmb();
	}
}

static inline void des_set_key_hw(struct deu_des_ctx *ctx)
{
	struct des_t *des = (struct des_t *)ltq_des_membase;
	u32 *key = ctx->key;
	u32 *keyreg = &des->K1HR;
	int keywords;
	int i;

	des->CTRL.bits.M =  ctx->keylen;
	if (ctx->keylen == 0) // 0 for des
		keywords = 2;
	else
		keywords = (ctx->keylen - 1) * 2;

	for (i = 0; i < keywords; i++)
		keyreg[i] = key[i];
}

static void deu_transform_block(struct deu_des_ctx *ctx, u32 *iv, u8 *out_arg,
			const u8 *in_arg, size_t nbytes, int mode, bool enc)
{
	struct des_t *des = (struct des_t *)ltq_des_membase;
	union des_control desc;
	const u32 *in = (u32 *)in_arg;
	u32 *out = (u32 *)out_arg;
	unsigned long flag;
	int i = 0;

	spin_lock_irqsave(&ltq_des_lock, flag);

	des_set_key_hw(ctx);

	des->CTRL.bits.E_D = !enc;
	des->CTRL.bits.O = mode;

	if (iv) {
		des->IVHR = iv[0];
		des->IVLR = iv[1];
	};

	while (nbytes) {
		des->IHR = in[i + 0];
		des->ILR = in[i + 1];

		do {
			desc.word = __raw_readl(ltq_des_membase);
		} while (desc.bits.BUS);

		out[i + 0] = des->OHR;
		out[i + 1] = des->OLR;

		nbytes -= DES_BLOCK_SIZE;
		i += (DES_BLOCK_SIZE / 4);
	}

	if (iv) {
		iv[0] = des->IVHR;
		iv[1] = des->IVLR;
	}

	spin_unlock_irqrestore(&ltq_des_lock, flag);
}

static int deu_skcipher_crypt(struct skcipher_request *req, int mode, bool enc)
{
	struct deu_des_ctx *ctx = crypto_tfm_ctx(req->base.tfm);
	struct skcipher_walk walk;
	unsigned int blk_bytes, nbytes;
	u32 *iv = NULL;
	int err;

	err = skcipher_walk_virt(&walk, req, false);

	if (mode > 0)
		iv = (u32 *)walk.iv;

	while ((nbytes = blk_bytes = walk.nbytes)
				&& (walk.nbytes >= DES_BLOCK_SIZE)) {
		blk_bytes -= (nbytes % DES_BLOCK_SIZE);

		deu_transform_block(ctx, iv, walk.dst.virt.addr,
				walk.src.virt.addr, blk_bytes, mode, enc);
		nbytes &= DES_BLOCK_SIZE - 1;
		err = skcipher_walk_done(&walk, nbytes);
	}
	/* For stream ciphers handle last block
	 * less than DES_BLOCK_SIZE (ofb, cfb and ctr)
	 */
	if (walk.nbytes) {
		u8 buf[DES_BLOCK_SIZE];

		memcpy(&buf, walk.src.virt.addr, nbytes);
		deu_transform_block(ctx, iv, buf, buf,
						DES_BLOCK_SIZE, mode, enc);

		memcpy(walk.dst.virt.addr, &buf, nbytes);
		err = skcipher_walk_done(&walk, 0);
	}

	return err;
}

/* Crypto API */
static int deu_skcipher_des_setkey(struct crypto_skcipher *tfm, const u8 *key,
			unsigned int len)
{
	struct crypto_tfm *ctfm = crypto_skcipher_tfm(tfm);
	struct deu_des_ctx *ctx = crypto_tfm_ctx(ctfm);
	int err;

	err = verify_skcipher_des_key(tfm, key);
	if (err)
		return err;

	ctx->keylen = 0; // this indicates DES
	memcpy(&ctx->key, key, len);

	return 0;
}

static int deu_skcipher_3des_setkey(struct crypto_skcipher *tfm,
				const u8 *key, unsigned int len)
{
	struct crypto_tfm *ctfm = crypto_skcipher_tfm(tfm);
	struct deu_des_ctx *ctx = crypto_tfm_ctx(ctfm);
	int err;

	err = verify_skcipher_des3_key(tfm, key);
	if (err)
		return err;

	ctx->keylen = len / 8 + 1;
	memcpy(&ctx->key, key, len);

	return 0;
}

static int deu_skcipher_encrypt(struct skcipher_request *req)
{
	struct deu_alg_template *tmpl = container_of(req->base.tfm->__crt_alg,
				struct deu_alg_template, alg.skcipher.base);

	return deu_skcipher_crypt(req, tmpl->mode, true);
}

static int deu_skcipher_decrypt(struct skcipher_request *req)
{
	struct deu_alg_template *tmpl = container_of(req->base.tfm->__crt_alg,
			struct deu_alg_template, alg.skcipher.base);

	return deu_skcipher_crypt(req, tmpl->mode, false);
}

struct deu_alg_template deu_alg_ecb_des = {
	.type = DEU_ALG_TYPE_SKCIPHER,
	.mode = MODE_ECB,
	.alg.skcipher = {
		.setkey = deu_skcipher_des_setkey,
		.encrypt = deu_skcipher_encrypt,
		.decrypt = deu_skcipher_decrypt,
		.min_keysize = DES_KEY_SIZE,
		.max_keysize = DES_KEY_SIZE,
		.ivsize = 0,
		.base = {
			.cra_name = "ecb(des)",
			.cra_driver_name = "ecb(des-deu)",
			.cra_priority = DEU_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_TYPE_SKCIPHER |
					CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = DES_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct deu_des_ctx),
			.cra_alignmask = 0,
			.cra_module = THIS_MODULE,
		},
	},
};

struct deu_alg_template deu_alg_cbc_des = {
	.type = DEU_ALG_TYPE_SKCIPHER,
	.mode = MODE_CBC,
	.alg.skcipher = {
		.setkey = deu_skcipher_des_setkey,
		.encrypt = deu_skcipher_encrypt,
		.decrypt = deu_skcipher_decrypt,
		.min_keysize = DES_KEY_SIZE,
		.max_keysize = DES_KEY_SIZE,
		.ivsize = DES_BLOCK_SIZE,
		.base = {
			.cra_name = "cbc(des)",
			.cra_driver_name = "cbc(des-deu)",
			.cra_priority = DEU_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_TYPE_SKCIPHER |
					CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = DES_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct deu_des_ctx),
			.cra_alignmask = 0x7,
			.cra_module = THIS_MODULE,
		},
	},
};

struct deu_alg_template deu_alg_ofb_des = {
	.type = DEU_ALG_TYPE_SKCIPHER,
	.mode = MODE_OFB,
	.alg.skcipher = {
		.setkey = deu_skcipher_des_setkey,
		.encrypt = deu_skcipher_encrypt,
		.decrypt = deu_skcipher_decrypt,
		.min_keysize = DES_KEY_SIZE,
		.max_keysize = DES_KEY_SIZE,
		.chunksize = DES_BLOCK_SIZE,
		.walksize = DES_BLOCK_SIZE,
		.ivsize = DES_BLOCK_SIZE,
		.base = {
			.cra_name = "ofb(des)",
			.cra_driver_name = "ofb(des-deu)",
			.cra_priority = DEU_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_TYPE_SKCIPHER |
					CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = 1,
			.cra_ctxsize = sizeof(struct deu_des_ctx),
			.cra_alignmask = 0,
			.cra_module = THIS_MODULE,
		},
	},
};

struct deu_alg_template deu_alg_cfb_des = {
	.type = DEU_ALG_TYPE_SKCIPHER,
	.mode = MODE_CFB,
	.alg.skcipher = {
		.setkey = deu_skcipher_des_setkey,
		.encrypt = deu_skcipher_encrypt,
		.decrypt = deu_skcipher_decrypt,
		.min_keysize = DES_KEY_SIZE,
		.max_keysize = DES_KEY_SIZE,
		.chunksize = DES_BLOCK_SIZE,
		.walksize = DES_BLOCK_SIZE,
		.ivsize = DES_BLOCK_SIZE,
		.base = {
			.cra_name = "cfb(des)",
			.cra_driver_name = "cfb(des-deu)",
			.cra_priority = DEU_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_TYPE_SKCIPHER |
					CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = 1,
			.cra_ctxsize = sizeof(struct deu_des_ctx),
			.cra_alignmask = 0,
			.cra_module = THIS_MODULE,
		},
	},
};

struct deu_alg_template deu_alg_ctr_des = {
	.type = DEU_ALG_TYPE_SKCIPHER,
	.mode = MODE_CTR,
	.alg.skcipher = {
		.setkey = deu_skcipher_des_setkey,
		.encrypt = deu_skcipher_encrypt,
		.decrypt = deu_skcipher_decrypt,
		.min_keysize = DES_KEY_SIZE,
		.max_keysize = DES_KEY_SIZE,
		.chunksize = DES_BLOCK_SIZE,
		.ivsize = DES_BLOCK_SIZE,
		.base = {
			.cra_name = "ctr(des)",
			.cra_driver_name = "ctr(des-deu)",
			.cra_priority = DEU_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_TYPE_SKCIPHER |
					CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = 1,
			.cra_ctxsize = sizeof(struct deu_des_ctx),
			.cra_alignmask = 1,
			.cra_module = THIS_MODULE,
		},
	},
};

struct deu_alg_template deu_alg_ecb_des3_ede = {
	.type = DEU_ALG_TYPE_SKCIPHER,
	.mode = MODE_ECB,
	.alg.skcipher = {
		.setkey = deu_skcipher_3des_setkey,
		.encrypt = deu_skcipher_encrypt,
		.decrypt = deu_skcipher_decrypt,
		.min_keysize = DES3_EDE_KEY_SIZE,
		.max_keysize = DES3_EDE_KEY_SIZE,
		.ivsize = 0,
		.base = {
			.cra_name = "ecb(des3_ede)",
			.cra_driver_name = "ecb(des3_ede-deu)",
			.cra_priority = DEU_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_TYPE_SKCIPHER |
					CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = DES3_EDE_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct deu_des_ctx),
			.cra_alignmask = 0,
			.cra_module = THIS_MODULE,
		},
	},
};

struct deu_alg_template deu_alg_cbc_des3_ede = {
	.type = DEU_ALG_TYPE_SKCIPHER,
	.mode = MODE_CBC,
	.alg.skcipher = {
		.setkey = deu_skcipher_3des_setkey,
		.encrypt = deu_skcipher_encrypt,
		.decrypt = deu_skcipher_decrypt,
		.min_keysize = DES3_EDE_KEY_SIZE,
		.max_keysize = DES3_EDE_KEY_SIZE,
		.ivsize = DES3_EDE_BLOCK_SIZE,
		.base = {
			.cra_name = "cbc(des3_ede)",
			.cra_driver_name = "cbc(des3_ede-deu)",
			.cra_priority = DEU_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_TYPE_SKCIPHER |
					CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = DES3_EDE_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct deu_des_ctx),
			.cra_alignmask = 0,
			.cra_module = THIS_MODULE,
		},
	},
};

struct deu_alg_template deu_alg_ofb_des3_ede = {
	.type = DEU_ALG_TYPE_SKCIPHER,
	.mode = MODE_OFB,
	.alg.skcipher = {
		.setkey = deu_skcipher_3des_setkey,
		.encrypt = deu_skcipher_encrypt,
		.decrypt = deu_skcipher_decrypt,
		.min_keysize = DES3_EDE_KEY_SIZE,
		.max_keysize = DES3_EDE_KEY_SIZE,
		.chunksize = DES3_EDE_BLOCK_SIZE,
		.walksize = DES3_EDE_BLOCK_SIZE,
		.ivsize = DES3_EDE_BLOCK_SIZE,
		.base = {
			.cra_name = "ofb(des3_ede)",
			.cra_driver_name = "ofb(des3_ede-deu)",
			.cra_priority = DEU_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_TYPE_SKCIPHER |
					CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = 1,
			.cra_ctxsize = sizeof(struct deu_des_ctx),
			.cra_alignmask = 0,
			.cra_module = THIS_MODULE,
		},
	},
};

struct deu_alg_template deu_alg_cfb_des3_ede = {
	.type = DEU_ALG_TYPE_SKCIPHER,
	.mode = MODE_CFB,
	.alg.skcipher = {
		.setkey = deu_skcipher_des_setkey,
		.encrypt = deu_skcipher_encrypt,
		.decrypt = deu_skcipher_decrypt,
		.min_keysize = DES3_EDE_KEY_SIZE,
		.max_keysize = DES3_EDE_KEY_SIZE,
		.chunksize = DES3_EDE_BLOCK_SIZE,
		.walksize = DES3_EDE_BLOCK_SIZE,
		.ivsize = DES3_EDE_BLOCK_SIZE,
		.base = {
			.cra_name = "cfb(des3_ede)",
			.cra_driver_name = "cfb(des3_ede-deu)",
			.cra_priority = DEU_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_TYPE_SKCIPHER |
					CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = 1,
			.cra_ctxsize = sizeof(struct deu_des_ctx),
			.cra_alignmask = 0,
			.cra_module = THIS_MODULE,
		},
	},
};

struct deu_alg_template deu_alg_ctr_des3_ede = {
	.type = DEU_ALG_TYPE_SKCIPHER,
	.mode = MODE_CTR,
	.alg.skcipher = {
		.setkey = deu_skcipher_3des_setkey,
		.encrypt = deu_skcipher_encrypt,
		.decrypt = deu_skcipher_decrypt,
		.min_keysize = DES3_EDE_KEY_SIZE,
		.max_keysize = DES3_EDE_KEY_SIZE,
		.chunksize = DES3_EDE_BLOCK_SIZE,
		.ivsize = DES3_EDE_BLOCK_SIZE,
		.base = {
			.cra_name = "ctr(des3_ede",
			.cra_driver_name = "ctr(des3_ede-deu)",
			.cra_priority = DEU_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_TYPE_SKCIPHER |
					CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = 1,
			.cra_ctxsize = sizeof(struct deu_des_ctx),
			.cra_alignmask = 1,
			.cra_module = THIS_MODULE,
		},
	},
};
