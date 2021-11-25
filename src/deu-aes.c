// SPDX-License-Identifier: GPL-2.0
/*
 * Based on  the original ltq-deu driver
 *
 * DATE		: September 8, 2009
 * AUTHOR	: Mohammad Firdaus
 * DESCRIPTION  : Data Encryption Unit Driver for AES Algorithm
 * COPYRIGHT	: Copyright(c) 2009
 *		  Infineon Technologies AG
 *		  Am Campeon 1-12, 85579 Neubiberg, Germany
 *
 * AES-XTS and CBCMAC(AES) Copyright (C) 2021 Daniel Kestrel
 *
 * Copyright (C) 2021 Richard van Schagen <vschagen@icloud.com>
 */

#include <crypto/aes.h>
#include <crypto/ctr.h>
#include <crypto/b128ops.h>
#include <crypto/gf128mul.h>
#include <crypto/scatterwalk.h>
#include <crypto/xts.h>
#include <linux/scatterlist.h>
#include <linux/spinlock.h>

#include "deu-aes.h"
#include "deu-core.h"


__iomem void *ltq_aes_membase;
spinlock_t ltq_aes_lock;

// Init AES Engine (vr9) TODO!
void aes_init_hw(__iomem void *base)
{
	ltq_aes_membase = base + 0x50;

	if (base) {
		struct aes_t *aes = (struct aes_t *)ltq_aes_membase;

		aes->CTRL.bits.SM = 1;
		aes->CTRL.bits.NDC = 1;
		wmb();
		aes->CTRL.bits.ENDI = 1;
		wmb();
		aes->CTRL.bits.ARS = 0;
		wmb();
	}

	spin_lock_init(&ltq_aes_lock);
}

static void aes_set_key_hw(struct aes_ctx *ctx)
{
	struct aes_t *aes = (struct aes_t *)ltq_aes_membase;
	u32 *key = ctx->key;
	int keylen = ctx->keylen;
	u32 *keyreg = &aes->K7R;
	int keywords = (keylen / 4);
	int i;

	if (ctx->use_tweak)
		key = ctx->tweakkey;

	aes->CTRL.bits.K =  (keylen / 8) - 2;

	for (i = 0; i < keywords; i++)
		keyreg[8 - keywords + i] = key[i];

	 /* let HW pre-process DEcryption key in any case(even if
	  * ENcryption is used). Key Valid(KV) bit is then only
	 * checked in decryption routine!
	 */

	 aes->CTRL.bits.PNK =  1;
}

static void deu_transform_block(struct aes_ctx *ctx, u32 *iv, u8 *out_arg,
			const u8 *in_arg, size_t nbytes, int mode, bool enc)
{
	struct aes_t *aes = (struct aes_t *)ltq_aes_membase;
	union aes_control aesc;
	const u32 *in = (u32 *)in_arg;
	u32 *out = (u32 *)out_arg;
	unsigned long flag;
	int i = 0;

	spin_lock_irqsave(&ltq_aes_lock, flag);

	aes_set_key_hw(ctx);

	aes->CTRL.bits.E_D = !enc;
	aes->CTRL.bits.O = mode;

	if (iv) {
		aes->IV3R = iv[0];
		aes->IV2R = iv[1];
		aes->IV1R = iv[2];
		aes->IV0R = iv[3];
	};

	while (nbytes) {
		aes->ID3R = in[i + 0];
		aes->ID2R = in[i + 1];
		aes->ID1R = in[i + 2];
		aes->ID0R = in[i + 3];

		do {
			aesc.word = __raw_readl(ltq_aes_membase);
		} while (aesc.bits.BUS);

		out[i + 0] = aes->OD3R;
		out[i + 1] = aes->OD2R;
		out[i + 2] = aes->OD1R;
		out[i + 3] = aes->OD0R;

		nbytes -= AES_BLOCK_SIZE;
		i += (AES_BLOCK_SIZE / 4);
	}

	if (iv) {
		iv[0] = aes->IV3R;
		iv[1] = aes->IV2R;
		iv[2] = aes->IV1R;
		iv[3] = aes->IV0R;
	}

	spin_unlock_irqrestore(&ltq_aes_lock, flag);
}

static void deu_transform_partial(struct aes_ctx *ctx, u32 *iv, u8 *out_arg,
			const u8 *in_arg, size_t nbytes, int mode, bool enc)
{
	struct aes_t *aes = (struct aes_t *)ltq_aes_membase;
	union aes_control aesc;
	u32 buf[AES_BLOCK_SIZE / 4];
	const u32 *in = (u32 *)in_arg;
	u32 *out = (u32 *)out_arg;
	unsigned long flag;

	spin_lock_irqsave(&ltq_aes_lock, flag);

	aes_set_key_hw(ctx);

	aes->CTRL.bits.E_D = !enc;
	aes->CTRL.bits.O = mode;

	aes->IV3R = iv[0];
	aes->IV2R = iv[1];
	aes->IV1R = iv[2];
	aes->IV0R = iv[3];

	memcpy(&buf, in, nbytes);

	aes->ID3R = buf[0];
	aes->ID2R = buf[1];
	aes->ID1R = buf[2];
	aes->ID0R = buf[3];

	do {
		aesc.word = __raw_readl(ltq_aes_membase);
	} while (aesc.bits.BUS);

	buf[0] = aes->OD3R;
	buf[1] = aes->OD2R;
	buf[2] = aes->OD1R;
	buf[3] = aes->OD0R;

	memcpy(out, &buf, nbytes);

	iv[0] = aes->IV3R;
	iv[1] = aes->IV2R;
	iv[2] = aes->IV1R;
	iv[3] = aes->IV0R;

	spin_unlock_irqrestore(&ltq_aes_lock, flag);
}

static void deu_aes_xts_transform(struct aes_ctx *ctx, u32 *iv, u8 *out_arg,
			const u8 *in_arg, size_t nbytes, bool enc)
{
    	struct aes_t *aes = (struct aes_t *)ltq_aes_membase;
	union aes_control aesc;
	const u32 *in = (u32 *)in_arg;
	u32 *out = (u32 *)out_arg;
        unsigned long flag;
	u32 saveiv[AES_BLOCK_SIZE / 4];
	u32 state[XTS_BLOCK_SIZE / 4];
	int i = 0, j;
	int byte_cnt = nbytes;

	spin_lock_irqsave(&ltq_aes_lock, flag);

	aes_set_key_hw (ctx);

	aes->CTRL.bits.E_D = !enc;
	aes->CTRL.bits.O = MODE_CBC;

	while (byte_cnt >= AES_BLOCK_SIZE) {
		if (!enc) {
			if (((byte_cnt % AES_BLOCK_SIZE) > 0) &&
					(byte_cnt < (2 * XTS_BLOCK_SIZE))) {
				memcpy(saveiv, iv, AES_BLOCK_SIZE);
				gf128mul_x_ble((le128 *)iv, (le128 *)iv);
			}
			u128_xor((u128 *)&in[i], (u128 *)&in[i], (u128 *)iv);
		}

		aes->IV3R = iv[0];
		aes->IV2R = iv[1];
		aes->IV1R = iv[2];
		aes->IV0R = iv[3];

		aes->ID3R = in[i + 0];
		aes->ID2R = in[i + 1];
		aes->ID1R = in[i + 2];
		aes->ID0R = in[i + 3];

		do {
			aesc.word = __raw_readl(ltq_aes_membase);
		} while (aesc.bits.BUS);

		out[i + 0] = aes->OD3R;
		out[i + 1] = aes->OD2R;
		out[i + 2] = aes->OD1R;
		out[i + 3] = aes->OD0R;

        	if (enc)
			u128_xor((u128 *)&out[i], (u128 *)&out[i], (u128 *)iv);

		gf128mul_x_ble((le128 *)iv, (le128 *)iv);
		i += (AES_BLOCK_SIZE / 4);
		byte_cnt -= AES_BLOCK_SIZE;
	}

	if (byte_cnt) {
		j = i - 4;

		if (!enc)
			memcpy(iv, saveiv, AES_BLOCK_SIZE);

		aes->IV3R = iv[0];
		aes->IV2R = iv[1];
		aes->IV1R = iv[2];
		aes->IV0R = iv[3];

		memcpy(state, &out[j], AES_BLOCK_SIZE);
      		memcpy(state, &in[i], byte_cnt);
		if (!enc)
			u128_xor((u128 *)state, (u128 *)state, (u128 *)iv);

		aes->ID3R = state[0];
		aes->ID2R = state[1];
		aes->ID1R = state[2];
		aes->ID0R = state[3];

		memcpy(&out[i], &out[j], byte_cnt);

		do {
			aesc.word = __raw_readl(ltq_aes_membase);
		} while (aesc.bits.BUS);

		out[j + 0] = aes->OD3R;
		out[j + 1] = aes->OD2R;
		out[j + 2] = aes->OD1R;
		out[j + 3] = aes->OD0R;

		if (enc)
			u128_xor((u128 *)&out[j], (u128 *)&out[j], (u128 *)iv);
	}

	spin_unlock_irqrestore(&ltq_aes_lock, flag);
}

static int deu_skcipher_crypt(struct skcipher_request *req, int mode, bool enc)
{
	struct aes_ctx *ctx = crypto_tfm_ctx(req->base.tfm);
	struct skcipher_walk walk;
	unsigned int blk_bytes, nbytes;
	u32 *iv = NULL;
	u32 rfc3686iv[AES_BLOCK_SIZE / 4];
	int err;

	err = skcipher_walk_virt(&walk, req, false);

	if (mode > 0)
		iv = (u32 *)walk.iv;

	if (mode == MODE_RFC3686) {
		rfc3686iv[0] = ctx->nonce;
		rfc3686iv[1] = iv[0];
		rfc3686iv[2] = iv[1];
		rfc3686iv[3] = cpu_to_be32(1);
		iv = rfc3686iv;
		mode = MODE_CTR;
	}

	while ((nbytes = blk_bytes = walk.nbytes) &&
					(walk.nbytes >= AES_BLOCK_SIZE)) {
		blk_bytes -= (nbytes % AES_BLOCK_SIZE);

		deu_transform_block(ctx, iv, walk.dst.virt.addr,
				walk.src.virt.addr, blk_bytes, mode, enc);
		nbytes &= AES_BLOCK_SIZE - 1;
		err = skcipher_walk_done(&walk, nbytes);
	}
	/* For stream ciphers handle last block
	 * less than AES_BLOCK_SIZE (ofb, cfb and ctr)
	 */
	if (walk.nbytes)  {
		deu_transform_partial(ctx, iv, walk.dst.virt.addr,
				walk.src.virt.addr, walk.nbytes, mode, enc);
		err = skcipher_walk_done(&walk, 0);
	}

	return err;
}

static int deu_aes_xts_crypt(struct skcipher_request *req, bool enc)
{
	struct aes_ctx *ctx = crypto_tfm_ctx(req->base.tfm);
	struct skcipher_walk walk;
	u32 *iv = NULL;
	unsigned int blk_bytes, nbytes, processed = 0;
	int err;

	err = skcipher_walk_virt(&walk, req, false);

	if (req->cryptlen < XTS_BLOCK_SIZE)
		return -EINVAL;

	ctx->use_tweak = true;
	deu_transform_block(ctx, iv, walk.iv, walk.iv, AES_BLOCK_SIZE, 0, true);
	ctx->use_tweak = false;

	iv = (u32 *)walk.iv;

    	while ((nbytes = walk.nbytes)
				&& (walk.nbytes >= (XTS_BLOCK_SIZE * 2)) ) {
		if (nbytes == walk.total) {
			blk_bytes = nbytes;
		} else {
			blk_bytes = nbytes & ~(XTS_BLOCK_SIZE - 1);

			if ((req->cryptlen - processed - blk_bytes) <
							(XTS_BLOCK_SIZE)) {
				if (blk_bytes > (2 * XTS_BLOCK_SIZE)) {
					blk_bytes -= XTS_BLOCK_SIZE;
				} else {
					break;
				}
			}
		}
		deu_aes_xts_transform(ctx, iv, walk.dst.virt.addr,
			walk.src.virt.addr, blk_bytes, enc);
		err = skcipher_walk_done(&walk, nbytes - blk_bytes);
		processed += blk_bytes;
	}

	if ((walk.nbytes)) {
		nbytes = req->cryptlen - processed;

		scatterwalk_map_and_copy(ctx->lastbuffer, req->src,
					(req->cryptlen - nbytes), nbytes, 0);
		deu_aes_xts_transform(ctx, iv, ctx->lastbuffer,
					ctx->lastbuffer, nbytes, enc);
        	scatterwalk_map_and_copy(ctx->lastbuffer, req->dst,
					(req->cryptlen - nbytes), nbytes, 1);
		skcipher_request_complete(req, 0);
	}

	return err;
}

/* Crypto API */
static int deu_skcipher_setkey(struct crypto_skcipher *tfm, const u8 *key,
			unsigned int len)
{
	struct crypto_tfm *ctfm = crypto_skcipher_tfm(tfm);
	struct aes_ctx *ctx = crypto_tfm_ctx(ctfm);

	switch (len) {
	case AES_KEYSIZE_128:
	case AES_KEYSIZE_192:
	case AES_KEYSIZE_256:
		break;
	default:
		return -EINVAL;
	}

	ctx->keylen = len;
	ctx->use_tweak = false;
	memcpy(&ctx->key, key, len);

	return 0;
}

static int deu_skcipher_rfc3686_setkey(struct crypto_skcipher *tfm,
				const u8 *key, unsigned int len)
{
	struct crypto_tfm *ctfm = crypto_skcipher_tfm(tfm);
	struct aes_ctx *ctx = crypto_tfm_ctx(ctfm);

	if (!key || !len)
		return -EINVAL;

	if (len < CTR_RFC3686_NONCE_SIZE)
		return -EINVAL;

	len -= CTR_RFC3686_NONCE_SIZE;
	memcpy(&ctx->nonce, key + len, CTR_RFC3686_NONCE_SIZE);

	return deu_skcipher_setkey(tfm, key, len);
}

static int deu_skcipher_xts_setkey(struct crypto_skcipher *tfm,
				const u8 *key, unsigned int keylen)
{
	struct aes_ctx *ctx = crypto_tfm_ctx(crypto_skcipher_tfm(tfm));
	unsigned int len = (keylen / 2);

	if (keylen % 2)
		return -EINVAL;

	memcpy(&ctx->tweakkey, key + len, len);

	return deu_skcipher_setkey(tfm, key, len);
}

static int deu_skcipher_encrypt(struct skcipher_request *req)
{
	struct deu_alg_template *tmpl = container_of(req->base.tfm->__crt_alg,
				struct deu_alg_template, alg.skcipher.base);

	if (tmpl->mode == MODE_XTS)
		return deu_aes_xts_crypt(req, true);

	return deu_skcipher_crypt(req, tmpl->mode, true);
}

static int deu_skcipher_decrypt(struct skcipher_request *req)
{
	struct deu_alg_template *tmpl = container_of(req->base.tfm->__crt_alg,
			struct deu_alg_template, alg.skcipher.base);

	if (tmpl->mode == MODE_XTS)
		return deu_aes_xts_crypt(req, false);

	return deu_skcipher_crypt(req, tmpl->mode, false);
}

struct deu_alg_template deu_alg_ecb_aes = {
	.type = DEU_ALG_TYPE_SKCIPHER,
	.mode = MODE_ECB,
	.alg.skcipher = {
		.setkey = deu_skcipher_setkey,
		.encrypt = deu_skcipher_encrypt,
		.decrypt = deu_skcipher_decrypt,
		.min_keysize = AES_MIN_KEY_SIZE,
		.max_keysize = AES_MAX_KEY_SIZE,
		.ivsize = 0,
		.base = {
			.cra_name = "ecb(aes)",
			.cra_driver_name = "ecb(aes-deu)",
			.cra_priority = DEU_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_TYPE_SKCIPHER |
					CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = AES_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct aes_ctx),
			.cra_alignmask = 0,
			.cra_module = THIS_MODULE,
		},
	},
};

struct deu_alg_template deu_alg_cbc_aes = {
	.type = DEU_ALG_TYPE_SKCIPHER,
	.mode = MODE_CBC,
	.alg.skcipher = {
		.setkey = deu_skcipher_setkey,
		.encrypt = deu_skcipher_encrypt,
		.decrypt = deu_skcipher_decrypt,
		.min_keysize = AES_MIN_KEY_SIZE,
		.max_keysize = AES_MAX_KEY_SIZE,
		.ivsize = AES_BLOCK_SIZE,
		.base = {
			.cra_name = "cbc(aes)",
			.cra_driver_name = "cbc(aes-deu)",
			.cra_priority = DEU_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_TYPE_SKCIPHER |
					CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = AES_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct aes_ctx),
			.cra_alignmask = 0xf,
			.cra_module = THIS_MODULE,
		},
	},
};

struct deu_alg_template deu_alg_ofb_aes = {
	.type = DEU_ALG_TYPE_SKCIPHER,
	.mode = MODE_OFB,
	.alg.skcipher = {
		.setkey = deu_skcipher_setkey,
		.encrypt = deu_skcipher_encrypt,
		.decrypt = deu_skcipher_decrypt,
		.min_keysize = AES_MIN_KEY_SIZE,
		.max_keysize = AES_MAX_KEY_SIZE,
		.chunksize = AES_BLOCK_SIZE,
		.walksize = AES_BLOCK_SIZE,
		.ivsize = AES_BLOCK_SIZE,
		.base = {
			.cra_name = "ofb(aes)",
			.cra_driver_name = "ofb(aes-deu)",
			.cra_priority = DEU_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_TYPE_SKCIPHER |
					CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = 1,
			.cra_ctxsize = sizeof(struct aes_ctx),
			.cra_alignmask = 0,
			.cra_module = THIS_MODULE,
		},
	},
};

struct deu_alg_template deu_alg_cfb_aes = {
	.type = DEU_ALG_TYPE_SKCIPHER,
	.mode = MODE_CFB,
	.alg.skcipher = {
		.setkey = deu_skcipher_setkey,
		.encrypt = deu_skcipher_encrypt,
		.decrypt = deu_skcipher_decrypt,
		.min_keysize = AES_MIN_KEY_SIZE,
		.max_keysize = AES_MAX_KEY_SIZE,
		.chunksize = AES_BLOCK_SIZE,
		.walksize = AES_BLOCK_SIZE,
		.ivsize = AES_BLOCK_SIZE,
		.base = {
			.cra_name = "cfb(aes)",
			.cra_driver_name = "cfb(aes-deu)",
			.cra_priority = DEU_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_TYPE_SKCIPHER |
					CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = 1,
			.cra_ctxsize = sizeof(struct aes_ctx),
			.cra_alignmask = 0,
			.cra_module = THIS_MODULE,
		},
	},
};

struct deu_alg_template deu_alg_ctr_aes = {
	.type = DEU_ALG_TYPE_SKCIPHER,
	.mode = MODE_CTR,
	.alg.skcipher = {
		.setkey = deu_skcipher_setkey,
		.encrypt = deu_skcipher_encrypt,
		.decrypt = deu_skcipher_decrypt,
		.min_keysize = AES_MIN_KEY_SIZE,
		.max_keysize = AES_MAX_KEY_SIZE,
		.chunksize = AES_BLOCK_SIZE,
		.ivsize = AES_BLOCK_SIZE,
		.base = {
			.cra_name = "ctr(aes)",
			.cra_driver_name = "ctr(aes-deu)",
			.cra_priority = DEU_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_TYPE_SKCIPHER |
					CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = 1,
			.cra_ctxsize = sizeof(struct aes_ctx),
			.cra_alignmask = 1,
			.cra_module = THIS_MODULE,
		},
	},
};

struct deu_alg_template deu_alg_rfc3686_aes = {
	.type = DEU_ALG_TYPE_SKCIPHER,
	.mode = MODE_RFC3686,
	.alg.skcipher = {
		.setkey = deu_skcipher_rfc3686_setkey,
		.encrypt = deu_skcipher_encrypt,
		.decrypt = deu_skcipher_decrypt,
		.min_keysize = AES_MIN_KEY_SIZE + CTR_RFC3686_NONCE_SIZE,
		.max_keysize = AES_MAX_KEY_SIZE + CTR_RFC3686_NONCE_SIZE,
		.chunksize = AES_BLOCK_SIZE,
		.ivsize = CTR_RFC3686_IV_SIZE,
		.base = {
			.cra_name = "rfc3686(ctr(aes))",
			.cra_driver_name = "rfc3686(ctr(aes-deu))",
			.cra_priority = DEU_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_TYPE_SKCIPHER |
					CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = 1,
			.cra_ctxsize = sizeof(struct aes_ctx),
			.cra_alignmask = 1,
			.cra_module = THIS_MODULE,
		},
	},
};

struct deu_alg_template deu_alg_xts_aes = {
	.type = DEU_ALG_TYPE_SKCIPHER,
	.mode = MODE_XTS,
	.alg.skcipher = {
		.setkey = deu_skcipher_xts_setkey,
		.encrypt = deu_skcipher_encrypt,
		.decrypt = deu_skcipher_decrypt,
		.min_keysize = AES_MIN_KEY_SIZE * 2,
		.max_keysize = AES_MAX_KEY_SIZE * 2,
		.walksize = XTS_BLOCK_SIZE * 2,
		.ivsize = XTS_BLOCK_SIZE,
		.base = {
			.cra_name = "xts(aes)",
			.cra_driver_name = "xts(aes-deu)",
			.cra_priority = DEU_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_TYPE_SKCIPHER |
					CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = XTS_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct aes_ctx),
			.cra_alignmask = 0,
			.cra_module = THIS_MODULE,
		},
	},
};
