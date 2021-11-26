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

#ifndef _DEU_AES_H_
#define _DEU_AES_H_

#include <crypto/aes.h>
#include <crypto/xts.h>

#define MODE_ECB	0
#define MODE_CBC	1
#define MODE_OFB	2
#define MODE_CFB	3
#define MODE_CTR	4
#define MODE_RFC3686	5	// Software mode
#define MODE_XTS	6	// Software mode

union aes_control {
	u32	word;
	struct {
		u32 KRE:1;
		u32 reserved1:4;
		u32 PNK:1;
		u32 GO:1;
		u32 STP:1;
		u32 reserved2:6;
		u32 NDC:1;
		u32 ENDI:1;
		u32 reserved3:2;
		u32 F:3;	//fbs
		u32 O:3;	//om
		u32 BUS:1;	//bsy
		u32 DAU:1;
		u32 ARS:1;
		u32 SM:1;
		u32 E_D:1;
		u32 KV:1;
		u32 K:2;	//KL
	} bits;
} __packed;

struct aes_t {
	union aes_control	CTRL;
	u32			ID3R;
	u32			ID2R;
	u32			ID1R;
	u32			ID0R;
	u32			K7R;
	u32			K6R;
	u32			K5R;
	u32			K4R;
	u32			K3R;
	u32			K2R;
	u32			K1R;
	u32			K0R;
	u32			IV3R;
	u32			IV2R;
	u32			IV1R;
	u32			IV0R;
	u32			OD3R;
	u32			OD2R;
	u32			OD1R;
	u32			OD0R;
};

struct deu_aes_ctx {
	int			keylen;
	u32			key[AES_MAX_KEY_SIZE / 4];
	u32		 	nonce;
	u32			tweakkey[AES_MAX_KEY_SIZE / 4];
	u8			lastbuffer[4 * XTS_BLOCK_SIZE];
	bool			use_tweak;
	u32			byte_count;
	u32			dbn;
	int			started;
	u32			(*temp)[AES_BLOCK_SIZE / 4];
	u8			block[AES_BLOCK_SIZE];
	u8			hash[AES_BLOCK_SIZE];
};

void aes_init_hw(__iomem void *base);

#endif /* _DEU_AES_H_ */
