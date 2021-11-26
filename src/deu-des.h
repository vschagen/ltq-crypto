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
 *
 * Copyright (C) 2021 Richard van Schagen <vschagen@icloud.com>
 */

#ifndef _DEU_DES_H_
#define _DEU_DES_H_

#include <crypto/internal/des.h>

#define MODE_ECB	0
#define MODE_CBC	1
#define MODE_OFB	2
#define MODE_CFB	3
#define MODE_CTR	4

union des_control {
	u32	word;
	struct {
		u32 KRE:1;
		u32 reserved1:5;
		u32 GO:1;
		u32 STP:1;
		u32 Res2:6;
                u32 NDC:1;
                u32 ENDI:1;
                u32 Res3:2;
		u32 F:3;
		u32 O:3;
		u32 BUS:1;
		u32 DAU:1;
		u32 ARS:1;
		u32 SM:1;
		u32 E_D:1;
		u32 M:3;
	} bits;
} __packed;

struct des_t {
	union des_control	CTRL;
	u32			IHR;
	u32			ILR;
	u32			K1HR;
	u32			K1LR;
	u32			K2HR;
	u32			K2LR;
	u32			K3HR;
	u32			K3LR;
	u32			IVHR;
	u32			IVLR;
	u32			OHR;
	u32			OLR;
};

struct deu_des_ctx {
	int	keylen;
        u32	key[DES3_EDE_KEY_SIZE / 4];
	u32	iv[DES_BLOCK_SIZE / 4];
};

void des_init_hw(__iomem void *base);

#endif /* _DEU_DES_H_ */
