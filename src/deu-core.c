// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2021
 *
 * Richard van Schagen <vschagen@icloud.com>
 */

#include <linux/module.h>
#include <linux/of_device.h>
#include <linux/platform_device.h>

#include <lantiq_soc.h>

#include "deu-core.h"
#include "deu-aes.h"

void __iomem *ltq_clk_membase;

extern struct deu_alg_template deu_alg_ecb_aes;
extern struct deu_alg_template deu_alg_cbc_aes;
extern struct deu_alg_template deu_alg_ofb_aes;
extern struct deu_alg_template deu_alg_cfb_aes;
extern struct deu_alg_template deu_alg_ctr_aes;
extern struct deu_alg_template deu_alg_rfc3686_aes;
extern struct deu_alg_template deu_alg_xts_aes;

extern struct deu_alg_template deu_alg_sha1;

static struct deu_alg_template *deu_algs[] = {
//#if IS_ENABLED(CONFIG_CRYPTO_DEV_DEU_DES)
//	&deu_alg_ecb_des,
//	&deu_alg_cbc_des,
//	&deu_alg_ecb_des3_ede,
//	&deu_alg_cbc_des3_ede,
//#endif
#if IS_ENABLED(CONFIG_CRYPTO_DEV_DEU_AES)
	&deu_alg_ecb_aes,
	&deu_alg_cbc_aes,
	&deu_alg_ofb_aes,
	&deu_alg_cfb_aes,
	&deu_alg_ctr_aes,
	&deu_alg_rfc3686_aes,
	&deu_alg_xts_aes,
#endif
#if IS_ENABLED(CONFIG_CRYPTO_DEV_DEU_HASH)
	&deu_alg_sha1,
//	&deu_alg_md5,
//	&deu_alg_hmac_md5,
//	&deu_alg_sha1,
//	&deu_alg_hmac_sha1,
#endif
};

static void deu_unregister_algs(unsigned int i)
{
	unsigned int j;

	for (j = 0; j < i; j++) {
		switch (deu_algs[j]->type) {
		case DEU_ALG_TYPE_SKCIPHER:
			crypto_unregister_skcipher(&deu_algs[j]->alg.skcipher);
			break;
		case DEU_ALG_TYPE_AHASH:
			crypto_unregister_ahash(&deu_algs[j]->alg.ahash);
			break;
		case DEU_ALG_TYPE_SHASH:
			crypto_unregister_shash(&deu_algs[j]->alg.shash);
		}
	}
}

static int deu_register_algs(void)
{
	int err = 0;
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(deu_algs); i++) {
		switch (deu_algs[i]->type) {
		case DEU_ALG_TYPE_SKCIPHER:
			err = crypto_register_skcipher(&deu_algs[i]->alg.skcipher);
			break;
		case DEU_ALG_TYPE_AHASH:
			err = crypto_register_ahash(&deu_algs[i]->alg.ahash);
			break;
		case DEU_ALG_TYPE_SHASH:
			err = crypto_register_shash(&deu_algs[i]->alg.shash);
			break;
		}
		if (err)
			goto fail;
	}

	return 0;

fail:
	deu_unregister_algs(i);

	return err;
}

static void ltq_deu_start(__iomem void *base)
{
	union clk_control clk;

	ltq_clk_membase = base;

	ltq_pmu_enable(PMU_DEU);

	clk.word = ltq_r32(ltq_clk_membase);
	clk.bits.FSOE = 0;
	clk.bits.SBWE = 0;
	clk.bits.SPEN = 0;
	clk.bits.SBWE = 0;
	clk.bits.DISS = 0;
	clk.bits.DISR = 0;
	ltq_w32(clk.word, ltq_clk_membase);

#if IS_ENABLED(CONFIG_CRYPTO_DEV_DEU_AES)
	aes_init_hw(base);
#endif

}

static void ltq_deu_stop(void)
{
	union clk_control clk;

	ltq_pmu_disable(PMU_DEU);

	clk.word = ltq_r32(ltq_clk_membase);
	clk.bits.FSOE = 1;
	clk.bits.SBWE = 1;
	clk.bits.SPEN = 1;
	clk.bits.SBWE = 1;
	clk.bits.DISS = 1;
	clk.bits.DISR = 1;
	ltq_w32(clk.word, ltq_clk_membase);
}

static int ltq_deu_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct resource *res;
	__iomem void *base;
	int err;

	platform_set_drvdata(pdev, dev);

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!res) {
		dev_err(&pdev->dev, "failed to get etop resource\n");
		return -ENOENT;
	}

	res = devm_request_mem_region(&pdev->dev, res->start,
		resource_size(res), dev_name(&pdev->dev));
	if (!res) {
		dev_err(&pdev->dev, "failed to request etop resource\n");
		return -EBUSY;
	}

	base = devm_ioremap(&pdev->dev, res->start, resource_size(res));

	if (!base) {
		dev_err(&pdev->dev, "failed to remap deu engine %d\n",
			pdev->id);
		return -ENOMEM;
	}
	ltq_deu_start(base);

	err = deu_register_algs();
	if (err)
		return err;

	dev_info(&pdev->dev, "Data Encryption Unit initialized.\n");

	return 0;
}

static int ltq_deu_remove(struct platform_device *pdev)
{
	deu_unregister_algs(ARRAY_SIZE(deu_algs));

	ltq_deu_stop();

	dev_info(&pdev->dev, "Date Encryption Unit removed.\n");

	return 0;
}

#if defined(CONFIG_OF)
static const struct of_device_id ltq_deu_match[] = {
	{ .compatible = "lantiq,deu-danube"},
	{ .compatible = "lantiq,deu-arx100"},
	{ .compatible = "lantiq,deu-xrx200"},
	{}
};
MODULE_DEVICE_TABLE(of, ltq_deu_match);
#endif

static struct platform_driver ltq_deu_driver = {
	.probe = ltq_deu_probe,
	.remove = ltq_deu_remove,
	.driver = {
		.name = "deu",
		.of_match_table = ltq_deu_match,
	},
};
module_platform_driver(ltq_deu_driver);

MODULE_AUTHOR("Richard van Schagen <vschagen@icloud.com>");
MODULE_ALIAS("platform:" KBUILD_MODNAME);
MODULE_DESCRIPTION("Infineon DEU crypto engine driver");
MODULE_LICENSE("GPL v2");
