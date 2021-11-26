# SPDX-License-Identifier: GPL-2.0-only
obj-m := ltq-crypto.o

ltq-crypto-$(CONFIG_CRYPTO_DEV_IFXDEU) += deu-core.o

ltq-crypto-$(CONFIG_CRYPTO_DEV_DEU_AES) += deu-aes.o
ltq-crypto-$(CONFIG_CRYPTO_DEV_DEU_DES) += deu-des.o
#ltq-crypto-$(CONFIG_CRYPTO_DEV_DEU_HASH) += deu-hash.o
