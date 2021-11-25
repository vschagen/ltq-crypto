#
# Copyright (C) 2006-2019 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#


include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=ltq-crypto
PKG_RELEASE:=0.1

include $(INCLUDE_DIR)/kernel.mk
include $(INCLUDE_DIR)/package.mk

define KernelPackage/ltq-crypto
	SECTION:=kernel
	CATEGORY:=Kernel modules
	SUBMENU:=Cryptographic API modules
	DEPENDS:=
	KCONFIG:=
	TITLE:=Lantiq Data Encryptio Unit module
	FILES:=$(PKG_BUILD_DIR)/ltq-crypto.ko
#	AUTOLOAD:=$(call AutoProbe,ltq-crypto)
	MENU:=1
endef

define KernelPackage/ltq-crypto/config
if PACKAGE_kmod-ltq-crypto

comment "Build Options"

config CRYPTO_DEV_IFXDEU
	tristate

config CRYPTO_DEV_DEU_AES
	bool "Register AES algorithm implementatons with the Crypto API"
	default y
	select CRYPTO_DEV_IFXDEU
	help
	  Selecting this will offload AES - ECB, CBC, OFB, CFB, CTR
	  and XTS crypto modes to the Data Encryption Unit.

config CRYPTO_DEV_DEU_DES
	bool "Register DES algorithm implementatons with the Crypto API"
	default n
	select CRYPTO_DEV_IFXDEU
	help
	  Selecting this will offload DES / 3DES - ECB and CBC crypto
	  to the Data Encryption Unit.

config CRYPTO_DEV_DEU_HASH
	bool "Register HASH algorithm implementatons with the Crypto API"
	default n
	select CRYPTO_DEV_IFXDEU
	help
	  Selecting this will offload MD5 and SHA1 hash algorithm
	  and HMAC(MD5) and HMAC(SHA1) to the Data Encryption Unit.
endif
endef

EXTRA_KCONFIG:=

ifdef CONFIG_CRYPTO_DEV_IFXDEU
	EXTRA_KCONFIG += CONFIG_CRYPTO_DEV_IFXDEU=y
endif

ifdef CONFIG_CRYPTO_DEV_DEU_AES
	EXTRA_KCONFIG += CONFIG_CRYPTO_DEV_DEU_AES=y
endif

ifdef CONFIG_CRYPTO_DEV_DEU_DES
	EXTRA_KCONFIG += CONFIG_CRYPTO_DEV_DEU_DES=y
endif

ifdef CONFIG_CRYPTO_DEV_DEU_HASH
	EXTRA_KCONFIG += CONFIG_CRYPTO_DEV_DEU_HASH=y
endif

EXTRA_CFLAGS:= \
	$(patsubst CONFIG_%, -DCONFIG_%=1, $(patsubst %=m,%,$(filter %=m,$(EXTRA_KCONFIG)))) \
	$(patsubst CONFIG_%, -DCONFIG_%=1, $(patsubst %=y,%,$(filter %=y,$(EXTRA_KCONFIG))))

MAKE_OPTS:= \
	$(KERNEL_MAKE_FLAGS) \
	M="$(PKG_BUILD_DIR)" \
	EXTRA_CFLAGS="$(EXTRA_CFLAGS)" \
	$(EXTRA_KCONFIG)

define Build/Compile
	$(MAKE) -C "$(LINUX_DIR)" \
		$(MAKE_OPTS) \
		modules
endef

$(eval $(call KernelPackage,ltq-crypto))
