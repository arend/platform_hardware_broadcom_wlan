
include $(CLEAR_VARS)

LOCAL_MODULE := brcmfmac
LOCAL_PATH := hardware/broadcom/wlan/brcmfmac/driver
LOCAL_KERNEL_COMPAT_DEFCONFIG := brcmfmac
COMPAT_KERNEL_MODULES += ${LOCAL_PATH}

define COMPAT_PRIVATE_$(LOCAL_MODULE)_PREINSTALL
	find $(1) -name *80211.ko -exec rm {} \;
endef

define COMPAT_PRIVATE_$(LOCAL_MODULE)_POSTINSTALL
	find $(1) -path \*updates\*\.ko -type f -print
endef

include $(BUILD_COMPAT_MODULE)

