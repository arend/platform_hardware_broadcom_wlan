
LOCAL_PATH := hardware/broadcom/wlan/brcmfmac/firmware

FIRMWARE_COPY_FILES := $(foreach f, \
			$(notdir \
			$(wildcard $(LOCAL_PATH)/*.bin $(LOCAL_PATH)/*.txt)), \
			$(LOCAL_PATH)/$(f):system/etc/firmware/brcm/$(f))

PRODUCT_COPY_FILES += $(FIRMWARE_COPY_FILES)
