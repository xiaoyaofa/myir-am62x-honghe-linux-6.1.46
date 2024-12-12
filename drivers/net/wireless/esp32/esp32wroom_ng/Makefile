# SPDX-License-Identifier: GPL-2.0
#Default interface is sdio
MODULE_NAME=esp32
module_objects += esp_bt.o main.o esp_cmd.o esp_utils.o esp_cfg80211.o esp_stats.o esp_debugfs.o esp_log.o
ifneq ($(CONFIG_WLAN_ESP32_WROOM_SDIO),)
	MODULE_NAME=esp32_sdio
	module_objects += esp_sdio.o esp_sdio_api.o
endif

ifneq ($(CONFIG_WLAN_ESP32_WROOM_SPI),)
	MODULE_NAME=esp32_spi
	module_objects += esp_spi.o
endif
CFLAGS_esp_log.o = -DDEBUG
obj-$(CONFIG_WLAN_ESP32_WROOM) += $(MODULE_NAME).o
$(MODULE_NAME)-y := $(module_objects)

