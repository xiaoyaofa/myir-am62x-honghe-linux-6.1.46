# SPDX-License-Identifier: GPL-2.0
#Default interface is sdio
MODULE_NAME=esp32
module_objects += esp_bt.o esp_rb.o esp_serial.o esp_stats.o main.o esp_fw_verify.o
ifneq ($(CONFIG_WLAN_ESP32_WROOM_SDIO),)
	MODULE_NAME=esp32_sdio
	module_objects += esp_sdio.o esp_sdio_api.o
endif

ifneq ($(CONFIG_WLAN_ESP32_WROOM_SPI),)
	MODULE_NAME=esp32_spi
	module_objects += esp_spi.o
endif
obj-$(CONFIG_WLAN_ESP32_WROOM) += $(MODULE_NAME).o
$(MODULE_NAME)-y := $(module_objects)