/* SPDX-License-Identifier: GPL-2.0 */
/*
 * This file is part of ILITEK CommonFlow
 *
 * Copyright (c) 2022 ILI Technology Corp.
 * Copyright (c) 2022 Luca Hsu <luca_hsu@ilitek.com>
 * Copyright (c) 2022 Joe Hung <joe_hung@ilitek.com>
 */

#ifndef __ILITEK_PROTOCOL_H__
#define __ILITEK_PROTOCOL_H__

#include "ilitek_def.h"

/* quirks definition */
#define QUIRK_WAIT_ACK_DELAY		0x1
#define QUIRK_BRIDGE			0x2
#define QUIRK_DAEMON_I2C		0x4
#define QUIRK_WIFI_ITS_I2C		0x8
#define QUIRK_LIBUSB			0x10

#define START_ADDR_LEGO			0x3000
#define START_ADDR_29XX			0x4000
#define END_ADDR_LEGO			0x40000

#define MM_ADDR_LEGO			0x3020
#define MM_ADDR_29XX			0x4020
#define MM_ADDR_2501X			0x4038

#define DF_START_ADDR_LEGO		0x3C000
#define DF_START_ADDR_29XX		0x2C000

#define ILITEK_TP_SYSTEM_READY		0x50

#define CRC_CALCULATE			0
#define CRC_GET				1

#define ILTIEK_MAX_BLOCK_NUM		20

#define PTL_ANY				0x00
#define PTL_V3				0x03
#define PTL_V6				0x06

#define BL_PROTOCOL_V1_8		0x10800
#define BL_PROTOCOL_V1_7		0x10700
#define BL_PROTOCOL_V1_6		0x10600

#define TOUT_CF_BLOCK_0			2500
#define TOUT_CF_BLOCK_N			500
#define TOUT_F1_SHORT			1600
#define TOUT_F1_OPEN			12
#define TOUT_F1_FREQ_MC			2
#define TOUT_F1_FREQ_SC			1
#define TOUT_F1_CURVE			13
#define TOUT_F1_KEY			400
#define TOUT_F1_OTHER			27
#define TOUT_F2				7
#define TOUT_CD				27
#define TOUT_C3				100
#define TOUT_65_WRITE			135
#define TOUT_65_READ			3
#define TOUT_68				24
#define TOUT_CC_SLAVE			16000

#define TOUT_F1_SHORT_RATIO		2
#define TOUT_F1_OPEN_RATIO		3
#define TOUT_F1_FREQ_RATIO		3
#define TOUT_F1_CURVE_RATIO		3
#define TOUT_F1_OTHER_RATIO		3
#define TOUT_F2_RATIO			3
#define TOUT_CD_RATIO			3
#define TOUT_C3_RATIO			3
#define TOUT_65_WRITE_RATIO		3
#define TOUT_65_READ_RATIO		3
#define TOUT_68_RATIO			3
#define TOUT_CC_SLAVE_RATIO		2

#define AP_MODE		0x5A
#define BL_MODE		0x55

#define STYLUS_MODES			\
	X(STYLUS_WGP,	0x1,	"WGP")	\
	X(STYLUS_USI,	0x2,	"USI")	\
	X(STYLUS_MPP,	0x4,	"MPP")

#define ILITEK_CMD_MAP							\
	X(0x20, PTL_ANY, GET_TP_INFO, api_protocol_get_tp_info)		\
	X(0x21, PTL_ANY, GET_SCRN_RES, api_protocol_get_scrn_res)	\
	X(0x22, PTL_ANY, GET_KEY_INFO, api_protocol_get_key_info)	\
	X(0x30, PTL_ANY, SET_IC_SLEEP, api_protocol_set_sleep)		\
	X(0x31, PTL_ANY, SET_IC_WAKE, api_protocol_set_wakeup)		\
	X(0x34, PTL_ANY, SET_MCU_IDLE, api_protocol_set_idle)		\
	X(0x40, PTL_ANY, GET_FW_VER, api_protocol_get_fw_ver)		\
	X(0x42, PTL_ANY, GET_PTL_VER, api_protocol_get_ptl_ver)		\
	X(0x43, PTL_ANY, GET_CORE_VER, api_protocol_get_core_ver)	\
	X(0x60, PTL_ANY, SET_SW_RST, api_protocol_set_sw_reset)		\
	X(0x61, PTL_ANY, GET_MCU_VER, api_protocol_get_mcu_ver)		\
	X(0x68, PTL_ANY, SET_FUNC_MOD, api_protocol_set_func_mode)	\
	X(0x80, PTL_ANY, GET_SYS_BUSY, api_protocol_get_sys_busy)	\
	X(0xC0, PTL_ANY, GET_MCU_MOD, api_protocol_get_mcu_mode)	\
	X(0xC1, PTL_ANY, SET_AP_MODE, api_protocol_set_ap_mode)		\
	X(0xC2, PTL_ANY, SET_BL_MODE, api_protocol_set_bl_mode)		\
	X(0xC5, PTL_ANY, READ_FLASH, api_protocol_read_flash)		\
	X(0xC7, PTL_ANY, GET_AP_CRC, api_protocol_get_ap_crc)		\
	X(0xC8, PTL_ANY, SET_ADDR, api_protocol_set_flash_addr)		\
									\
	/* v3 only cmds */						\
	X(0x25, PTL_V3, GET_CDC_INFO_V3, api_protocol_get_cdc_info_v3)	\
	X(0x63, PTL_V3, TUNING_PARA_V3, api_protocol_tuning_para_v3)	\
	X(0xC3, PTL_V3, WRITE_DATA_V3, api_protocol_write_data_v3)	\
	X(0xC4, PTL_V3, WRITE_ENABLE, api_protocol_write_enable)	\
	X(0xCA, PTL_V3, GET_DF_CRC, api_protocol_get_df_crc)		\
	X(0xF2, PTL_V3, SET_TEST_MOD, api_protocol_set_mode_v3)		\
	X(0xF3, PTL_V3, INIT_CDC_V3, api_protocol_set_cdc_init_v3)	\
									\
	/* v6 only cmds */						\
	X(0x24, PTL_V6, POWER_STATUS, api_protocol_power_status)	\
	X(0x27, PTL_V6, GET_SENSOR_ID, api_protocol_get_sensor_id)	\
	X(0x44, PTL_V6, GET_TUNING_VER, api_protocol_get_tuning_ver)	\
	X(0x45, PTL_V6, GET_PRODUCT_INFO, api_protocol_get_product_info)\
	X(0x46, PTL_V6, GET_FWID, api_protocol_get_fwid)		\
	X(0x47, PTL_V6, GET_CRYPTO_INFO, api_protocol_get_crypto_info)	\
	X(0x48, PTL_V6, GET_HID_INFO, api_protocol_get_hid_info)	\
	X(0x62, PTL_V6, GET_MCU_INFO, api_protocol_get_mcu_info)	\
	X(0x65, PTL_V6, TUNING_PARA_V6, api_protocol_tuning_para_v6)	\
	X(0x69, PTL_V6, SET_FS_INFO, api_protocol_set_fs_info)		\
	X(0x6A, PTL_V6, SET_SHORT_INFO, api_protocol_set_short_info)	\
	X(0x6B, PTL_V6, C_MODEL_INFO, api_protocol_c_model_info)	\
	X(0x6C, PTL_V6, SET_P2P_INFO, api_protocol_set_p2p_info)	\
	X(0x6D, PTL_V6, SET_OPEN_INFO, api_protocol_set_open_info)	\
	X(0x6E, PTL_V6, SET_CHARGE_INFO, api_protocol_set_charge_info)	\
	X(0x6F, PTL_V6, SET_PEN_FS_INFO, api_protocol_set_pen_fs_info)	\
	X(0xB0, PTL_V6, WRITE_DATA_M2V, api_protocol_write_data_m2v)	\
	X(0xC3, PTL_V6, WRITE_DATA_V6, api_protocol_write_data_v6)	\
	X(0xC9, PTL_V6, SET_DATA_LEN, api_protocol_set_data_len)	\
	X(0xCB, PTL_V6, ACCESS_SLAVE, api_protocol_access_slave)	\
	X(0xCC, PTL_V6, SET_FLASH_EN, api_protocol_set_flash_enable)	\
	X(0xCD, PTL_V6, GET_BLK_CRC_ADDR, api_protocol_get_crc_by_addr)	\
	X(0xCF, PTL_V6, GET_BLK_CRC_NUM, api_protocol_get_crc_by_num)	\
	X(0xF0, PTL_V6, SET_MOD_CTRL, api_protocol_set_mode_v6)		\
	X(0xF1, PTL_V6, INIT_CDC_V6, api_protocol_set_cdc_init_v6)	\
	X(0xF2, PTL_V6, GET_CDC_V6, api_protocol_get_cdc_v6)


#define X(_cmd, _protocol, _cmd_id, _api)	_cmd_id,
enum ilitek_cmd_ids {
	ILITEK_CMD_MAP
	/* ALWAYS keep at the end */
	MAX_CMD_CNT
};
#undef X

#define X(_cmd, _protocol, _cmd_id, _api)	CMD_##_cmd_id = _cmd,
enum ilitek_cmds { ILITEK_CMD_MAP };
#undef X

enum ilitek_hw_interfaces {
	interface_i2c = 0,
	interface_hid_over_i2c,
	interface_usb,
};

enum ilitek_fw_modes {
	mode_unknown = -1,
	mode_normal = 0,
	mode_test,
	mode_debug,
	mode_suspend,
};

enum ilitek_key_modes {
	key_disable = 0,
	key_hw = 1,
	key_hsw = 2,
	key_vitual = 3,
	key_fw_disable = 0xff,
};

#define ILITEK_TOUCH_REPORT_FORMAT 		\
	X(touch_fmt_0x0,	0x0, 5, 10)	\
	X(touch_fmt_0x1,	0x1, 6, 10)	\
	X(touch_fmt_0x2,	0x2, 10, 5)	\
	X(touch_fmt_0x3,	0x3, 10, 5)	\
	X(touch_fmt_0x4,	0x4, 10, 5)	\
	X(touch_fmt_0x10,	0x10, 10, 6)	\
	X(touch_fmt_0x11,	0x11, 5, 10)

#define X(_enum, _id, _size, _cnt)	_enum = _id,
enum ilitek_touch_fmts {
	ILITEK_TOUCH_REPORT_FORMAT
	touch_fmt_max = 0x100,
};
#undef X

#define ILITEK_PEN_REPORT_FORMAT 	\
	X(pen_fmt_0x0, 0x0, 12, 1)	\
	X(pen_fmt_0x1, 0x1, 18, 1)	\
	X(pen_fmt_0x2, 0x2, 22, 1)

#define X(_enum, _id, _size, _cnt)	_enum = _id,
enum ilitek_pen_fmts {
	ILITEK_PEN_REPORT_FORMAT
	pen_fmt_max = 0x100,
};
#undef X

struct ilitek_slave_access {
	uint8_t slave_id;
	uint8_t func;
	void *data;
};

struct tuning_para_settings {
	uint8_t func;
	uint8_t ctrl;
	uint8_t type;

	uint8_t *buf;
	uint32_t len;
};

struct reports {
	bool touch_need_update;
	bool pen_need_update;

	uint8_t touch[64];
	uint8_t pen[64];
};

struct grid_data {
	bool need_update;
	unsigned int X, Y;

	int32_t *data;
};

struct grids {
	struct grid_data mc;
	struct grid_data sc_x;
	struct grid_data sc_y;
	struct grid_data pen_x;
	struct grid_data pen_y;

	struct grid_data key_mc;
	struct grid_data key_x;
	struct grid_data key_y;

	struct grid_data self;

	/* touch/pen debug message along with frame update */
	struct reports dmsg;
};

enum ilitek_enum_type {
	enum_ap_bl = 0,
	enum_sw_reset,
};

typedef void (*update_grid_t)(uint32_t, uint32_t, struct grids *, void *);
typedef void (*update_report_rate_t)(unsigned int);

typedef int (*write_then_read_t)(uint8_t *, int, uint8_t *, int, void *);
typedef int (*read_ctrl_in_t)(uint8_t *, int, unsigned int, void *);
typedef int (*read_interrupt_in_t)(uint8_t *, int, unsigned int, void *);
typedef void (*init_ack_t)(unsigned int, void *);
typedef int (*wait_ack_t)(uint8_t, unsigned int, void *);
typedef int (*hw_reset_t)(unsigned int, void *);
typedef int (*re_enum_t)(uint8_t, void *);
typedef void (*delay_ms_t)(unsigned int);


typedef int (*write_then_read_direct_t)(uint8_t *, int, uint8_t *, int, void *);
typedef void (*mode_switch_notify_t)(bool, bool, void *);

#ifdef _WIN32
/* packed below structures by 1 byte */
#pragma pack(1)
#endif

struct __PACKED__ touch_fmt {
	uint8_t id : 6;
	uint8_t status : 1;
	uint8_t reserve : 1;
	uint16_t x;
	uint16_t y;
	uint8_t pressure;
	uint16_t width;
	uint16_t height;

	uint8_t algo;
};

struct __PACKED__ touch_iwb_fmt {
	uint8_t status : 3;
	uint8_t reserve : 5;
	uint8_t id : 6;
	uint8_t reserve_1 : 2;
	uint16_t x;
	uint16_t y;
	uint16_t width;
	uint16_t height;

	uint8_t algo;
};

struct __PACKED__ pen_fmt {
	union __PACKED__ {
		uint8_t modes;
		struct __PACKED__ {
			uint8_t tip_sw : 1;
			uint8_t barrel_sw : 1;
			uint8_t eraser : 1;
			uint8_t invert : 1;
			uint8_t in_range : 1;
			uint8_t reserve : 3;
		};
	};
	uint16_t x;
	uint16_t y;
	uint16_t pressure;
	int16_t x_tilt;
	int16_t y_tilt;

	uint8_t battery;

	union __PACKED__ {
		/* usi v1.0 */
		struct __PACKED__ {
			uint16_t barrel_pressure;
			uint8_t idx;
			uint8_t color;
			uint8_t width;
			uint8_t style;
		} usi_1;

		/* usi v2.0 */
		struct __PACKED__ {
			uint16_t barrel_pressure;
			uint8_t idx;
			uint8_t color;
			uint8_t color_24[3];
			uint8_t no_color;
			uint8_t width;
			uint8_t style;
		} usi_2;
	};
};

struct __PACKED__ ilitek_report_fmt_info {
	uint32_t touch_size;
	uint32_t touch_max_cnt;

	uint32_t pen_size;
	uint32_t pen_max_cnt;
};

struct __PACKED__ ilitek_screen_info {
	uint16_t x_min;
	uint16_t y_min;
	uint16_t x_max;
	uint16_t y_max;
	uint16_t pressure_min;
	uint16_t pressure_max;
	int16_t x_tilt_min;
	int16_t x_tilt_max;
	int16_t y_tilt_min;
	int16_t y_tilt_max;
	uint16_t pen_x_min;
	uint16_t pen_y_min;
	uint16_t pen_x_max;
	uint16_t pen_y_max;
};

struct __PACKED__ ilitek_tp_info_v6 {
	uint16_t x_resolution;
	uint16_t y_resolution;
	uint16_t x_ch;
	uint16_t y_ch;
	uint8_t max_fingers;
	uint8_t key_num;
	uint8_t ic_num;
	uint8_t support_modes;
	uint8_t format;
	uint8_t die_num;
	uint8_t block_num;
	uint8_t pen_modes;
	uint8_t pen_format;
	uint16_t pen_x_resolution;
	uint16_t pen_y_resolution;
};

struct __PACKED__ ilitek_tp_info_v3 {
	uint16_t x_resolution;
	uint16_t y_resolution;
	uint8_t x_ch;
	uint8_t y_ch;
	uint8_t max_fingers;
	uint8_t reserve;
	uint8_t key_num;
	uint8_t reserve_1;
	uint8_t touch_start_y;
	uint8_t touch_end_y;
	uint8_t touch_start_x;
	uint8_t touch_end_x;
	uint8_t support_modes;
};

struct __PACKED__ ilitek_key_info_v6 {
	uint8_t mode;
	uint16_t x_len;
	uint16_t y_len;

	struct __PACKED__ _ilitek_key_info_v6 {
		uint8_t id;
		uint16_t x;
		uint16_t y;
	} keys[50];
};

struct __PACKED__ ilitek_key_info_v3 {
	uint8_t x_len[2];
	uint8_t y_len[2];

	struct __PACKED__ _ilitek_key_info_v3 {
		uint8_t id;
		uint8_t x[2];
		uint8_t y[2];
	} keys[20];
};

struct __PACKED__ ilitek_ts_kernel_info {
	char ic_name[6];
	char mask_ver[2];
	uint32_t mm_addr;
	uint32_t min_addr;
	uint32_t max_addr;
	char module_name[32];

	char ic_full_name[16];
};

struct __PACKED__ ilitek_key_info {
	struct ilitek_key_info_v6 info;
	bool clicked[50];
};

struct __PACKED__ ilitek_power_status {
	uint16_t header;
	uint8_t vdd33_lvd_flag;
	uint8_t vdd33_lvd_level_sel;
};

struct __PACKED__ ilitek_sensor_id {
	uint16_t header;
	uint8_t id;
};

struct __PACKED__ ilitek_func_mode {
	uint16_t header;
	uint8_t mode;
};

struct __PACKED__ ilitek_ts_protocol {
	uint32_t ver;
	uint8_t flag;
};

struct __PACKED__ ilitek_ts_ic {
	uint8_t mode;
	uint32_t crc[ILTIEK_MAX_BLOCK_NUM];

	char mode_str[32];
};

struct __PACKED__ ilitek_hid_info {
	uint16_t pid;
	uint16_t vid;
	uint16_t rev;
};

struct __PACKED__ freq_category {
	uint32_t start;
	uint32_t end;
	uint32_t step;
	uint32_t steps;

	uint32_t size;
	char limit[1024];

	uint8_t mode;

	int32_t *data;
};

struct __PACKED__ freq_settings {
	bool prepared;

	unsigned int frame_cnt;

	/* add from v6.0.A */
	unsigned int mc_frame_cnt;
	unsigned int dump_frame_cnt;

	unsigned int scan_type;

	struct freq_category sine;
	struct freq_category mc_swcap;
	struct freq_category sc_swcap;
	struct freq_category pen;

	struct freq_category dump1;
	struct freq_category dump2;
	uint8_t dump1_val;
	uint8_t dump2_val;

	uint16_t packet_steps;
};

struct __PACKED__ short_settings {
	bool prepared;

	uint8_t dump_1;
	uint8_t dump_2;
	uint8_t v_ref_L;
	uint16_t post_idle;
};

struct __PACKED__ open_settings {
	bool prepared;

	uint16_t freq;
	uint8_t gain;
	uint8_t gain_rfb;
	uint8_t afe_res_sel;
	uint8_t mc_fsel;
	uint16_t frame;
};

struct __PACKED__ p2p_settings {
	bool prepared;

	uint16_t frame_cnt;
	uint8_t type;

	/* add from v6.0.A */
	uint16_t freq;
};

struct __PACKED__ charge_curve_sweep {
	uint16_t start;
	uint16_t end;
	uint8_t step;
	uint16_t post_idle;
	uint16_t fix_val;

	uint16_t steps;
};

struct __PACKED__ charge_curve_settings {
	bool prepared;

	uint8_t scan_mode;

	struct charge_curve_sweep dump;
	struct charge_curve_sweep charge;

	uint16_t c_sub;
	uint16_t frame_cnt;

	struct __PACKED__ charge_curve_point {
		uint16_t x;
		uint16_t y;
		uint16_t *dump_max;
		uint16_t *dump_avg;
		uint16_t *charge_max;
		uint16_t *charge_avg;
	} pt[9];

	uint16_t packet_steps;
};

struct __PACKED__ cdc_settings {
	uint8_t cmd;
	uint16_t config;

	bool skip_checksum;

	/* freq. */
	struct freq_settings freq;
	/* short */
	struct short_settings _short;
	/* open */
	struct open_settings open;
	/* p2p */
	struct p2p_settings p2p;
	/* charge curve */
	struct charge_curve_settings curve;

	/* status only writable by CDC commonflow */
	bool is_key;
	bool is_p2p;
	bool is_freq;
	bool is_curve;
	bool is_short;
	bool is_open;
	bool is_16bit;
	bool is_sign;
	bool is_fast_mode;
	unsigned int total_bytes;

	/* error code during cdc data collection */
	int32_t error;
};

struct __PACKED__ mp_station_old {
	struct __PACKED__ {
		uint8_t week;
		uint8_t year;
		uint8_t fw_ver[8];
		char module[19];

		uint8_t short_test:2;
		uint8_t open_test:2;
		uint8_t self_test:2;
		uint8_t uniform_test:2;

		uint8_t dac_test:2;
		uint8_t key_test:2;
		uint8_t final_result:2;
		uint8_t paint_test:2;

		uint8_t mopen_test:2;
		uint8_t gpio_test:2;
		uint8_t reserve_1:4;

		char bar_code[28];
		uint8_t reserve_2[35];

		uint16_t custom_id;
		uint16_t fwid;
		uint8_t idx;
	} station[10];
};

struct __PACKED__ mp_station {
	struct __PACKED__ {
		uint8_t week;
		uint8_t year;
		uint8_t fw_ver[8];
		char module[19];

		uint8_t short_test : 2;
		uint8_t open_test : 2;
		uint8_t self_test : 2;
		uint8_t uniform_test : 2;

		uint8_t dac_test : 2;
		uint8_t key_test : 2;
		uint8_t final_result : 2;
		uint8_t paint_test : 2;

		uint8_t mopen_test : 2;
		uint8_t gpio_test : 2;
		uint8_t reserve : 4;

		uint8_t tool_ver[8];
		char bar_code[135];

		uint16_t custom_id;
		uint16_t fwid;
		uint8_t idx;
	} station[5];

	struct __PACKED__ {
		uint8_t reserve_1[91];
		uint32_t mp_result_ver;
		uint16_t customer_id;
		uint16_t fwid;
		uint8_t reserve_2;
	} info;

	uint16_t crc;
};

struct __PACKED__ ilitek_ts_settings {
	bool no_retry;
	bool no_INT_ack;

	bool sw_reset_at_last;

	uint8_t sensor_id_mask;

	/* only used for QUIRK_WAIT_ACK_DELAY */
	uint32_t wait_ack_delay;

	/*
	 * engineer mode would likely report default format
	 * ex. IWB-format
	 */
	bool default_format_enabled;
};

struct __PACKED__ ilitek_sys_info {
	uint16_t pid;
};

struct __PACKED__ ilitek_ts_callback {
	/* Please don't use "repeated start" for I2C interface */
	write_then_read_t write_then_read;
	read_ctrl_in_t read_ctrl_in;
	read_interrupt_in_t read_interrupt_in;
	init_ack_t init_ack;
	wait_ack_t wait_ack;
	hw_reset_t hw_reset;
	re_enum_t re_enum;
	delay_ms_t delay_ms;
	msg_t msg;

	/* write cmd without adding any hid header */
	write_then_read_direct_t write_then_read_direct;
	/* notify caller after AP/BL mode switch command */
	mode_switch_notify_t mode_switch_notify;
};

struct __PACKED__ ilitek_common_info {
	uint32_t quirks;
	uint8_t _interface;

	uint16_t customer_id;
	uint16_t fwid;

	char pen_mode[64];
	uint8_t fw_ver[8];
	uint8_t core_ver[8];
	uint8_t tuning_ver[4];
	uint8_t product_info[8];

	struct ilitek_sys_info sys;
	struct ilitek_ts_protocol protocol;
	struct ilitek_func_mode func;
	struct ilitek_sensor_id sensor;
	struct ilitek_ts_ic ic[32];
	struct ilitek_screen_info screen;
	struct ilitek_tp_info_v6 tp;
	struct ilitek_key_info key;
	struct ilitek_ts_kernel_info mcu;
	struct ilitek_hid_info hid;
	struct ilitek_report_fmt_info fmt;
	struct ilitek_power_status pwr;
};

struct __PACKED__ ilitek_ts_device {
	void *_private;
	char id[64];
	uint32_t reset_time;

	struct ilitek_ts_settings setting;

	uint32_t quirks;
	uint8_t _interface;

	uint16_t customer_id;
	uint16_t fwid;

	char pen_mode[64];
	uint8_t fw_ver[8];
	uint8_t core_ver[8];
	uint8_t tuning_ver[4];
	uint8_t product_info[8];

	struct ilitek_sys_info sys;
	struct ilitek_ts_protocol protocol;
	struct ilitek_func_mode func;
	struct ilitek_sensor_id sensor;
	struct ilitek_ts_ic ic[32];
	struct ilitek_screen_info screen_info;
	struct ilitek_tp_info_v6 tp_info;
	struct ilitek_key_info key;
	struct ilitek_ts_kernel_info mcu_info;
	struct ilitek_hid_info hid_info;
	struct ilitek_report_fmt_info fmt;
	struct ilitek_power_status pwr;

	uint8_t fw_mode;
	struct mp_station mp;

	uint8_t wbuf[4096];
	uint8_t rbuf[4096];
	struct ilitek_ts_callback cb;
};

#ifdef _WIN32
#pragma pack()
#endif

#ifdef __cplusplus
extern "C" {
#endif

uint16_t __DLL le16(const uint8_t *p);
uint16_t __DLL be16(const uint8_t *p);
uint32_t __DLL le32(const uint8_t *p, int bytes);
uint32_t __DLL be32(const uint8_t *p, int bytes);

bool __DLL is_29xx(void *handle);

bool __DLL _is_231x(char *ic_name);
bool __DLL is_231x(void *handle);

bool __DLL has_hw_key(void *handle);

uint8_t __DLL get_protocol_ver_flag(uint32_t ver);

int __DLL grid_alloc(void *handle, struct grids *grid);
void __DLL grid_free(struct grids *grid);
void __DLL grid_reset(struct grids *grid);

uint16_t __DLL get_crc(uint32_t start, uint32_t end,
		       uint8_t *buf, uint32_t buf_size);

uint32_t __DLL  get_checksum(uint32_t start, uint32_t end,
			     uint8_t *buf, uint32_t buf_size);

bool __DLL is_checksum_matched(uint8_t checksum, int start, int end,
			       uint8_t *buf, int buf_size);

bool __DLL support_sensor_id(void *handle);
bool __DLL support_production_info(void *handle);
bool __DLL support_fwid(void *handle);

int __DLL bridge_set_int_monitor(void *handle, bool enable);
int __DLL bridge_set_test_mode(void *handle, bool enable);

int __DLL reset_helper(void *handle);

int __DLL write_then_read(void *handle, uint8_t *cmd, int wlen,
			  uint8_t *buf, int rlen);
int __DLL write_then_read_direct(void *handle, uint8_t *cmd, int wlen,
				 uint8_t *buf, int rlen);
int __DLL read_interrupt_in(void *handle, uint8_t *buf, int rlen,
			    unsigned int timeout_ms);
int __DLL read_ctrl_in(void *handle, uint8_t cmd, uint8_t *buf, int rlen,
		       unsigned int timeout_ms);

void __DLL __ilitek_get_info(void *handle,
			     struct ilitek_common_info *info);

void __DLL ilitek_dev_set_quirks(void *handle, uint32_t quirks);
void __DLL ilitek_dev_set_sys_info(void *handle, struct ilitek_sys_info *sys);
void __DLL ilitek_dev_setting(void *handle,
			      struct ilitek_ts_settings *setting);

void __DLL ilitek_dev_bind_callback(void *handle,
				    struct ilitek_ts_callback *callback);

void __DLL *ilitek_dev_init(uint8_t _interface, const char *id,
			    bool need_update_ts_info,
			    struct ilitek_ts_callback *callback,
			    void *_private);
void __DLL ilitek_dev_exit(void *handle);

void __DLL api_print_ts_info(void *handle);
void __DLL api_read_then_print_m2v_info(void *handle);

int __DLL api_update_ts_info(void *handle);

int __DLL api_protocol_set_cmd(void *handle, uint8_t idx, void *data);
int __DLL api_set_ctrl_mode(void *handle, uint8_t mode, bool eng, bool force);

uint16_t __DLL api_get_block_crc_by_addr(void *handle, uint8_t type,
					 uint32_t start, uint32_t end);
uint16_t __DLL api_get_block_crc_by_num(void *handle, uint8_t type,
					uint8_t block_num);

int __DLL api_set_data_len(void *handle, uint16_t data_len);
int __DLL api_write_enable_v6(void *handle, bool in_ap, bool is_slave,
			      uint32_t start, uint32_t end);
int __DLL api_write_data_v6(void *handle, int wlen);
int __DLL api_access_slave(void *handle, uint8_t id, uint8_t func, void *data);
int __DLL api_check_busy(void *handle, int timeout_ms, int delay_ms);
int __DLL api_write_enable_v3(void *handle, bool in_ap,
			      bool write_ap, uint32_t end, uint32_t checksum);
int __DLL api_write_data_v3(void *handle);

int __DLL api_to_bl_mode(void *handle, bool bl, uint32_t start, uint32_t end);

int __DLL api_write_data_m2v(void *handle, int wlen);
int __DLL api_to_bl_mode_m2v(void *handle, bool to_bl);

int __DLL api_set_idle(void *handle, bool enable);
int __DLL api_set_func_mode(void *handle, uint8_t mode);
int __DLL api_get_func_mode(void *handle);

int __DLL api_erase_data_v3(void *handle);

int __DLL api_read_flash(void *handle, uint8_t *buf,
			 uint32_t start_addr, uint32_t len);

int __DLL _api_read_mp_result(void *handle);
int __DLL api_read_mp_result(void *handle);
int __DLL _api_write_mp_result(void *handle, struct mp_station *mp);
int __DLL api_write_mp_result(void *handle, struct mp_station *mp);
void __DLL api_decode_mp_result(void *handle);

int __DLL api_read_tuning(void *handle, uint8_t *buf, int rlen);

int __DLL api_get_ic_crc(void *handle, uint8_t final_fw_mode);

#ifdef __cplusplus
}
#endif

#endif
