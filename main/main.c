/**
 * Copyright (c) 2017, Łukasz Marcin Podkalicki <lpodkalicki@gmail.com>
 * ESP32/016
 * WiFi Sniffer.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include "esp_system.h"
#include "esp_event.h"
#include "esp_event_loop.h"
#include "nvs_flash.h"
#include "driver/uart.h"
#include "driver/gpio.h"
#include <time.h>

#define ECHO_TEST_TXD (GPIO_NUM_17)
#define ECHO_TEST_RXD (GPIO_NUM_16)
#define ECHO_TEST_RTS (UART_PIN_NO_CHANGE)
#define ECHO_TEST_CTS (UART_PIN_NO_CHANGE)

#define BUF_SIZE (1024)
#define WIFI_CHANNEL_MAX (13)
#define WIFI_CHANNEL_SWITCH_INTERVAL (500)

static wifi_country_t wifi_country = {.cc = "CN", .schan = 1, .nchan = 13, .policy = WIFI_COUNTRY_POLICY_AUTO};

typedef struct
{
	unsigned frame_ctrl : 16;
	unsigned duration_id : 16;
	uint8_t addr1[6]; /* receiver address */
	uint8_t addr2[6]; /* sender address */
	uint8_t addr3[6]; /* filtering address */
	unsigned sequence_ctrl : 16;
	uint8_t addr4[6]; /* optional */
} wifi_ieee80211_mac_hdr_t;

typedef struct
{
	wifi_ieee80211_mac_hdr_t hdr;
	uint8_t payload[0]; /* network data ended with 4 bytes csum (CRC32) */
} wifi_ieee80211_packet_t;

static esp_err_t event_handler(void *ctx, system_event_t *event);
static void wifi_sniffer_init(void);
static void wifi_sniffer_set_channel(uint8_t channel);
static const char *wifi_sniffer_packet_type2str(wifi_promiscuous_pkt_type_t type);
static void wifi_sniffer_packet_handler(void *, wifi_promiscuous_pkt_type_t type);
const char *wifi_sniffer_packet_subtype2str(unsigned frame_control);

void app_main(void)
{
	uint8_t channel = 1;

	/* setup */
	wifi_sniffer_init();
	/* Configure parameters of an UART driver,
	 * communication pins and install the driver */
	uart_config_t uart_config = {
		.baud_rate = 115200,
		.data_bits = UART_DATA_8_BITS,
		.parity = UART_PARITY_DISABLE,
		.stop_bits = UART_STOP_BITS_1,
		.flow_ctrl = UART_HW_FLOWCTRL_DISABLE};
	uart_param_config(UART_NUM_1, &uart_config);
	uart_set_pin(UART_NUM_1, ECHO_TEST_TXD, ECHO_TEST_RXD, ECHO_TEST_RTS, ECHO_TEST_CTS);
	uart_driver_install(UART_NUM_1, BUF_SIZE * 2, 0, 0, NULL, 0);

	/* loop */
	while (true)
	{
		vTaskDelay(WIFI_CHANNEL_SWITCH_INTERVAL / portTICK_PERIOD_MS);
		wifi_sniffer_set_channel(channel);
		channel = (channel % WIFI_CHANNEL_MAX) + 1;
	}
}

esp_err_t
event_handler(void *ctx, system_event_t *event)
{

	return ESP_OK;
}

void wifi_sniffer_init(void)
{

	nvs_flash_init();
	tcpip_adapter_init();
	ESP_ERROR_CHECK(esp_event_loop_init(event_handler, NULL));
	wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
	ESP_ERROR_CHECK(esp_wifi_init(&cfg));
	ESP_ERROR_CHECK(esp_wifi_set_country(&wifi_country)); /* set country for channel range [1, 13] */
	ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
	ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_NULL));
	ESP_ERROR_CHECK(esp_wifi_start());
	esp_wifi_set_promiscuous(true);
	esp_wifi_set_promiscuous_rx_cb(&wifi_sniffer_packet_handler);
}

void wifi_sniffer_set_channel(uint8_t channel)
{

	esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
}

const char *
wifi_sniffer_packet_type2str(wifi_promiscuous_pkt_type_t type)
{
	switch (type)
	{
	case WIFI_PKT_MGMT:
		return "MGMT";
	case WIFI_PKT_DATA:
		return "DATA";
	default:
	case WIFI_PKT_MISC:
		return "MISC";
	}
}

const char *
wifi_sniffer_packet_subtype2str(unsigned frame_control)
{
	char bin16_1[] = "0000000000000000";
	char *bin_subtype = malloc(sizeof(char *) * 5);
	int pos;
	for (pos = 15; pos >= 0; --pos)
	{
		if (frame_control % 2)
			bin16_1[pos] = '1';
		frame_control /= 2;
	}
	strncpy(bin_subtype, bin16_1, 4);
	int subtype = atoi(bin_subtype);
	printf("%d", subtype);
	switch (subtype)
	{
	case 0000:
		return "1";
	case 0001:
		return "2";
	case 0010:
		return "3";
	case 0011:
		return "4";
	case 0100:
		return "5";
	case 0101:
		return "6";
	case 0110:
		return "7";
	case 0111:
		return "8";
	case 1000:
		return "9";
	case 1001:
		return "10";
	case 1010:
		return "11";
	case 1011:
		return "12";
	case 1100:
		return "13";
	case 1101:
		return "14";
	case 1110:
		return "15";
	case 1111:
		return "16";
	default:
		return "0";
	}
}

void wifi_sniffer_packet_handler(void *buff, wifi_promiscuous_pkt_type_t type)
{

	if (type != WIFI_PKT_MGMT)
		return;

	const wifi_promiscuous_pkt_t *ppkt = (wifi_promiscuous_pkt_t *)buff;
	const wifi_ieee80211_packet_t *ipkt = (wifi_ieee80211_packet_t *)ppkt->payload;
	const wifi_ieee80211_mac_hdr_t *hdr = &ipkt->hdr;
	char subtype[] = "";
	char add[] = "";
	char rssi[] = "";

	char *line_wifi = malloc(200);
	sprintf(line_wifi, "%d;%02x%02x%02x%02x%02x%02x;%02d;%s\n",
			(int)time(NULL),
			hdr->addr2[0], hdr->addr2[1], hdr->addr2[2],
			hdr->addr2[3], hdr->addr2[4], hdr->addr2[5],
			ppkt->rx_ctrl.rssi,
			wifi_sniffer_packet_subtype2str(hdr->frame_ctrl));
	// sprintf(line_wifi,"PACKET TYPE=%s, SUBTYPE=%s, CHAN=%02d, RSSI=%02d,"
	// 	" ADDR1=%02x:%02x:%02x:%02x:%02x:%02x,"
	// 	" ADDR2=%02x:%02x:%02x:%02x:%02x:%02x,"
	// 	" ADDR3=%02x:%02x:%02x:%02x:%02x:%02x\n",
	// 	wifi_sniffer_packet_type2str(type),
	// 	wifi_sniffer_packet_subtype2str(hdr->frame_ctrl),
	// 	ppkt->rx_ctrl.channel,
	// 	ppkt->rx_ctrl.rssi,
	// 	/* ADDR1 */
	// 	hdr->addr1[0],hdr->addr1[1],hdr->addr1[2],
	// 	hdr->addr1[3],hdr->addr1[4],hdr->addr1[5],
	// 	/* ADDR2 */
	// 	hdr->addr2[0],hdr->addr2[1],hdr->addr2[2],
	// 	hdr->addr2[3],hdr->addr2[4],hdr->addr2[5],
	// 	/* ADDR3 */
	// 	hdr->addr3[0],hdr->addr3[1],hdr->addr3[2],
	// 	hdr->addr3[3],hdr->addr3[4],hdr->addr3[5]
	// );
	uart_write_bytes(UART_NUM_1, (const char *)line_wifi, strlen(line_wifi));
	printf(line_wifi);
	free(line_wifi);
}
