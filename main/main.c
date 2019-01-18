#include "esp_wifi_types.h"
#include "esp_event.h"
#include "driver/gpio.h"
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "esp_wifi.h"
#include "esp_system.h"
#include "nvs_flash.h"
#include "esp_event_loop.h"
#include "esp_log.h"

#include "freertos/ringbuf.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "freertos/queue.h"
#include "freertos/event_groups.h"

#include "lwip/sockets.h"
#include "lwip/dns.h"
#include "lwip/netdb.h"

#include "mqtt_client.h"
#include "cJSON.h"

#define	LED_GPIO_PIN			22
#define	WIFI_CHANNEL_MAX		(13)
#define	WIFI_CHANNEL_SWITCH_INTERVAL	(500)
#define SSID_MAX_LEN (32+1) //max length of a SSID

typedef struct {
	unsigned frame_ctrl:16;
	unsigned duration_id:16;
	uint8_t addr1[6]; /* receiver address */
	uint8_t addr2[6]; /* sender address */
	uint8_t addr3[6]; /* filtering address */
	unsigned sequence_ctrl:16;
	uint8_t addr4[6]; /* optional */
} wifi_ieee80211_mac_hdr_t;

typedef struct {
	wifi_ieee80211_mac_hdr_t hdr;
	unsigned char payload[]; /* network data ended with 4 bytes csum (CRC32) */
} wifi_ieee80211_packet_t;


static void wifi_sniffer_init(void);
static void wifi_sniffer_set_channel(uint8_t channel);
static const char *wifi_sniffer_packet_type2str(wifi_promiscuous_pkt_type_t type);
static void wifi_sniffer_packet_handler(void *buff, wifi_promiscuous_pkt_type_t type);
static void wifi_sniffer_deinit();
static void get_ssid(unsigned char *data, char ssid[SSID_MAX_LEN], uint8_t ssid_len);
static int get_sn(unsigned char *data);
static void mqtt_app_start(void);
static void wifi_init(void);
static void wifi_connect_deinit();
static void json_task(void *pvParameter);
static void reboot(char *msg_err);
static esp_err_t wifi_event_handler(void *ctx, system_event_t *event);
static esp_err_t mqtt_event_handler(esp_mqtt_event_handle_t event);

RingbufHandle_t packetRingbuf ;
static const cJSON *mqtt_Packages ;

static const char *TAG = "main";
static EventGroupHandle_t wifi_event_group;
static EventGroupHandle_t mqtt_event_group;
const static int CONNECTED_BIT = BIT0;
bool running = false;
char *string = NULL; //Später löschen und mqtt einfügen

/* Handle for json task */
static TaskHandle_t xHandle_json = NULL;

uint8_t level = 0, channel = 1;

void app_main(void)
{	
	nvs_flash_init();
	gpio_set_direction(LED_GPIO_PIN, GPIO_MODE_OUTPUT);	
	packetRingbuf = xRingbufferCreate(12 * 1024, RINGBUF_TYPE_NOSPLIT);
	mqtt_Packages = cJSON_CreateObject();
	wifi_sniffer_init();
	
	xTaskCreate(&json_task, "json_task", 99999, NULL, 1, &xHandle_json);
	if(xHandle_json == NULL)
		reboot("Impossible to create json task");
	
	unsigned long startTime = esp_log_timestamp();
	
	while(true){			
			
		if (esp_log_timestamp() - startTime >= (CONFIG_WIFI_SNIFFING_TIME * 1000) && running == false) {
			running = true;
			
			//später für mqtt
			string = cJSON_Print(mqtt_Packages);
			if (string == NULL) {
				fprintf(stderr, "Failed to print monitor.\n");
			}
			printf("%s", string);

			wifi_sniffer_deinit();
			wifi_init();
			mqtt_app_start();
			////
		}else if(running == false){
			gpio_set_level(LED_GPIO_PIN, level ^= 1);
			vTaskDelay( 60 / portTICK_PERIOD_MS);
			wifi_sniffer_set_channel(channel);
			channel = (channel % CONFIG_WIFI_CHANNEL) + 1;	
		}
	}
}

// void loop(){
		// if (esp_log_timestamp() - startTime >= (CONFIG_WIFI_SNIFFING_TIME * 1000) && running == false) {
			// running = true;	
			// wifi_sniffer_deinit();
			// wifi_init();
			// mqtt_app_start();
			// vTaskDelete(&xHandle_json);
		// }else if(running == false){
			// gpio_set_level(LED_GPIO_PIN, level ^= 1);
			// vTaskDelay( 60 / portTICK_PERIOD_MS);
			// wifi_sniffer_set_channel(channel);
			// channel = (channel % CONFIG_WIFI_CHANNEL) + 1;	
		// }
// }


/* Sniffer*/
void wifi_sniffer_init(void)
{
    tcpip_adapter_init();
    ESP_ERROR_CHECK( esp_event_loop_init(wifi_event_handler, NULL) );
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
	ESP_ERROR_CHECK( esp_wifi_init(&cfg) );
	static wifi_country_t wifi_country = {.cc="CN", .schan=1, .nchan=13, .policy=WIFI_COUNTRY_POLICY_AUTO};
	ESP_ERROR_CHECK( esp_wifi_set_country(&wifi_country) ); /* set country for channel range [1, 13] */
	ESP_ERROR_CHECK( esp_wifi_set_storage(WIFI_STORAGE_RAM) );
    ESP_ERROR_CHECK( esp_wifi_set_mode(WIFI_MODE_NULL) );
    ESP_ERROR_CHECK( esp_wifi_start() );
	esp_wifi_set_promiscuous(true);
	esp_wifi_set_promiscuous_rx_cb(&wifi_sniffer_packet_handler);	
}

static void wifi_sniffer_deinit()
{
	ESP_ERROR_CHECK(esp_wifi_set_promiscuous(false)); //set as 'false' the promiscuous mode
	ESP_ERROR_CHECK(esp_wifi_stop()); //it stop soft-AP and free soft-AP control block
	ESP_ERROR_CHECK(esp_wifi_deinit()); //free all resource allocated in esp_wifi_init() and stop WiFi task
}

void wifi_sniffer_set_channel(uint8_t channel)
{
	esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
}

const char * wifi_sniffer_packet_type2str(wifi_promiscuous_pkt_type_t type)
{
	switch(type) {
	case WIFI_PKT_MGMT: return "MGMT";
	case WIFI_PKT_DATA: return "DATA";
	default:	
	case WIFI_PKT_MISC: return "MISC";
	}
}

void wifi_sniffer_packet_handler(void* buff, wifi_promiscuous_pkt_type_t type)
{
		
	if (type == WIFI_PKT_MGMT && CONFIG_PROBE_REQUEST){
		wifi_promiscuous_pkt_t *ppkt = (wifi_promiscuous_pkt_t *)buff;
		xRingbufferSend(packetRingbuf, ppkt, ppkt->rx_ctrl.sig_len, 1);
	}	
	else if(!CONFIG_PROBE_REQUEST){
		wifi_promiscuous_pkt_t *ppkt = (wifi_promiscuous_pkt_t *)buff;
		xRingbufferSend(packetRingbuf, ppkt, ppkt->rx_ctrl.sig_len, 1);
	}		
}

static void get_ssid(unsigned char *data, char ssid[SSID_MAX_LEN], uint8_t ssid_len)
{
	int i, j;
			for(i=26, j=0; j<=SSID_MAX_LEN && j<=ssid_len-1 ; i++, j++){
				ssid[j] = data[i];
	}
}

static int get_sn(unsigned char *data)
{
	int sn;
    char num[5] = "\0";

	sprintf(num, "%02x%02x", data[22], data[23]);
    sscanf(num, "%x", &sn);

    return sn;
}

/*END Sniffer*/
static esp_err_t mqtt_event_handler(esp_mqtt_event_handle_t event)
{
    esp_mqtt_client_handle_t client = event->client;
    int msg_id;

    switch (event->event_id) {
        case MQTT_EVENT_CONNECTED:
            ESP_LOGI(TAG, "MQTT_EVENT_CONNECTED");
            msg_id = esp_mqtt_client_subscribe(client, "/topic/qos0", 0);
            ESP_LOGI(TAG, "sent subscribe successful, msg_id=%d", msg_id);

            msg_id = esp_mqtt_client_subscribe(client, "/topic/qos1", 1);
            ESP_LOGI(TAG, "sent subscribe successful, msg_id=%d", msg_id);

            msg_id = esp_mqtt_client_unsubscribe(client, "/topic/qos1");
            ESP_LOGI(TAG, "sent unsubscribe successful, msg_id=%d", msg_id);
            break;
        case MQTT_EVENT_DISCONNECTED:
            ESP_LOGI(TAG, "MQTT_EVENT_DISCONNECTED");
            break;

        case MQTT_EVENT_SUBSCRIBED:
            ESP_LOGI(TAG, "MQTT_EVENT_SUBSCRIBED, msg_id=%d", event->msg_id);
            msg_id = esp_mqtt_client_publish(client, "/topic/qos0", "data", 0, 0, 0);
            ESP_LOGI(TAG, "sent publish successful, msg_id=%d", msg_id);
            break;
        case MQTT_EVENT_UNSUBSCRIBED:
            ESP_LOGI(TAG, "MQTT_EVENT_UNSUBSCRIBED, msg_id=%d", event->msg_id);
            break;
        case MQTT_EVENT_PUBLISHED:
            ESP_LOGI(TAG, "MQTT_EVENT_PUBLISHED, msg_id=%d", event->msg_id);
            break;
        case MQTT_EVENT_DATA:
            ESP_LOGI(TAG, "MQTT_EVENT_DATA");
            printf("TOPIC=%.*s\r\n", event->topic_len, event->topic);
            printf("DATA=%.*s\r\n", event->data_len, event->data);
            break;
        case MQTT_EVENT_ERROR:
            ESP_LOGI(TAG, "MQTT_EVENT_ERROR");
            break;
    }
    return ESP_OK;
}

static void mqtt_app_start(void)
{
	int msg_id;
    const esp_mqtt_client_config_t mqtt_cfg = {
    .uri  = CONFIG_MQTT_SERVER_URI,
    .port = CONFIG_MQTT_PORT,
	.transport = MQTT_TRANSPORT_OVER_TCP,
    .username = CONFIG_MQTT_USER,
    .password = CONFIG_MQTT_PASS,
    .event_handle = mqtt_event_handler,
};

	mqtt_event_group = xEventGroupCreate();
	esp_mqtt_client_handle_t client = esp_mqtt_client_init(&mqtt_cfg);
	ESP_LOGI(TAG, "MQTT Client init finished");
	ESP_ERROR_CHECK(esp_mqtt_client_start(client));
	ESP_LOGI(TAG, "MQTT Client start finished");
	xEventGroupWaitBits(mqtt_event_group, CONNECTED_BIT, false, true, portMAX_DELAY);
	ESP_LOGI(TAG, "MQTT Client connected");
	
	string = cJSON_Print(mqtt_Packages);
	if (string == NULL) {
		fprintf(stderr, "Failed to print monitor.\n");
	}
			
	msg_id = esp_mqtt_client_publish(client, CONFIG_MQTT_TOPIC, string, strlen(string), 0, 0);
	ESP_LOGI(TAG, "[WI-FI] Sent publish successful on topic=%s, msg_id=%d", CONFIG_MQTT_TOPIC, msg_id);
}

/*END MQTT*/

/*WIFI INIT*/
static esp_err_t wifi_event_handler(void *ctx, system_event_t *event)
{
    switch (event->event_id) {
        case SYSTEM_EVENT_STA_START:
            esp_wifi_connect();
            break;
        case SYSTEM_EVENT_STA_GOT_IP:
            xEventGroupSetBits(wifi_event_group, CONNECTED_BIT);
            break;
        case SYSTEM_EVENT_STA_DISCONNECTED:
            esp_wifi_connect();
            xEventGroupClearBits(wifi_event_group, CONNECTED_BIT);
            break;
        default:
            break;
    }
    return ESP_OK;
}

static void wifi_init(void)
{
	nvs_flash_init();
    tcpip_adapter_init();
    wifi_event_group = xEventGroupCreate();
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    wifi_config_t wifi_config = {
        .sta = {
            .ssid = CONFIG_WIFI_SSID,
            .password = CONFIG_WIFI_PSW,
        },
    };
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(ESP_IF_WIFI_STA, &wifi_config));
    ESP_LOGI(TAG, "start the WIFI SSID:[%s] password:[%s]", CONFIG_WIFI_SSID, "******");
    ESP_ERROR_CHECK(esp_wifi_start());
    ESP_LOGI(TAG, "Waiting for wifi");
    xEventGroupWaitBits(wifi_event_group, CONNECTED_BIT, false, true, portMAX_DELAY);
}
static void wifi_connect_deinit()
{
	ESP_ERROR_CHECK(esp_wifi_disconnect()); //disconnect the ESP32 WiFi station from the AP
	ESP_ERROR_CHECK(esp_wifi_stop()); //it stop station and free station control block
	ESP_ERROR_CHECK(esp_wifi_deinit()); //free all resource allocated in esp_wifi_init and stop WiFi task
}
/*WIFI End*/

/*JSON*/
static void json_task(void *pvParameter)
{

	// ESP_LOGI("json_task: Core %d for time intensive operation active!", xPortGetCoreID());
	while (1) {
		// Daten aus Ringpuffer nehmen
		size_t len;
		wifi_promiscuous_pkt_t* ppkt = (wifi_promiscuous_pkt_t*)xRingbufferReceive(packetRingbuf, &len, portMAX_DELAY);
		wifi_ieee80211_packet_t *ipkt = (wifi_ieee80211_packet_t *)ppkt->payload;
		wifi_ieee80211_mac_hdr_t *hdr = &ipkt->hdr;
		
		//Falls Ringpuffer leer ist, 
		if (len == 1) {
			printf("\n Ringbuffer wird geleert");
			vRingbufferReturnItem(packetRingbuf, ppkt);
			vRingbufferDelete(packetRingbuf);
			vTaskDelete(NULL);
		}		
		
		// unsigned int frameControl = ((unsigned int)snifferPacket->data[1] << 8) + snifferPacket->data[0];

		// uint8_t version      = (hdr->frame_ctrl & 0b0000000000000011) >> 0;
		// uint8_t frameType    = (hdr->frame_ctrl & 0b0000000000001100) >> 2;
		// uint8_t frameSubType = (hdr->frame_ctrl & 0b0000000011110000) >> 4;
		uint8_t toDS         = (hdr->frame_ctrl & 0b0000000100000000) >> 8;
		uint8_t fromDS       = (hdr->frame_ctrl & 0b0000001000000000) >> 9;
				
		if( (fromDS == 0 && toDS == 1) || (hdr->frame_ctrl==64 ) )
		{	
			uint8_t ssid_len;
			char ssid[SSID_MAX_LEN] = "\0";
				
			char *temp_Adr[18]; 
			cJSON *jdevices = NULL;
			cJSON *jssid =  cJSON_CreateObject();
			cJSON *channel =  cJSON_CreateObject();
			cJSON *adr =  cJSON_CreateObject();
			cJSON *rssi = cJSON_CreateObject();
			
			if(CONFIG_PROBE_REQUEST){
				jdevices = cJSON_AddArrayToObject(mqtt_Packages, "PROBE_REQUEST");
			}else{
				jdevices = cJSON_AddArrayToObject(mqtt_Packages, "Traffic Paket");
			}
			
			
			ssid_len = ppkt->payload[25];
			if((ssid_len > 0) && CONFIG_SSID)	{
 
				get_ssid(ppkt->payload, ssid, ssid_len);
			}
			
			sprintf(temp_Adr, "%02x:%02x:%02x:%02x:%02x:%02x", hdr->addr2[0],hdr->addr2[1],hdr->addr2[2],
				 hdr->addr2[3],hdr->addr2[4],hdr->addr2[5]);

			cJSON_AddStringToObject(adr, "Adresse", temp_Adr);
			cJSON_AddNumberToObject(channel, "Channel", ppkt->rx_ctrl.channel);
			cJSON_AddNumberToObject(rssi, "RSSI", ppkt->rx_ctrl.rssi);
			cJSON_AddStringToObject(jssid, "SSID", ssid);
			
			cJSON_AddItemToArray(jdevices, adr);
			cJSON_AddItemToArray(jdevices, channel);
			cJSON_AddItemToArray(jdevices, rssi);
			cJSON_AddItemToArray(jdevices, jssid);
			
			// string = cJSON_Print(mqtt_Packages);
			// if (string == NULL) {
				// fprintf(stderr, "Failed to print monitor.\n");
			// }
			// printf("%s", string);		
		}
			vRingbufferReturnItem(packetRingbuf, ppkt);

	}
}

static void reboot(char *msg_err)
{
	int i;

	ESP_LOGE(TAG, "%s", msg_err);
    for(i=3; i>=0; i--){
        ESP_LOGW(TAG, "Restarting in %d seconds...", i);
        vTaskDelay(1000 / portTICK_PERIOD_MS);
    }

    ESP_LOGW(TAG, "Restarting now");
    fflush(stdout);

    esp_restart();
}