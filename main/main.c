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
#include "esp_sleep.h"
#include "driver/rtc_io.h"


#include "lwip/sockets.h"
#include "lwip/dns.h"
#include "lwip/netdb.h"

#include "mqtt_client.h"
#include "cJSON.h"


#define SSID_MAX_LEN (32+1) 	// Maximale laenge eines SSID
#define MACLIST_MAX_LEN (256) 	// Maximale laenge der MacListe

typedef struct {
	unsigned frame_ctrl:16;
	unsigned duration_id:16;
	uint8_t addr1[6]; /* Address1 */
	uint8_t addr2[6]; /* Address2 */
	uint8_t addr3[6]; /* Address3 */
	unsigned sequence_ctrl:16;
	uint8_t addr4[6]; /* Address4 */
} wifi_ieee80211_mac_hdr_t;

typedef struct {
	wifi_ieee80211_mac_hdr_t hdr;
	unsigned char payload[]; 
} wifi_ieee80211_packet_t;


static void wifi_sniffer_init(void);
static void wifi_sniffer_set_channel(uint8_t channel);
static void wifi_sniffer_packet_handler(void *buff, wifi_promiscuous_pkt_type_t type);
static void wifi_sniffer_deinit();
static void get_ssid(unsigned char *data, char ssid[SSID_MAX_LEN], uint8_t ssid_len);
static void mqtt_app_start(void);
static void wifi_init(void);
static void wifi_connect_deinit();
static void json_task(void *pvParameter);
static void reboot(char *msg_err);
static esp_err_t wifi_event_handler(void *ctx, system_event_t *event);
static esp_err_t mqtt_event_handler(esp_mqtt_event_handle_t event);

RingbufHandle_t packetRingbuf ; //
static cJSON *mqtt_Packages ;
static cJSON *jdevices ;
static const char *TAG = "main";
static EventGroupHandle_t wifi_event_group;
static EventGroupHandle_t mqtt_event_group;
const static int CONNECTED_BIT = BIT0;
char deviceMacList[MACLIST_MAX_LEN][19];	// Array für Mac-Adressen. Verhindert Redundanz 
unsigned int deviceCounter = 0;				// Zeigt anzahl der bekannten Mac-Adressen


/* Handle für json task */
static TaskHandle_t xHandle_json = NULL;

uint8_t level = 0, channel = 1;

void app_main(void)
{	
	
	// LED
	gpio_set_direction(CONFIG_LED_PIN, GPIO_MODE_OUTPUT);	
	
	// PIR initialisieren
	rtc_gpio_deinit(CONFIG_PIR_PIN); //Gibt vom vorherhigen Durchlauf den RTC IO frei. Verhindert Dauerschleife, da IO Wert immer HIGH anzeigen würde.  
	rtc_gpio_init(CONFIG_PIR_PIN);  // initialisiert PIR Pin als RTC IO neu
	rtc_gpio_pullup_en(CONFIG_PIR_PIN);
    ESP_ERROR_CHECK(esp_sleep_enable_ext1_wakeup(BIT(CONFIG_PIR_PIN), ESP_EXT1_WAKEUP_ANY_HIGH));

	// Ringbuffer initialisieren
	packetRingbuf = xRingbufferCreate(12 * 1024, RINGBUF_TYPE_NOSPLIT);
	
	// JSON Objekt initialisieren 
	mqtt_Packages = cJSON_CreateObject();
	jdevices = NULL;
	jdevices = cJSON_AddArrayToObject(mqtt_Packages, "Mac");
	
	// Wifi Sniffer starten
	wifi_sniffer_init();
	
	// Erstellt eine neue Task, die auf der CPU 1 läuft-> Zuständig für das Einpacken der Mac-Adressen in ein JSON-Format
	xTaskCreate(&json_task, "json_task", 99999, NULL, 1, &xHandle_json);
	if(xHandle_json == NULL) //Startet System neu, falls JSON-Taskerstellung nicht erfolgreich war
		reboot("Impossible to create json task");
	
	unsigned long startTime = esp_log_timestamp(); // Setzt Timer für Snifferzeit
	
	while(true){			
			// Wird true, sobald die Sniffer Zeit abläuft
		if (esp_log_timestamp() - startTime >= (CONFIG_WIFI_SNIFFING_TIME * 1000) ) {
						
			wifi_sniffer_deinit();
			wifi_init();
			mqtt_app_start();
			wifi_connect_deinit();
			ESP_LOGI(TAG, "Enter Deepsleep");
			esp_deep_sleep_start();
		}else {
			gpio_set_level(CONFIG_LED_PIN, level ^= 1);
			vTaskDelay( CONFIG_SWITCHING_TIME / portTICK_PERIOD_MS);
			channel = (channel % CONFIG_WIFI_CHANNEL) + 1;
			wifi_sniffer_set_channel(channel);	
		}
	}
}


/* Sniffer*/
//WiFi Driver zum empfangen der Pakete initialisieren
void wifi_sniffer_init(void)
{
	nvs_flash_init();
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

// Gibt alle Ressourcen des WLAN-Sniffers frei und stoppt das WLAN.
static void wifi_sniffer_deinit()
{
	ESP_ERROR_CHECK(esp_wifi_set_promiscuous(false)); 
	ESP_ERROR_CHECK(esp_wifi_stop()); 
	ESP_ERROR_CHECK(esp_wifi_deinit()); 
}

// Zuständig für das Wechseln des WLAN Kanals
void wifi_sniffer_set_channel(uint8_t channel)
{
	esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
}


// Callback: Wird bei jeden empfangenden WLAN-Frame aufgerufen
void wifi_sniffer_packet_handler(void* buff, wifi_promiscuous_pkt_type_t type)
{		
	if (type == WIFI_PKT_MGMT && CONFIG_PROBE_REQUEST){
		// Speichert Paket des Types Management in den Ringbuffer
		wifi_promiscuous_pkt_t *ppkt = (wifi_promiscuous_pkt_t *)buff;
		if( ppkt->rx_ctrl.rssi > CONFIG_RSSI_Max){			
			xRingbufferSend(packetRingbuf, ppkt, ppkt->rx_ctrl.sig_len, 1);
		}
	}	
	else {
		// Speichert beliebiges Paket in den Ringbuffer
		wifi_promiscuous_pkt_t *ppkt = (wifi_promiscuous_pkt_t *)buff;
		if( ppkt->rx_ctrl.rssi > CONFIG_RSSI_Max){
			xRingbufferSend(packetRingbuf, ppkt, ppkt->rx_ctrl.sig_len, 1);
		}
	}		
}
// Parsen des SSID
static void get_ssid(unsigned char *data, char ssid[SSID_MAX_LEN], uint8_t ssid_len)
{
	int i, j;
			for(i=26, j=0; j<=SSID_MAX_LEN && j<=ssid_len-1 ; i++, j++){
				ssid[j] = data[i];
	}
}

/*END Sniffer*/

/*MQTT*/
static esp_err_t mqtt_event_handler(esp_mqtt_event_handle_t event)
{
  switch (event->event_id) {
    case MQTT_EVENT_CONNECTED:
      ESP_LOGI(TAG, "MQTT_EVENT_CONNECTED");
      xEventGroupSetBits(mqtt_event_group, CONNECTED_BIT);
      break;
    case MQTT_EVENT_DISCONNECTED:
      ESP_LOGI(TAG, "MQTT_EVENT_DISCONNECTED");
      xEventGroupClearBits(mqtt_event_group, CONNECTED_BIT);
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
    default:
      break;
  }
  return ESP_OK;
}

// Bereitet MQTT vor und sendet JSON Nachricht
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
	
	char *string = cJSON_Print(mqtt_Packages);
	if (string == NULL) {
		fprintf(stderr, "Failed to print monitor.\n");
	}
	
	printf("%s", string);		
	msg_id = esp_mqtt_client_publish(client, CONFIG_MQTT_TOPIC, string, strlen(string), 0, 0);
	ESP_LOGI(TAG, "[WI-FI] Sent publish successful on topic=%s, msg_id=%d", CONFIG_MQTT_TOPIC, msg_id);
	esp_mqtt_client_stop(client);
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

//WiFi Driver zum senden initialisieren
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

// Gibt alle Ressourcen des WLANs frei und stoppt das WLAN.
static void wifi_connect_deinit()
{
	ESP_ERROR_CHECK(esp_wifi_disconnect()); //disconnect the ESP32 WiFi station from the AP
	ESP_ERROR_CHECK(esp_wifi_stop()); //it stop station and free station control block
	ESP_ERROR_CHECK(esp_wifi_deinit()); //free all resource allocated in esp_wifi_init and stop WiFi task
}
// /*WIFI End*/

/*JSON*/

// Json Task: wandelt die im im Ringerbuffer hinterlegten Mac-Adressen in ein JSON-Format um
static void json_task(void *pvParameter)
{

	while (1) {
		// Daten aus Ringpuffer nehmen
		size_t len;
		wifi_promiscuous_pkt_t* ppkt = (wifi_promiscuous_pkt_t*)xRingbufferReceive(packetRingbuf, &len, portMAX_DELAY);
		wifi_ieee80211_packet_t *ipkt = (wifi_ieee80211_packet_t *)ppkt->payload;
		wifi_ieee80211_mac_hdr_t *hdr = &ipkt->hdr;
		
		//Gibt Ringbuffer frei und beendet Task. 
		if (len == 1) {
			vRingbufferReturnItem(packetRingbuf, ppkt);
			vRingbufferDelete(packetRingbuf);
			vTaskDelete(NULL);
		}		
		
		uint8_t toDS         = (hdr->frame_ctrl & 0b0000000100000000) >> 8;
		uint8_t fromDS       = (hdr->frame_ctrl & 0b0000001000000000) >> 9;
		
		//Nur die MAC-Adressen eines Probe Request	Paket 
		//oder Pakete die von einem Client verschickt wurden, werden in einen JSON-Format umgewandelt (siehe Kapitel 2.1.1 Aufbau des IEEE 802.11 WLAN-Frames)
		if( (fromDS == 0 && toDS == 1) || (hdr->frame_ctrl == 64 ) )
		{	
			bool knowMac = false;	//Flag für bekannte MAC-Adressem
			char temp_Adr[19]; 
	
			snprintf(temp_Adr,19 ,"%02x:%02x:%02x:%02x:%02x:%02x", hdr->addr2[0],hdr->addr2[1],hdr->addr2[2],
				 hdr->addr2[3],hdr->addr2[4],hdr->addr2[5]);
				 
			// Prüft ob aktuelle Mac-Adressen bereits bekannt ist. Falls ja, bricht aktuelle Task ab
			for(int i=1; i <= deviceCounter; i++){

				if( 0 == memcmp(deviceMacList[i-1], temp_Adr, 19 ) ){
					knowMac = true;				
					break;
					
				}
			}
			
			// Falls aktuelle Mac-Adressen neu ist, setze sie in die Mac-Liste ein 
			if(!knowMac &&  (deviceCounter+1 <= MACLIST_MAX_LEN)){
				char ssid[SSID_MAX_LEN] = "\0";

				cJSON *jssid =  cJSON_CreateObject();
				cJSON *adr =  cJSON_CreateObject();

			
				// Prüft SSID im Paket, falls Option aktiviert ist
				if( CONFIG_SSID && hdr->frame_ctrl== 64  ){
					uint8_t ssid_len;
					
					ssid_len = ppkt->payload[25];
					if(ssid_len > 0){
						get_ssid(ppkt->payload, ssid, ssid_len);	
					}	
				}
				
				//Kopiert neue Mac-Adressen in die deviceMacList und erhöht den deviceCounter
				strcpy(deviceMacList[deviceCounter], temp_Adr);				
				deviceCounter++;
							
				cJSON_AddStringToObject(adr, "Adresse", temp_Adr);
				cJSON_AddStringToObject(jssid, "SSID", ssid);
			
				cJSON_AddItemToArray(jdevices, adr);
				cJSON_AddItemToArray(adr, jssid);				
			}		
		}
		//Löscht aktuelles WLAN-Frame aus dem Ringerbuffer
		vRingbufferReturnItem(packetRingbuf, ppkt);
	}
}
/*JSON END*/

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