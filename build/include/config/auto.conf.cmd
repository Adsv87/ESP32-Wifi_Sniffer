deps_config := \
	/home/Alex/esp/esp-idf/components/app_trace/Kconfig \
	/home/Alex/esp/esp-idf/components/aws_iot/Kconfig \
	/home/Alex/esp/esp-idf/components/bt/Kconfig \
	/home/Alex/esp/esp-idf/components/driver/Kconfig \
	/home/Alex/esp/esp-idf/components/esp32/Kconfig \
	/home/Alex/esp/esp-idf/components/esp_adc_cal/Kconfig \
	/home/Alex/esp/esp-idf/components/esp_http_client/Kconfig \
	/home/Alex/esp/esp-idf/components/espmqtt/Kconfig \
	/home/Alex/esp/esp-idf/components/ethernet/Kconfig \
	/home/Alex/esp/esp-idf/components/fatfs/Kconfig \
	/home/Alex/esp/esp-idf/components/freertos/Kconfig \
	/home/Alex/esp/esp-idf/components/heap/Kconfig \
	/home/Alex/esp/esp-idf/components/http_server/Kconfig \
	/home/Alex/esp/esp-idf/components/libsodium/Kconfig \
	/home/Alex/esp/esp-idf/components/log/Kconfig \
	/home/Alex/esp/esp-idf/components/lwip/Kconfig \
	/home/Alex/esp/esp-idf/components/mbedtls/Kconfig \
	/home/Alex/esp/esp-idf/components/mdns/Kconfig \
	/home/Alex/esp/esp-idf/components/openssl/Kconfig \
	/home/Alex/esp/esp-idf/components/pthread/Kconfig \
	/home/Alex/esp/esp-idf/components/spi_flash/Kconfig \
	/home/Alex/esp/esp-idf/components/spiffs/Kconfig \
	/home/Alex/esp/esp-idf/components/tcpip_adapter/Kconfig \
	/home/Alex/esp/esp-idf/components/vfs/Kconfig \
	/home/Alex/esp/esp-idf/components/wear_levelling/Kconfig \
	/home/Alex/esp/esp-idf/Kconfig.compiler \
	/home/Alex/esp/esp-idf/components/bootloader/Kconfig.projbuild \
	/home/Alex/esp/esp-idf/components/esptool_py/Kconfig.projbuild \
	/home/Alex/esp/esp-idf/eigene/Wi-Fi-Sniffer2/main/Kconfig.projbuild \
	/home/Alex/esp/esp-idf/components/partition_table/Kconfig.projbuild \
	/home/Alex/esp/esp-idf/Kconfig

include/config/auto.conf: \
	$(deps_config)


$(deps_config): ;
