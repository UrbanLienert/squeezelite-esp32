#ifdef NETWORK_HTTP_SERVER_LOG_LEVEL
#define LOG_LOCAL_LEVEL NETWORK_HTTP_SERVER_LOG_LEVEL
#endif
/*
 *  Squeezelite for esp32
 *
 *  (c) Sebastien 2019
 *      Philippe G. 2019, philippe_44@outlook.com
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "http_server_handlers.h"
#include "esp_log.h"
#include "esp_http_server.h"
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "messaging.h"
#include "platform_esp32.h"
#include "trace.h"
#include "tools.h"

#include "audio_controls.h"
#include "driver/uart.h"
#include "driver/gpio.h"
#define UART_PORT_NUM 1
#define BUF_SIZE 128

static TimerHandle_t polled_uart_timer;

static const char TAG[] = "http_server";

EXT_RAM_ATTR static httpd_handle_t _server;
EXT_RAM_ATTR static int _port;
EXT_RAM_ATTR rest_server_context_t *rest_context;
EXT_RAM_ATTR RingbufHandle_t messaging;

httpd_handle_t http_get_server(int *port) {
	if (port) *port = _port;
	return _server;
}

uint8_t buf[BUF_SIZE] = { 0 };
uint8_t data[BUF_SIZE] = { 0 };

static esp_err_t remote_handler(httpd_req_t *req)
{
    httpd_ws_frame_t ws_pkt;
    memset(&ws_pkt, 0, sizeof(httpd_ws_frame_t));
    ws_pkt.payload = buf;
    ws_pkt.type = HTTPD_WS_TYPE_TEXT;
    esp_err_t ret = httpd_ws_recv_frame(req, &ws_pkt, BUF_SIZE);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "httpd_ws_recv_frame failed with %d", ret);
        return ret;
    }
    ESP_LOGI(TAG, "Got packet with message: %s", ws_pkt.payload);

	buf[ws_pkt.len] = '\0';
	const char *cmd = (const char *)buf;
	if (strstr(cmd, "Button")!=NULL) {
		// Button command
		uint16_t addr = 30345;
		if (strstr(cmd, "Play")!=NULL) {
			uint16_t cmd = 4335;
			actrls_ir_action(addr, cmd);
		} else if (strstr(cmd, "Pause")!=NULL) {
			uint16_t cmd = 8415;
			actrls_ir_action(addr, cmd);
		} else if (strstr(cmd, "Prev")!=NULL) { 
			uint16_t cmd = 49215;
			actrls_ir_action(addr, cmd);
		} else if (strstr(cmd, "Next")!=NULL) { 
			uint16_t cmd = 41055;
			actrls_ir_action(addr, cmd);
		}
	} else {
		// NAD remote command
		uart_write_bytes(UART_PORT_NUM, (const char *) buf, ws_pkt.len);
		//ESP_LOGI(TAG, "sending to NAD: %i", sent);
	}

    return ret;
}

void register_common_handlers(httpd_handle_t server){
	httpd_uri_t css_get = { .uri = "/css/*", .method = HTTP_GET, .handler = resource_filehandler, .user_ctx = rest_context };
	httpd_register_uri_handler(server, &css_get);
	httpd_uri_t js_get = { .uri = "/js/*", .method = HTTP_GET, .handler = resource_filehandler, .user_ctx = rest_context };
	httpd_register_uri_handler(server, &js_get);
	httpd_uri_t icon_get = { .uri = "/icons*", .method = HTTP_GET, .handler = resource_filehandler, .user_ctx = rest_context };
	httpd_register_uri_handler(server, &icon_get);	
	httpd_uri_t png_get = { .uri = "/favicon*", .method = HTTP_GET, .handler = resource_filehandler, .user_ctx = rest_context };
	httpd_register_uri_handler(server, &png_get);	
}
void register_regular_handlers(httpd_handle_t server){
	httpd_uri_t root_get = { .uri = "/", .method = HTTP_GET, .handler = root_get_handler, .user_ctx = rest_context };
	httpd_register_uri_handler(server, &root_get);

	httpd_uri_t ws = {.uri = "/ws", .method = HTTP_GET, .handler = remote_handler, .user_ctx = NULL, .is_websocket = true};
	httpd_register_uri_handler(server, &ws);

	httpd_uri_t ap_get = { .uri = "/ap.json", .method = HTTP_GET, .handler = ap_get_handler, .user_ctx = rest_context };
	httpd_register_uri_handler(server, &ap_get);
	httpd_uri_t scan_get = { .uri = "/scan.json", .method = HTTP_GET, .handler = ap_scan_handler, .user_ctx = rest_context };
	httpd_register_uri_handler(server, &scan_get);
	httpd_uri_t config_get = { .uri = "/config.json", .method = HTTP_GET, .handler = config_get_handler, .user_ctx = rest_context };
	httpd_register_uri_handler(server, &config_get);
	httpd_uri_t status_get = { .uri = "/status.json", .method = HTTP_GET, .handler = status_get_handler, .user_ctx = rest_context };
	httpd_register_uri_handler(server, &status_get);
	httpd_uri_t messages_get = { .uri = "/messages.json", .method = HTTP_GET, .handler = messages_get_handler, .user_ctx = rest_context };
	httpd_register_uri_handler(server, &messages_get);

	httpd_uri_t commands_get = { .uri = "/commands.json", .method = HTTP_GET, .handler = console_cmd_get_handler, .user_ctx = rest_context };
	httpd_register_uri_handler(server, &commands_get);
	httpd_uri_t commands_post = { .uri = "/commands.json", .method = HTTP_POST, .handler = console_cmd_post_handler, .user_ctx = rest_context };
	httpd_register_uri_handler(server, &commands_post);

	httpd_uri_t config_post = { .uri = "/config.json", .method = HTTP_POST, .handler = config_post_handler, .user_ctx = rest_context };
	httpd_register_uri_handler(server, &config_post);
	httpd_uri_t connect_post = { .uri = "/connect.json", .method = HTTP_POST, .handler = connect_post_handler, .user_ctx = rest_context };
	httpd_register_uri_handler(server, &connect_post);

	httpd_uri_t reboot_ota_post = { .uri = "/reboot_ota.json", .method = HTTP_POST, .handler = reboot_ota_post_handler, .user_ctx = rest_context };
	httpd_register_uri_handler(server, &reboot_ota_post);

	httpd_uri_t reboot_post = { .uri = "/reboot.json", .method = HTTP_POST, .handler = reboot_post_handler, .user_ctx = rest_context };
	httpd_register_uri_handler(server, &reboot_post);

	httpd_uri_t recovery_post = { .uri = "/recovery.json", .method = HTTP_POST, .handler = recovery_post_handler, .user_ctx = rest_context };
	httpd_register_uri_handler(server, &recovery_post);

	httpd_uri_t connect_delete = { .uri = "/connect.json", .method = HTTP_DELETE, .handler = connect_delete_handler, .user_ctx = rest_context };
	httpd_register_uri_handler(server, &connect_delete);

	if(is_recovery_running){
		httpd_uri_t flash_post = { .uri = "/flash.json", .method = HTTP_POST, .handler = flash_post_handler, .user_ctx = rest_context };
		httpd_register_uri_handler(server, &flash_post);
	}
	// from https://github.com/tripflex/wifi-captive-portal/blob/master/src/mgos_wifi_captive_portal.c
	// https://unix.stackexchange.com/questions/432190/why-isnt-androids-captive-portal-detection-triggering-a-browser-window
	 // Known HTTP GET requests to check for Captive Portal

	///kindle-wifi/wifiredirect.html Kindle when requested with com.android.captiveportallogin
	///kindle-wifi/wifistub.html Kindle before requesting with captive portal login window (maybe for detection?)


	httpd_uri_t connect_redirect_1 = { .uri = "/mobile/status.php", .method = HTTP_GET, .handler = redirect_200_ev_handler, .user_ctx = rest_context };// Android 8.0 (Samsung s9+)
	httpd_register_uri_handler(server, &connect_redirect_1);
	httpd_uri_t connect_redirect_2 = { .uri = "/generate_204", .method = HTTP_GET, .handler = redirect_200_ev_handler, .user_ctx = rest_context };// Android
	httpd_register_uri_handler(server, &connect_redirect_2);
	httpd_uri_t connect_redirect_3 = { .uri = "/gen_204", .method = HTTP_GET, .handler = redirect_ev_handler, .user_ctx = rest_context };// Android 9.0
	httpd_register_uri_handler(server, &connect_redirect_3);
//	httpd_uri_t connect_redirect_4 = { .uri = "/ncsi.txt", .method = HTTP_GET, .handler = redirect_ev_handler, .user_ctx = rest_context };// Windows
//	httpd_register_uri_handler(server, &connect_redirect_4);
	httpd_uri_t connect_redirect_5 = { .uri = "/hotspot-detect.html", .method = HTTP_GET, .handler = redirect_ev_handler, .user_ctx = rest_context }; // iOS 8/9
	httpd_register_uri_handler(server, &connect_redirect_5);
	httpd_uri_t connect_redirect_6 = { .uri = "/library/test/success.html", .method = HTTP_GET, .handler = redirect_ev_handler, .user_ctx = rest_context };// iOS 8/9
	httpd_register_uri_handler(server, &connect_redirect_6);
	httpd_uri_t connect_redirect_7 = { .uri = "/hotspotdetect.html", .method = HTTP_GET, .handler = redirect_ev_handler, .user_ctx = rest_context }; // iOS
	httpd_register_uri_handler(server, &connect_redirect_7);
	httpd_uri_t connect_redirect_8 = { .uri = "/success.txt", .method = HTTP_GET, .handler = redirect_ev_handler, .user_ctx = rest_context }; // OSX
	httpd_register_uri_handler(server, &connect_redirect_8);



	ESP_LOGD(TAG,"Registering default error handler for 404");
	httpd_register_err_handler(server, HTTPD_404_NOT_FOUND,&err_handler);

}

static void uart_polling( TimerHandle_t xTimer ) {
	int len = uart_read_bytes(UART_PORT_NUM, data, (BUF_SIZE), 20 / portTICK_PERIOD_MS);
    if (len) {
        //data[len] = '\0';
        //ESP_LOGI(TAG, "<- %s", (char *) data);

		// trying to send it to all clients
		int client_fds[10];
		size_t fds = 10;
		esp_err_t err = httpd_get_client_list(_server, &fds, client_fds);
		if (err != ESP_OK){
    		ESP_LOGE_LOC(TAG, "Failed to get client list");
    	} else {
			httpd_ws_frame_t ws_pkt;
    		memset(&ws_pkt, 0, sizeof(httpd_ws_frame_t));
    		ws_pkt.payload = data;
    		ws_pkt.type = HTTPD_WS_TYPE_BINARY;
			ws_pkt.fragmented = false;
			ws_pkt.len = len;
			for (int i=0; i<fds; i++) {
				int fd = client_fds[i];
				if (httpd_ws_get_fd_info(_server, fd) == HTTPD_WS_CLIENT_WEBSOCKET) {
					ESP_LOGI(TAG, "sending data to remote");
					err = httpd_ws_send_frame_async(_server, fd, &ws_pkt);
					if (err != ESP_OK){
						ESP_LOGE_LOC(TAG, "Failed to send frame");
					}
				}
			}
		}
	}
}

esp_err_t http_server_start()
{
	
	ESP_LOGI(TAG, "Initializing HTTP Server");
	MEMTRACE_PRINT_DELTA_MESSAGE("Registering messaging subscriber");
	messaging = messaging_register_subscriber(10, "http_server");
	MEMTRACE_PRINT_DELTA_MESSAGE("Allocating RAM for server context");
    rest_context = malloc_init_external( sizeof(rest_server_context_t));
    if(rest_context==NULL){
    	ESP_LOGE(TAG,"No memory for http context");
    	return ESP_FAIL;
    }

    strlcpy(rest_context->base_path, "/res/", sizeof(rest_context->base_path));

    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.max_uri_handlers = 30;
    config.max_open_sockets = 3;
	config.lru_purge_enable = true;
	config.backlog_conn = 1;
    config.uri_match_fn = httpd_uri_match_wildcard;
	config.task_priority = ESP_TASK_PRIO_MIN;
	_port = config.server_port;
    //todo:  use the endpoint below to configure session token?
    // config.open_fn

    MEMTRACE_PRINT_DELTA_MESSAGE( "Starting HTTP Server");
    esp_err_t err= httpd_start(&_server, &config);
    if(err != ESP_OK){
    	ESP_LOGE_LOC(TAG,"Start server failed");
    }
    else {
		MEMTRACE_PRINT_DELTA_MESSAGE( "HTTP Server started. Registering common handlers");
    	register_common_handlers(_server);
		MEMTRACE_PRINT_DELTA_MESSAGE("Registering regular handlers");
    	register_regular_handlers(_server);
		MEMTRACE_PRINT_DELTA_MESSAGE("HTTP Server regular handlers registered");
    }

	polled_uart_timer = xTimerCreate("uart polling", 100 / portTICK_RATE_MS, pdTRUE, NULL, uart_polling);		
	xTimerStart(polled_uart_timer, portMAX_DELAY);

    return err;
}


/* Function to free context */
void adder_free_func(void *ctx)
{
    ESP_LOGD(TAG, "/adder Free Context function called");
    free(ctx);
}


void stop_webserver(httpd_handle_t server)
{
    // Stop the httpd server
	xTimerStop(polled_uart_timer, 0);
    httpd_stop(server);
}



