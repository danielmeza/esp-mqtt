/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <catch2/catch_test_macros.hpp>
#include <cstdint>
#include <cstring>
#include <memory>
#include <type_traits>

#include "esp_err.h"
#include "esp_transport.h"
/* mqtt_client.h must come first: mqtt5_client.h sets its own include guard
   before including mqtt_client.h, so pulling it in first leaves mqtt_client.h
   without the MQTT5 types its own prototypes reference. */
#include "mqtt_client.h"
#include "mqtt5_client.h"

extern "C" {
    esp_err_t test_mqtt5_check_inflight_maximum(uint16_t send_count, uint16_t receive_maximum);
    int test_mqtt5_increment_packet_counter_with_dup(void);
    esp_err_t test_mqtt5_validate_subscribe_property(const esp_mqtt5_subscribe_property_config_t *property,
                                                     bool shared_available, esp_mqtt_protocol_ver_t protocol_ver);
    esp_err_t test_mqtt5_validate_unsubscribe_property(const esp_mqtt5_unsubscribe_property_config_t *property,
                                                       bool shared_available, esp_mqtt_protocol_ver_t protocol_ver);
    esp_err_t test_mqtt5_validate_publish_property(const esp_mqtt5_publish_property_config_t *property,
                                                   uint16_t topic_alias_maximum, esp_mqtt_protocol_ver_t protocol_ver);
    const void *test_mqtt5_staged_publish_property(esp_mqtt_client_handle_t client);
    const char *test_mqtt5_connect_auth_method(esp_mqtt_client_handle_t client);
    const char *test_mqtt5_connect_auth_data(esp_mqtt_client_handle_t client);
    uint16_t test_mqtt5_connect_auth_data_len(esp_mqtt_client_handle_t client);

#include "Mockesp_event.h"
#include "Mockesp_timer.h"
#include "Mockesp_transport.h"
#include "Mockesp_transport_ssl.h"
#include "Mockesp_transport_tcp.h"
#include "Mockesp_transport_ws.h"
#include "Mockevent_groups.h"
#include "Mockqueue.h"
#include "Mocktask.h"
#if __has_include("Mockidf_additions.h")
    /* Some functions were moved from "task.h" to "idf_additions.h" */
#include "Mockidf_additions.h"
#endif
}

using unique_mqtt_client =
    std::unique_ptr < std::remove_pointer_t<esp_mqtt_client_handle_t>,
    decltype([](esp_mqtt_client_handle_t client)
{
    esp_mqtt_client_destroy(client);
}) >;

static esp_err_t validate_subscribe(const esp_mqtt5_subscribe_property_config_t &property, bool shared_available = true)
{
    return test_mqtt5_validate_subscribe_property(&property, shared_available, MQTT_PROTOCOL_V_5);
}

static esp_err_t validate_unsubscribe(const esp_mqtt5_unsubscribe_property_config_t &property,
                                      bool shared_available = true)
{
    return test_mqtt5_validate_unsubscribe_property(&property, shared_available, MQTT_PROTOCOL_V_5);
}

static esp_err_t validate_publish(const esp_mqtt5_publish_property_config_t &property, uint16_t topic_alias_maximum = 10)
{
    return test_mqtt5_validate_publish_property(&property, topic_alias_maximum, MQTT_PROTOCOL_V_5);
}

/* The CONNECT authentication properties are stored in the private mqtt5 config,
   so the tests need a client built by esp_mqtt_client_init() rather than the
   hand-filled structs the validators above use. Same mock preamble as the
   SCENARIO below; the handles are only carried around by the mocks and never
   dereferenced, so static storage keeps them valid for the whole run. */
static unique_mqtt_client make_mqtt5_client()
{
    static int mutex;
    static int transport_list;
    static int transport;
    static int event_group;
    esp_timer_get_time_IgnoreAndReturn(0);
    xQueueTakeMutexRecursive_IgnoreAndReturn(true);
    xQueueGiveMutexRecursive_IgnoreAndReturn(true);
    xQueueCreateMutex_ExpectAnyArgsAndReturn(reinterpret_cast<QueueHandle_t>(&mutex));
    xEventGroupCreate_IgnoreAndReturn(reinterpret_cast<EventGroupHandle_t>(&event_group));
    esp_transport_list_init_IgnoreAndReturn(reinterpret_cast<esp_transport_list_handle_t>(&transport_list));
    esp_transport_tcp_init_IgnoreAndReturn(reinterpret_cast<esp_transport_handle_t>(&transport));
    esp_transport_ssl_init_IgnoreAndReturn(reinterpret_cast<esp_transport_handle_t>(&transport));
    esp_transport_ws_init_IgnoreAndReturn(reinterpret_cast<esp_transport_handle_t>(&transport));
    esp_transport_ws_set_subprotocol_IgnoreAndReturn(ESP_OK);
    esp_transport_list_add_IgnoreAndReturn(ESP_OK);
    esp_transport_set_default_port_IgnoreAndReturn(ESP_OK);
    esp_event_loop_create_IgnoreAndReturn(ESP_OK);
    esp_event_loop_delete_IgnoreAndReturn(ESP_OK);
    esp_transport_list_destroy_IgnoreAndReturn(ESP_OK);
    esp_transport_destroy_IgnoreAndReturn(ESP_OK);
    xTaskCreatePinnedToCore_IgnoreAndReturn(pdTRUE);
    vEventGroupDelete_Ignore();
    vQueueDelete_Ignore();
    esp_mqtt_client_config_t config{};
    config.broker.address.uri = "mqtt://1.1.1.1";
    config.session.protocol_ver = MQTT_PROTOCOL_V_5;
    return unique_mqtt_client{esp_mqtt_client_init(&config)};
}

/* Binary on purpose: a NUL and a high byte inside the payload make a copy that
   stops at strlen() or at the first NUL visibly wrong. */
static const char auth_data[] = {'\x00', '\x01', '\x7f', static_cast<char>(0xff), 'x'};

static void require_auth_stored(esp_mqtt_client_handle_t client, const char *method)
{
    const char *stored_method = test_mqtt5_connect_auth_method(client);
    const char *stored_data = test_mqtt5_connect_auth_data(client);
    REQUIRE(stored_method != nullptr);
    REQUIRE(std::strcmp(stored_method, method) == 0);
    REQUIRE(stored_data != nullptr);
    REQUIRE(test_mqtt5_connect_auth_data_len(client) == sizeof(auth_data));
    REQUIRE(std::memcmp(stored_data, auth_data, sizeof(auth_data)) == 0);
}

TEST_CASE("MQTT5 inflight quota uses an exact upper bound")
{
    REQUIRE(test_mqtt5_check_inflight_maximum(1, 2) == ESP_OK);
    REQUIRE(test_mqtt5_check_inflight_maximum(2, 2) == ESP_FAIL);
}

TEST_CASE("MQTT5 first send on a connection counts even when PUBLISH has DUP set")
{
    REQUIRE(test_mqtt5_increment_packet_counter_with_dup() == 1);
}

TEST_CASE("MQTT5 shared subscribe property needs a usable share name")
{
    // mqtt5_msg_subscribe() calls strlen(share_name) unconditionally once
    // is_share_subscribe is set, so these two must never reach the encoder.
    esp_mqtt5_subscribe_property_config_t no_name = {};
    no_name.is_share_subscribe = true;
    REQUIRE(validate_subscribe(no_name) == ESP_FAIL);
    esp_mqtt5_subscribe_property_config_t empty_name = {};
    empty_name.is_share_subscribe = true;
    empty_name.share_name = "";
    REQUIRE(validate_subscribe(empty_name) == ESP_FAIL);
    // Control: the same property with a share name is legal and must pass.
    esp_mqtt5_subscribe_property_config_t named = {};
    named.is_share_subscribe = true;
    named.share_name = "group";
    REQUIRE(validate_subscribe(named) == ESP_OK);
    // ... but only when the broker advertised shared-subscription support.
    REQUIRE(validate_subscribe(named, /*shared_available=*/false) == ESP_FAIL);
}

TEST_CASE("MQTT5 shared unsubscribe property needs a usable share name")
{
    esp_mqtt5_unsubscribe_property_config_t no_name = {};
    no_name.is_share_subscribe = true;
    REQUIRE(validate_unsubscribe(no_name) == ESP_FAIL);
    esp_mqtt5_unsubscribe_property_config_t named = {};
    named.is_share_subscribe = true;
    named.share_name = "group";
    REQUIRE(validate_unsubscribe(named) == ESP_OK);
    REQUIRE(validate_unsubscribe(named, /*shared_available=*/false) == ESP_FAIL);
}

TEST_CASE("MQTT5 rejects No Local on a shared subscription")
{
    // MQTT-3.8.3-4 forbids the combination; the broker answers with a
    // protocol-error DISCONNECT rather than a SUBACK.
    esp_mqtt5_subscribe_property_config_t property = {};
    property.is_share_subscribe = true;
    property.share_name = "group";
    property.no_local_flag = true;
    REQUIRE(validate_subscribe(property) == ESP_FAIL);
    // Control: No Local on a non-shared subscription is legal.
    esp_mqtt5_subscribe_property_config_t unshared = {};
    unshared.no_local_flag = true;
    REQUIRE(validate_subscribe(unshared) == ESP_OK);
}

TEST_CASE("MQTT5 subscribe retain_handle is limited to 0, 1, 2")
{
    esp_mqtt5_subscribe_property_config_t property = {};

    for (uint8_t handle = 0; handle <= 2; ++handle) {
        property.retain_handle = handle;
        REQUIRE(validate_subscribe(property) == ESP_OK);
    }

    property.retain_handle = 3;
    REQUIRE(validate_subscribe(property) == ESP_FAIL);
}

TEST_CASE("MQTT5 publish topic alias is bounded by the server maximum")
{
    esp_mqtt5_publish_property_config_t property = {};
    property.topic_alias = 11;
    REQUIRE(validate_publish(property, /*topic_alias_maximum=*/10) == ESP_FAIL);
    // Control: the maximum itself is a valid alias.
    property.topic_alias = 10;
    REQUIRE(validate_publish(property, /*topic_alias_maximum=*/10) == ESP_OK);
    // A server that advertised no alias support rejects every alias.
    property.topic_alias = 1;
    REQUIRE(validate_publish(property, /*topic_alias_maximum=*/0) == ESP_FAIL);
}

TEST_CASE("MQTT5 properties are rejected on a non-v5 connection")
{
    const esp_mqtt5_publish_property_config_t publish = {};
    const esp_mqtt5_subscribe_property_config_t subscribe = {};
    const esp_mqtt5_unsubscribe_property_config_t unsubscribe = {};
    REQUIRE(test_mqtt5_validate_publish_property(&publish, 10, MQTT_PROTOCOL_V_3_1_1) == ESP_FAIL);
    REQUIRE(test_mqtt5_validate_subscribe_property(&subscribe, true, MQTT_PROTOCOL_V_3_1_1) == ESP_FAIL);
    REQUIRE(test_mqtt5_validate_unsubscribe_property(&unsubscribe, true, MQTT_PROTOCOL_V_3_1_1) == ESP_FAIL);
    // A NULL property means "no properties" and is accepted on any version.
    REQUIRE(test_mqtt5_validate_publish_property(nullptr, 10, MQTT_PROTOCOL_V_3_1_1) == ESP_OK);
    REQUIRE(test_mqtt5_validate_subscribe_property(nullptr, true, MQTT_PROTOCOL_V_3_1_1) == ESP_OK);
    REQUIRE(test_mqtt5_validate_unsubscribe_property(nullptr, true, MQTT_PROTOCOL_V_3_1_1) == ESP_OK);
}

SCENARIO("MQTT5 per-message publish property does not consume the staged one")
{
    // Same mock preamble the mqtt_client host tests use to build a real client.
    int mtx = 0;
    int transport_list = 0;
    int transport = 0;
    int event_group = 0;
    esp_timer_get_time_IgnoreAndReturn(0);
    xQueueTakeMutexRecursive_IgnoreAndReturn(true);
    xQueueGiveMutexRecursive_IgnoreAndReturn(true);
    xQueueCreateMutex_ExpectAnyArgsAndReturn(reinterpret_cast<QueueHandle_t>(&mtx));
    xEventGroupCreate_IgnoreAndReturn(reinterpret_cast<EventGroupHandle_t>(&event_group));
    esp_transport_list_init_IgnoreAndReturn(reinterpret_cast<esp_transport_list_handle_t>(&transport_list));
    esp_transport_tcp_init_IgnoreAndReturn(reinterpret_cast<esp_transport_handle_t>(&transport));
    esp_transport_ssl_init_IgnoreAndReturn(reinterpret_cast<esp_transport_handle_t>(&transport));
    esp_transport_ws_init_IgnoreAndReturn(reinterpret_cast<esp_transport_handle_t>(&transport));
    esp_transport_ws_set_subprotocol_IgnoreAndReturn(ESP_OK);
    esp_transport_list_add_IgnoreAndReturn(ESP_OK);
    esp_transport_set_default_port_IgnoreAndReturn(ESP_OK);
    esp_event_loop_create_IgnoreAndReturn(ESP_OK);
    esp_event_loop_delete_IgnoreAndReturn(ESP_OK);
    esp_transport_list_destroy_IgnoreAndReturn(ESP_OK);
    esp_transport_destroy_IgnoreAndReturn(ESP_OK);
    xTaskCreatePinnedToCore_IgnoreAndReturn(pdTRUE);
    vEventGroupDelete_Ignore();
    vQueueDelete_Ignore();
    GIVEN("A v5 client with a staged publish property") {
        esp_mqtt_client_config_t config{};
        config.broker.address.uri = "mqtt://1.1.1.1";
        config.session.protocol_ver = MQTT_PROTOCOL_V_5;
        auto client = unique_mqtt_client{esp_mqtt_client_init(&config)};
        REQUIRE(client != nullptr);
        // The client stays disconnected on purpose: the publish still runs
        // through make_publish(), which is where the staged property is
        // consumed, and only then bails out at the "not connected" check.
        const esp_mqtt5_publish_property_config_t staged = { .message_expiry_interval = 60 };
        REQUIRE(esp_mqtt5_client_set_publish_property(client.get(), &staged) == ESP_OK);
        REQUIRE(test_mqtt5_staged_publish_property(client.get()) == &staged);
        WHEN("A per-message property is published") {
            const esp_mqtt5_publish_property_config_t per_message = { .message_expiry_interval = 5 };
            esp_mqtt_client_publish5(client.get(), "topic", "data", 0, 0, 0, &per_message);
            THEN("The staged property is left for the next plain publish") {
                // Otherwise a publish5() on one task silently strips the
                // properties off a publish() another task already staged.
                REQUIRE(test_mqtt5_staged_publish_property(client.get()) == &staged);
            }
        }
        WHEN("A plain publish is made") {
            esp_mqtt_client_publish(client.get(), "topic", "data", 0, 0, 0);
            THEN("The staged one-shot property is consumed as before") {
                REQUIRE(test_mqtt5_staged_publish_property(client.get()) == nullptr);
            }
        }
    }
}

TEST_CASE("MQTT5 CONNECT authentication method and data are copied into the client config")
{
    auto client = make_mqtt5_client();
    REQUIRE(client != nullptr);
    char method[] = "SCRAM-SHA-256";
    esp_mqtt5_connection_property_config_t property = {};
    property.authentication_method = method;
    property.authentication_data = auth_data;
    property.authentication_data_len = sizeof(auth_data);
    REQUIRE(esp_mqtt5_client_set_connect_property(client.get(), &property) == ESP_OK);
    const char *stored_method = test_mqtt5_connect_auth_method(client.get());
    const char *stored_data = test_mqtt5_connect_auth_data(client.get());
    // The caller's buffers are stack locals that die with this test, so a
    // pointer the client kept instead of copying would dangle from here on.
    // Identity is therefore part of the contract, not an implementation detail.
    REQUIRE(stored_method != nullptr);
    REQUIRE(stored_method != method);
    REQUIRE(stored_data != nullptr);
    REQUIRE(stored_data != auth_data);
    require_auth_stored(client.get(), method);
}

TEST_CASE("MQTT5 CONNECT authentication values are replaced by a second call")
{
    auto client = make_mqtt5_client();
    REQUIRE(client != nullptr);
    char first_method[] = "SCRAM-SHA-256";
    char second_method[] = "SCRAM-SHA-512";
    const char second_data[] = {'\x10', '\x00', '\x20'};
    // First call: a different method and a payload of a different length, so
    // any state left behind by it is visible in the assertions below.
    {
        esp_mqtt5_connection_property_config_t property = {};
        property.authentication_method = first_method;
        property.authentication_data = auth_data;
        property.authentication_data_len = sizeof(auth_data);
        REQUIRE(esp_mqtt5_client_set_connect_property(client.get(), &property) == ESP_OK);
    }
    require_auth_stored(client.get(), first_method);
    esp_mqtt5_connection_property_config_t property = {};
    property.authentication_method = second_method;
    property.authentication_data = second_data;
    property.authentication_data_len = sizeof(second_data);
    // The previous copies are freed here; ASan reports a double free or an
    // invalid one, and LSan a copy that was dropped instead of released.
    REQUIRE(esp_mqtt5_client_set_connect_property(client.get(), &property) == ESP_OK);
    const char *stored_method = test_mqtt5_connect_auth_method(client.get());
    const char *stored_data = test_mqtt5_connect_auth_data(client.get());
    REQUIRE(stored_method != nullptr);
    REQUIRE(std::strcmp(stored_method, second_method) == 0);
    REQUIRE(stored_data != nullptr);
    REQUIRE(test_mqtt5_connect_auth_data_len(client.get()) == sizeof(second_data));
    REQUIRE(std::memcmp(stored_data, second_data, sizeof(second_data)) == 0);
}

TEST_CASE("MQTT5 CONNECT authentication data without a method is rejected")
{
    auto client = make_mqtt5_client();
    REQUIRE(client != nullptr);
    esp_mqtt5_connection_property_config_t property = {};
    property.authentication_data = auth_data;
    property.authentication_data_len = sizeof(auth_data);
    // MQTT 5.0 3.1.2.11.10: it is a Protocol Error to send Authentication Data
    // with no Authentication Method.
    REQUIRE(esp_mqtt5_client_set_connect_property(client.get(), &property) == ESP_ERR_INVALID_ARG);
    // The rejected call stored nothing, so a later connect cannot send data
    // whose method was never set.
    REQUIRE(test_mqtt5_connect_auth_data(client.get()) == nullptr);
    REQUIRE(test_mqtt5_connect_auth_data_len(client.get()) == 0);
    REQUIRE(test_mqtt5_connect_auth_method(client.get()) == nullptr);
    // Control: no data is not the same as data without a method.
    property.authentication_data_len = 0;
    REQUIRE(esp_mqtt5_client_set_connect_property(client.get(), &property) == ESP_OK);
    // Control: the same data is accepted once a method says how to read it.
    property.authentication_data = auth_data;
    property.authentication_data_len = sizeof(auth_data);
    property.authentication_method = "SCRAM-SHA-256";
    REQUIRE(esp_mqtt5_client_set_connect_property(client.get(), &property) == ESP_OK);
    require_auth_stored(client.get(), "SCRAM-SHA-256");
}

TEST_CASE("MQTT5 CONNECT property accepts a NULL property as a no-op")
{
    auto client = make_mqtt5_client();
    REQUIRE(client != nullptr);
    // A caller that passes NULL asks for "no properties". The validation for
    // data-without-a-method used to sit above the `if (connect_property)`
    // guard, so this call dereferenced NULL.
    REQUIRE(esp_mqtt5_client_set_connect_property(client.get(), nullptr) == ESP_OK);
    char method[] = "SCRAM-SHA-256";
    esp_mqtt5_connection_property_config_t property = {};
    property.authentication_method = method;
    property.authentication_data = auth_data;
    property.authentication_data_len = sizeof(auth_data);
    REQUIRE(esp_mqtt5_client_set_connect_property(client.get(), &property) == ESP_OK);
    REQUIRE(esp_mqtt5_client_set_connect_property(client.get(), nullptr) == ESP_OK);
    // ... and it leaves what was configured before it untouched.
    require_auth_stored(client.get(), method);
}

TEST_CASE("MQTT5 CONNECT authentication copies are released when the client is destroyed")
{
    // LeakSanitizer runs at process exit, so a copy this test leaves behind
    // fails the run on its own; a double free would abort in this destructor.
    auto client = make_mqtt5_client();
    REQUIRE(client != nullptr);
    esp_mqtt5_connection_property_config_t property = {};
    property.authentication_method = "SCRAM-SHA-256";
    property.authentication_data = auth_data;
    property.authentication_data_len = sizeof(auth_data);
    REQUIRE(esp_mqtt5_client_set_connect_property(client.get(), &property) == ESP_OK);
    esp_mqtt_client_destroy(client.release());
}
