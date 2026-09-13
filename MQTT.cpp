#include <WiFi.h>
#include <PubSubClient.h>
#include <ArduinoJson.h>
#include <esp_task_wdt.h>
#include "Log.h"
#include "ConfigSettings.h"
#include "MQTT.h"
#include "Somfy.h"
#include "Network.h"
#include "Utils.h"

WiFiClient tcpClient;
PubSubClient mqttClient(tcpClient);

#define MQTT_MAX_RESPONSE 2048
static char g_content[MQTT_MAX_RESPONSE];

extern ConfigSettings settings;
extern SomfyShadeController somfy;
extern Network net;
extern rebootDelay_t rebootDelay;


bool MQTTClass::begin() {
  this->suspended = false;
  return true;
}
bool MQTTClass::end() {
  this->suspended = true;
  this->disconnect();
  return true;
}
void MQTTClass::reset() {
  this->disconnect();
  this->lastConnect = 0;
  this->connect();
}
bool MQTTClass::loop() {
  if(settings.MQTT.enabled && !rebootDelay.reboot && !this->suspended && !mqttClient.connected()) {
    esp_task_wdt_reset();
    if(!this->connected() && net.connected()) this->connect();
  }
  esp_task_wdt_reset();
  if(settings.MQTT.enabled) mqttClient.loop();
  return true;
}
void MQTTClass::receive(const char *topic, byte*payload, uint32_t length) {
  esp_task_wdt_reset(); // Make sure we do not reboot here.
  LOG_I("MQTT Topic:");
  LOG_I(topic);
  LOG_I(" payload:");
  for(uint32_t i=0; i<length; i++)
    LOG_I((char)payload[i]);
  LOG_ILN();

  // We need to start at the last slash in the data
  size_t len = strlen(topic);
  if(len == 0) return;
  uint8_t slashes = 0;
  size_t ndx = len - 1;
  while(ndx > 0) {
    if(topic[ndx] == '/') slashes++;
    if(slashes == 4) break;
    ndx--;
  }
  char entityId[4];
  char command[32];
  char entityType[7];
  char value[10];
  memset(command, 0x00, sizeof(command));
  memset(entityId, 0x00, sizeof(entityId));
  memset(entityType, 0x00, sizeof(entityType));
  memset(value, 0x00, sizeof(value));
  uint8_t i = 0;
  while(topic[ndx] == '/' && ndx < len) ndx++;
  while(ndx < len) {
    if(topic[ndx] != '/' && i < sizeof(entityType) - 1)
      entityType[i++] = topic[ndx];
    ndx++;
    if(topic[ndx] == '/') break;
  }
  i = 0;
  while(topic[ndx] == '/' && ndx < len) ndx++;
  while(ndx < len) {
    if(topic[ndx] != '/' && i < sizeof(entityId) - 1)
      entityId[i++] = topic[ndx];
    ndx++;
    if(topic[ndx] == '/') break;
  }
  i = 0;
  while(topic[ndx] == '/' && ndx < len) ndx++;
  while(ndx < len) {
    if(topic[ndx] != '/' && i < sizeof(command) - 1)
      command[i++] = topic[ndx];
    ndx++;
    if(topic[ndx] == '/') break;
  }
  for(uint32_t j = 0; j < length && j < sizeof(value) - 1; j++)
    value[j] = payload[j];
  
  LOG_I("MQTT type:[");
  LOG_I(entityType);
  LOG_I("] command:[");
  LOG_I(command);
  LOG_I("] entityId:");
  LOG_I(entityId);
  LOG_I(" value:");
  LOG_ILN(value);
  if(strncmp(entityType, "shades", sizeof(entityType)) == 0) {
    SomfyShade* shade = somfy.getShadeById(atoi(entityId));
    if (shade) {
      int val = atoi(value);
      if(strncmp(command, "target", sizeof(command)) == 0) {
        if(val >= 0 && val <= 100)
          shade->moveToTarget(shade->transformPosition(atoi(value)));
      }
      if(strncmp(command, "tiltTarget", sizeof(command)) == 0) {
        if(val >= 0 && val <= 100)
          shade->moveToTiltTarget(atoi(value));
      }
      else if(strncmp(command, "direction", sizeof(command)) == 0) {
        if(val < 0)
          shade->sendCommand(somfy_commands::Up);
        else if(val > 0)
          shade->sendCommand(somfy_commands::Down);
        else
          shade->sendCommand(somfy_commands::My);
      }
      else if(strncmp(command, "mypos", sizeof(command)) == 0) {
        if(val >= 0 && val <= 100)
          shade->setMyPosition(val);
      }
      else if(strncmp(command, "myTiltPos", sizeof(command)) == 0) {
        if(val >= 0 && val <= 100)
          shade->setMyPosition(shade->myPos, val);
      }
      else if(strncmp(command, "sunFlag", sizeof(command)) == 0) {
        if(val > 0) shade->sendCommand(somfy_commands::SunFlag);
        else shade->sendCommand(somfy_commands::Flag);
      }
      else if(strncmp(command, "position", sizeof(command)) == 0) {
        if(val >= 0 && val <= 100) {
          shade->target = shade->currentPos = shade->transformPosition((float)val);
          shade->emitState();
        }
      }
      else if(strncmp(command, "tiltPosition", sizeof(command)) == 0) {
        if(val >= 0 && val <= 100) {
          shade->tiltTarget = shade->currentTiltPos = (float)val;
          shade->emitState();
        }
      }
      else if(strncmp(command, "sunny", sizeof(command)) == 0) {
        if(val >= 0) shade->sendSensorCommand(-1, val, shade->repeats);
      }
      else if(strncmp(command, "windy", sizeof(command)) == 0) {
        if(val >= 0) shade->sendSensorCommand(val, -1, shade->repeats);
      }
    }
  }
  else if(strncmp(entityType, "groups", sizeof(entityType)) == 0) {
    SomfyGroup* group = somfy.getGroupById(atoi(entityId));
    if (group) {
      int val = atoi(value);
      if(strncmp(command, "direction", sizeof(command)) == 0) {
        if(val < 0)
          group->sendCommand(somfy_commands::Up);
        else if(val > 0)
          group->sendCommand(somfy_commands::Down);
        else
          group->sendCommand(somfy_commands::My);
      }
      else if(strncmp(command, "sunFlag", sizeof(command)) == 0) {
        // Même sens que pour les volets : 1 active le mode soleil (SunFlag), 0 le désactive (Flag).
        if(val > 0)
          group->sendCommand(somfy_commands::SunFlag);
        else
          group->sendCommand(somfy_commands::Flag);
      }
      else if(strncmp(command, "sunny", sizeof(command)) == 0) {
        if(val >= 0) group->sendSensorCommand(-1, val, group->repeats);
      }
      else if(strncmp(command, "windy", sizeof(command)) == 0) {
        if(val >= 0) group->sendSensorCommand(val, -1, group->repeats);
      }
    }
  }
  esp_task_wdt_reset(); // Make sure we do not reboot here.
}
// Topics de commande souscrits : une seule liste pour subscribe et unsubscribe.
static const char *const kCommandTopics[] = {
  "shades/+/target/set", "shades/+/tiltTarget/set", "shades/+/direction/set", "shades/+/mypos/set",
  "shades/+/myTiltPos/set", "shades/+/sunFlag/set", "shades/+/sunny/set", "shades/+/windy/set",
  "shades/+/position/set", "shades/+/tiltPosition/set",
  "groups/+/direction/set", "groups/+/sunFlag/set", "groups/+/sunny/set", "groups/+/windy/set"
};
bool MQTTClass::connect() {
  esp_task_wdt_reset(); // Make sure we do not reboot here.
  if(mqttClient.connected()) {
    if(!settings.MQTT.enabled || this->suspended)
      return this->disconnect();
    else
      return true;
  }
  if(settings.MQTT.enabled && !this->suspended) {
    // Reconnexion avec délai croissant (10 s puis doublé jusqu'à 5 min) : un broker absent ne doit pas
    // geler loop() toutes les 10 s le temps d'une résolution DNS et d'un connect() bloquant.
    if(!elapsed(this->lastConnect, this->reconnectDelay)) return false;
    uint64_t mac = ESP.getEfuseMac();
    snprintf(this->clientId, sizeof(this->clientId), "client-%08x%08x", (uint32_t)((mac >> 32) & 0xFFFFFFFF), (uint32_t)(mac & 0xFFFFFFFF));
    if(strlen(settings.MQTT.protocol) > 0 && strlen(settings.MQTT.hostname) > 0) {
      mqttClient.setServer(settings.MQTT.hostname, settings.MQTT.port);
      mqttClient.setSocketTimeout(MQTT_SOCKET_TIMEOUT_S);
      char lwtTopic[128] = "status";
      if(strlen(settings.MQTT.rootTopic) > 0)
        snprintf(lwtTopic, sizeof(lwtTopic), "%s/status", settings.MQTT.rootTopic);
      esp_task_wdt_reset();
      if(mqttClient.connect(this->clientId, settings.MQTT.username, settings.MQTT.password, lwtTopic, 0, true, "offline")) {
        LOG_I("Successfully connected MQTT client ");
        LOG_ILN(this->clientId);
        this->publish("status", "online", true);
        this->publish("ipAddress", settings.IP.ip.toString().c_str(), true);
        this->publish("host", settings.hostname, true);
        this->publish("firmware", settings.fwVersion.name, true);
        this->publish("serverId", settings.serverId, true);
        this->publish("mac", net.mac.c_str());
        somfy.publish();
        mqttClient.setCallback(MQTTClass::receive);
        for(const char *topic : kCommandTopics) this->subscribe(topic);
        LOG_ILN("MQTT Startup Completed");
        esp_task_wdt_reset();
        this->lastConnect = millis();
        this->reconnectDelay = MQTT_RECONNECT_MIN_MS;
        return true;
      }
      else {
        LOG_E("MQTT Connection failed for: ");
        LOG_ELN(mqttClient.state());
        this->lastConnect = millis();
        this->reconnectDelay = min(this->reconnectDelay * 2, (uint32_t)MQTT_RECONNECT_MAX_MS);
        return false;
      }
    }
    else
      return true;
  }
  return true;
}
bool MQTTClass::disconnect() {
  if(mqttClient.connected()) {
    for(const char *topic : kCommandTopics) this->unsubscribe(topic);
    mqttClient.disconnect();
  }
  return true;
}
bool MQTTClass::unsubscribe(const char *topic) {
  if(mqttClient.connected()) {
    char top[128];
    if(strlen(settings.MQTT.rootTopic) > 0)
      snprintf(top, sizeof(top), "%s/%s", settings.MQTT.rootTopic, topic);
    else
      strlcpy(top, topic, sizeof(top));
    LOG_I("MQTT Unsubscribed from:");
    LOG_ILN(top);
    return mqttClient.unsubscribe(top);
  }
  return true;
}
bool MQTTClass::subscribe(const char *topic) {
  if(mqttClient.connected()) {
    esp_task_wdt_reset(); // Make sure we do not reboot here.
    char top[128];
    if(strlen(settings.MQTT.rootTopic) > 0)
      snprintf(top, sizeof(top), "%s/%s", settings.MQTT.rootTopic, topic);
    else
      strlcpy(top, topic, sizeof(top));
    LOG_I("MQTT Subscribed to:");
    LOG_ILN(top);
    return mqttClient.subscribe(top);
  }
  return true;
}
bool MQTTClass::publish(const char *topic, const char *payload, bool retain) {
  if(mqttClient.connected()) {
    char top[128];
    if(strlen(settings.MQTT.rootTopic) > 0)
      snprintf(top, sizeof(top), "%s/%s", settings.MQTT.rootTopic, topic);
    else
      strlcpy(top, topic, sizeof(top));
    esp_task_wdt_reset(); // Make sure we do not reboot here.
    mqttClient.publish(top, payload, retain);
    return true;
  }
  return false;
}
bool MQTTClass::publish(const char *topic, uint32_t val, bool retain) {
  snprintf(g_content, sizeof(g_content), "%u", val);
  return this->publish(topic, g_content, retain);
}
bool MQTTClass::unpublish(const char *topic) {
  if(mqttClient.connected()) {
    char top[128];
    if(strlen(settings.MQTT.rootTopic) > 0)
      snprintf(top, sizeof(top), "%s/%s", settings.MQTT.rootTopic, topic);
    else
      strlcpy(top, topic, sizeof(top));
    esp_task_wdt_reset(); // Make sure we do not reboot here.
    mqttClient.publish(top, (const uint8_t *)"", 0, true);
    return true;
  }
  return false;

//  mqttClient.beginPublish(topic, 0, true);
//  mqttClient.endPublish();
}

bool MQTTClass::publishBuffer(const char *topic, uint8_t *data, uint16_t len, bool retain) {
  size_t res;
  uint16_t offset = 0;
  uint16_t to_write = len;
  uint16_t buff_len;
  esp_task_wdt_reset(); // Make sure we do not reboot here.
  mqttClient.beginPublish(topic, len, retain);
  do { 
    buff_len = to_write;
    if(buff_len > 128) buff_len = 128;
    res = mqttClient.write(data+offset, buff_len);
    offset += buff_len;
    to_write -= buff_len;
  } while(res == buff_len && to_write > 0);
  mqttClient.endPublish();
  return true;
}
bool MQTTClass::publishDisco(const char *topic, JsonObject &obj, bool retain) {
  serializeJson(obj, g_content, sizeof(g_content));
  this->publishBuffer(topic, (uint8_t *)g_content, strlen(g_content), retain);
  return true;
}
bool MQTTClass::publish(const char *topic, int8_t val, bool retain) {
  snprintf(g_content, sizeof(g_content), "%d", val);
  return this->publish(topic, g_content, retain);
}
bool MQTTClass::publish(const char *topic, uint8_t val, bool retain) {
  snprintf(g_content, sizeof(g_content), "%u", val);
  return this->publish(topic, g_content, retain);
}
bool MQTTClass::publish(const char *topic, uint16_t val, bool retain) {
  snprintf(g_content, sizeof(g_content), "%u", val);
  return this->publish(topic, g_content, retain);
}
bool MQTTClass::publish(const char *topic, bool val, bool retain) {
  snprintf(g_content, sizeof(g_content), "%s", val ? "true" : "false");
  return this->publish(topic, g_content, retain);
}
bool MQTTClass::connected() {
  if(settings.MQTT.enabled) return mqttClient.connected();
  return false;
}
