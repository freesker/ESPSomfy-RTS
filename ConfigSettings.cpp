#include <Arduino.h>
#include "Log.h"
#include <LittleFS.h>       // https://github.com/espressif/arduino-esp32/tree/master/libraries/LittleFS
#include <time.h>
#include <WiFi.h>
#include <Preferences.h>
#include "ConfigSettings.h"
#include "Utils.h"
#include "esp_chip_info.h"

Preferences pref;

void restore_options_t::fromJSON(JsonObject &obj) {
  if(obj.containsKey("shades")) this->shades = obj["shades"];
  if(obj.containsKey("settings")) this->settings = obj["settings"];
  if(obj.containsKey("network")) this->network = obj["network"];
  if(obj.containsKey("transceiver")) this->transceiver = obj["transceiver"];
  if(obj.containsKey("repeaters")) this->repeaters = obj["repeaters"];
  if(obj.containsKey("mqtt")) this->mqtt = obj["mqtt"];
}
int8_t appver_t::compare(appver_t &ver) {
  if(this->major == ver.major && this->minor == ver.minor && this->build == ver.build) return 0;
  if(this->major > ver.major) return 1;
  else if(this->major < ver.major) return -1;
  else {
    if(this->minor > ver.minor) return 1;
    else if(this->minor < ver.minor) return -1;
    else {
      if(this->build > ver.build) return 1;
      else if(this->build < ver.build) return -1;
    }
  }
  return 0;
}
void appver_t::copy(appver_t &ver) {
  strcpy(this->name, ver.name);
  this->major = ver.major;
  this->minor = ver.minor;
  this->build = ver.build;
  strcpy(this->suffix, ver.suffix);
}
void appver_t::parse(const char *ver) {
  // Now lets parse this pig.
  memset(this, 0x00, sizeof(appver_t));
  strlcpy(this->name, ver, sizeof(this->name));
  char num[3];
  uint8_t i = 0;
  memset(num, 0x00, sizeof(num));
  for(uint8_t j = 0; j < 3 && i < strlen(ver);) {
    char ch = ver[i++];
    // Trim off all the prefix.
    if(ch == '.') break;
    if(!isdigit(ch)) continue;
    if(ch != '.')
      num[j++] = ch;
    else
      break;
  }
  this->major = static_cast<uint8_t>(atoi(num) & 0xFF);
  memset(num, 0x00, sizeof(num));
  for(uint8_t j = 0; j < 3 && i < strlen(ver);) {
    char ch = ver[i++];
    if(ch != '.')
      num[j++] = ch;
    else
      break;
  }
  this->minor = static_cast<uint8_t>(atoi(num) & 0xFF);
  memset(num, 0x00, sizeof(num));
  for(uint8_t j = 0; j < 3 && i < strlen(ver);) {
    char ch = ver[i++];
    if(!isdigit(ch)) break;
    if(ch != '.')
      num[j++] = ch;
    else
      break;
  }
  this->build = static_cast<uint8_t>(atoi(num) & 0xFF);
  if(strlen(ver) < i) strlcpy(this->suffix, &ver[i], sizeof(this->suffix));
}
bool appver_t::toJSON(JsonObject &obj) {
  obj["name"] = this->name;
  obj["major"] = this->major;
  obj["minor"] = this->minor;
  obj["build"] = this->build;
  obj["suffix"] = this->suffix;
  return true;
}
void appver_t::toJSON(JsonResponse &json) {
  json.addElem("name", this->name);
  json.addElem("major", this->major);
  json.addElem("minor", this->minor);
  json.addElem("build", this->build);
  json.addElem("suffix", this->suffix);
}
void appver_t::toJSON(JsonSockEvent *json) {
  json->addElem("name", this->name);
  json->addElem("major", this->major);
  json->addElem("minor", this->minor);
  json->addElem("build", this->build);
  json->addElem("suffix", this->suffix);
}

bool BaseSettings::load() { return true; }
bool BaseSettings::parseSecretString(JsonObject &obj, const char *prop, char *pdest, size_t size, bool allowEmpty) {
  if(!obj.containsKey(prop) || !obj[prop].is<const char*>()) return false;
  const char *val = obj[prop].as<const char*>();
  if(strcmp(val, SECRET_MASK) == 0) return false;
  if(!allowEmpty && strlen(val) == 0) return false;
  strlcpy(pdest, val, size);
  return true;
}
// ArduinoJson renvoie un pointeur nul pour une valeur qui n'est pas une chaîne (null, nombre, objet) :
// strlcpy plantait alors l'appareil sur un simple {"hostname":null}.
bool BaseSettings::parseValueString(JsonObject &obj, const char *prop, char *pdest, size_t size) {
  if(!obj[prop].is<const char*>()) return false;
  strlcpy(pdest, obj[prop].as<const char*>(), size);
  return true;
}
bool BaseSettings::parseIPAddress(JsonObject &obj, const char *prop, IPAddress *pdest) {
  if(!obj[prop].is<const char*>()) return false;
  char buff[16];
  strlcpy(buff, obj[prop].as<const char*>(), sizeof(buff));
  IPAddress parsed;
  if(!parsed.fromString(buff)) return false;
  *pdest = parsed;
  return true;
}
int BaseSettings::parseValueInt(JsonObject &obj, const char *prop, int defVal) {
  if(obj.containsKey(prop)) return obj[prop]; 
  return defVal;
}
double BaseSettings::parseValueDouble(JsonObject &obj, const char *prop, double defVal) {
  if(obj.containsKey(prop)) return obj[prop];
  return defVal;
}
bool ConfigSettings::begin() {
  uint32_t chipId = 0;
  esp_chip_info_t ci;
  esp_chip_info(&ci);
  switch(ci.model) {
    case esp_chip_model_t::CHIP_ESP32:
      strcpy(this->chipModel, "");
      break;
    case esp_chip_model_t::CHIP_ESP32S3:
      strcpy(this->chipModel, "s3");
      break;
    case esp_chip_model_t::CHIP_ESP32S2:
      strcpy(this->chipModel, "s2");
      break;
    case esp_chip_model_t::CHIP_ESP32C3:
      strcpy(this->chipModel, "c3");
      break;
//    case esp_chip_model_t::CHIP_ESP32C2:
//      strcpy(this->chipModel, "c2");
//      break;
//    case esp_chip_model_t::CHIP_ESP32C6:
//      strcpy(this->chipModel, "c6");
//      break;
    case esp_chip_model_t::CHIP_ESP32H2:
      strcpy(this->chipModel, "h2");
      break;
    default:
      sprintf(this->chipModel, "UNK%d", static_cast<int>(ci.model));
      break;
  }
  LOG_DF("Chip Model ESP32-%s\n", this->chipModel);
  this->fwVersion.parse(FW_VERSION);
  uint64_t mac = ESP.getEfuseMac();
  for(int i=0; i<17; i=i+8) {
    chipId |= ((mac >> (40 - i)) & 0xff) << i;
  }
  snprintf_P(this->serverId, sizeof(this->serverId), "%02X%02X%02X",
    (uint16_t)((chipId >> 16) & 0xff),
    (uint16_t)((chipId >> 8) & 0xff),
    (uint16_t)chipId & 0xff);
  this->load();
  this->Security.begin();
  this->IP.begin();
  this->WIFI.begin();
  this->Ethernet.begin();
  this->NTP.begin();
  this->MQTT.begin();
  this->print();
  return true;
}
bool ConfigSettings::load() {
  this->fwVersion.parse(FW_VERSION);
  this->getAppVersion();
  pref.begin("CFG");
  pref.getString("hostname", this->hostname, sizeof(this->hostname));
  this->ssdpBroadcast = pref.getBool("ssdpBroadcast", true);
  this->checkForUpdate = pref.getBool("checkForUpdate", true);
  this->connType = static_cast<conn_types_t>(pref.getChar("connType", 0x00));
  //LOG_DF("Preference GFG Free Entries: %d\n", pref.freeEntries());
  pref.end();
  if(this->connType == conn_types_t::unset) {
    // We are doing this to convert the data from previous versions.
    this->connType = conn_types_t::wifi;
    pref.begin("WIFI");
    pref.getString("hostname", this->hostname, sizeof(this->hostname));
    this->ssdpBroadcast = pref.getBool("ssdpBroadcast", true);
    pref.remove("hostname");
    pref.remove("ssdpBroadcast");
    pref.end();
    this->save();    
  }
  return true;
}
bool ConfigSettings::getAppVersion() {
  char app[15];
  if(!LittleFS.exists("/appversion")) return false;
  File f = LittleFS.open("/appversion", "r");
  memset(app, 0x00, sizeof(app));
  f.read((uint8_t *)app, sizeof(app) - 1);
  f.close();
  _trim(app);
  this->appVersion.parse(app);
  return true;
}
bool ConfigSettings::save() {
  pref.begin("CFG");
  pref.putString("hostname", this->hostname);
  pref.putBool("ssdpBroadcast", this->ssdpBroadcast);
  pref.putChar("connType", static_cast<uint8_t>(this->connType));
  pref.putBool("checkForUpdate", this->checkForUpdate);
  pref.end();
  return true;
}
bool ConfigSettings::toJSON(JsonObject &obj) {
  obj["ssdpBroadcast"] = this->ssdpBroadcast;
  obj["hostname"] = this->hostname;
  obj["connType"] = static_cast<uint8_t>(this->connType);
  obj["chipModel"] = this->chipModel;
  obj["checkForUpdate"] = this->checkForUpdate;
  return true;
}
void ConfigSettings::toJSON(JsonResponse &json) {
  json.addElem("ssdpBroadcast", this->ssdpBroadcast);
  json.addElem("hostname", this->hostname);
  json.addElem("connType", static_cast<uint8_t>(this->connType));
  json.addElem("chipModel", this->chipModel);
  json.addElem("checkForUpdate", this->checkForUpdate);
}

bool ConfigSettings::requiresAuth() { return this->Security.type != security_types::None; }
bool ConfigSettings::fromJSON(JsonObject &obj) {
    if(obj.containsKey("ssdpBroadcast")) this->ssdpBroadcast = obj["ssdpBroadcast"];
    if(obj.containsKey("hostname")) this->parseValueString(obj, "hostname", this->hostname, sizeof(this->hostname));
    if(obj.containsKey("connType")) this->connType = static_cast<conn_types_t>(obj["connType"].as<uint8_t>());
    if(obj.containsKey("checkForUpdate")) this->checkForUpdate = obj["checkForUpdate"];
    return true;
}
void ConfigSettings::print() {
  this->Security.print();
  LOG_DF("Connection Type: %u\n", (unsigned int) this->connType);
  this->NTP.print();
  if(this->connType == conn_types_t::wifi || this->connType == conn_types_t::unset) this->WIFI.print();
  if(this->connType == conn_types_t::ethernet || this->connType == conn_types_t::ethernetpref) this->Ethernet.print();
}
void ConfigSettings::emitSockets() {}
void ConfigSettings::emitSockets(uint8_t num) {}
uint16_t ConfigSettings::calcSettingsRecSize() {
  return strlen(this->fwVersion.name) + 3 
    + strlen(this->hostname) + 3
    + strlen(this->NTP.ntpServer) + 3
    + strlen(this->NTP.posixZone) + 3
    + 6  // ssdpbroadcast
    + 6; // updateCheck
}
uint16_t ConfigSettings::calcNetRecSize() {
  return 4 // connType
    + 6 // dhcp
    + this->IP.ip.toString().length() + 3
    + this->IP.gateway.toString().length() + 3
    + this->IP.subnet.toString().length() + 3
    + this->IP.dns1.toString().length() + 3
    + this->IP.dns2.toString().length() + 3
    + strlen(this->MQTT.protocol) + 3
    + strlen(this->MQTT.hostname) + 3
    + 6 // MQTT Port
    + 6 // PubDisco
    + strlen(this->MQTT.rootTopic) + 3
    + strlen(this->MQTT.discoTopic) + 3
    + 4 // ETH.boardType
    + 4 // ETH.phyType
    + 4 // ETH.clkMode
    + 5 // ETH.phyAddress
    + 5 // ETH.PWRPin
    + 5 // ETH.MDCPin
    + 5; // ETH.MDIOPin
}
bool MQTTSettings::begin() {
  this->load();
  return true;
}
void MQTTSettings::toJSON(JsonResponse &json) {
  json.addElem("enabled", this->enabled);
  json.addElem("pubDisco", this->pubDisco);
  json.addElem("protocol", this->protocol);
  json.addElem("hostname", this->hostname);
  json.addElem("port", (uint32_t)this->port);
  json.addElem("username", this->username);
  json.addElem("password", strlen(this->password) > 0 ? SECRET_MASK : "");
  json.addElem("rootTopic", this->rootTopic);
  json.addElem("discoTopic", this->discoTopic);
}

bool MQTTSettings::toJSON(JsonObject &obj) {
  obj["enabled"] = this->enabled;
  obj["pubDisco"] = this->pubDisco;
  obj["protocol"] = this->protocol;
  obj["hostname"] = this->hostname;
  obj["port"] = this->port;
  obj["username"] = this->username;
  obj["password"] = strlen(this->password) > 0 ? SECRET_MASK : "";
  obj["rootTopic"] = this->rootTopic;
  obj["discoTopic"] = this->discoTopic;
  return true;
}
bool MQTTSettings::fromJSON(JsonObject &obj) {
  if(obj.containsKey("enabled")) this->enabled = obj["enabled"];
  if(obj.containsKey("pubDisco")) this->pubDisco = obj["pubDisco"];
  this->parseValueString(obj, "protocol", this->protocol, sizeof(this->protocol));
  this->parseValueString(obj, "hostname", this->hostname, sizeof(this->hostname));
  this->parseValueString(obj, "username", this->username, sizeof(this->username));
  this->parseSecretString(obj, "password", this->password, sizeof(this->password));
  this->parseValueString(obj, "rootTopic", this->rootTopic, sizeof(this->rootTopic));
  this->parseValueString(obj, "discoTopic", this->discoTopic, sizeof(this->discoTopic));
  if(obj.containsKey("port")) this->port = obj["port"];
  return true;
}
bool MQTTSettings::save() {
  pref.begin("MQTT");
  pref.clear();
  pref.putString("protocol", this->protocol);
  pref.putString("hostname", this->hostname);
  pref.putShort("port", this->port);
  pref.putString("username", this->username);
  pref.putString("password", this->password);
  pref.putString("rootTopic", this->rootTopic);
  pref.putBool("enabled", this->enabled);
  pref.putBool("pubDisco", this->pubDisco);
  pref.putString("discoTopic", this->discoTopic);
  pref.end();
  return true;
}
bool MQTTSettings::load() {
  pref.begin("MQTT");
  pref.getString("protocol", this->protocol, sizeof(this->protocol));
  pref.getString("hostname", this->hostname, sizeof(this->hostname));
  this->port = pref.getShort("port", 1883);
  pref.getString("username", this->username, sizeof(this->username));
  pref.getString("password", this->password, sizeof(this->password));
  pref.getString("rootTopic", this->rootTopic, sizeof(this->rootTopic));
  this->enabled = pref.getBool("enabled", false);
  this->pubDisco = pref.getBool("pubDisco", false);
  pref.getString("discoTopic", this->discoTopic, sizeof(this->discoTopic));
  pref.end();
  return true;
}
bool ConfigSettings::toJSON(DynamicJsonDocument &doc) {
  doc["fwVersion"] = this->fwVersion.name;
  JsonObject objWIFI = doc.createNestedObject("WIFI");
  this->WIFI.toJSON(objWIFI);
  JsonObject objNTP = doc.createNestedObject("NTP");
  this->NTP.toJSON(objNTP);
  JsonObject objMQTT = doc.createNestedObject("MQTT");
  this->MQTT.toJSON(objMQTT);
  return true;
}
bool NTPSettings::begin() {
  this->load();
  this->apply();
  return true;
}
bool NTPSettings::save() {
  pref.begin("NTP");
  pref.clear();
  pref.putString("ntpServer", this->ntpServer);
  pref.putString("posixZone", this->posixZone);
  pref.end();
  return this->apply();
}
bool NTPSettings::load() {
  pref.begin("NTP");
  pref.getString("ntpServer", this->ntpServer, sizeof(this->ntpServer));
  pref.getString("posixZone", this->posixZone, sizeof(this->posixZone));
  pref.end();
  return true;
}
void NTPSettings::print() {
  LOG_DLN("NTP Settings ");
  LOG_D(this->ntpServer);
  LOG_D(" TZ:");
  LOG_DLN(this->posixZone);  
}
bool NTPSettings::fromJSON(JsonObject &obj) {
  this->parseValueString(obj, "ntpServer", this->ntpServer, sizeof(this->ntpServer));
  this->parseValueString(obj, "posixZone", this->posixZone, sizeof(this->posixZone));
  return true;
}
void NTPSettings::toJSON(JsonResponse &json) {
  json.addElem("ntpServer", this->ntpServer);
  json.addElem("posixZone", this->posixZone);
}

bool NTPSettings::toJSON(JsonObject &obj) {
  obj["ntpServer"] = this->ntpServer;
  obj["posixZone"] = this->posixZone;
  return true;
}
// configTzTime applique le fuseau immédiatement et lance SNTP sans attendre : l'ancien getLocalTime
// bloquait 5 s au démarrage (avant même que le réseau ne soit monté) et le fuseau n'était alors jamais
// appliqué avant une nouvelle sauvegarde des réglages.
bool NTPSettings::apply() {
  configTzTime(this->posixZone, this->ntpServer);
  return true;
}
IPSettings::IPSettings() {}
bool IPSettings::begin() {
  this->load();
  return true;
}
bool IPSettings::fromJSON(JsonObject &obj) {
  if(obj.containsKey("dhcp")) this->dhcp = obj["dhcp"];
  this->parseIPAddress(obj, "ip", &this->ip);
  this->parseIPAddress(obj, "gateway", &this->gateway);
  this->parseIPAddress(obj, "subnet", &this->subnet);
  this->parseIPAddress(obj, "dns1", &this->dns1);
  this->parseIPAddress(obj, "dns2", &this->dns2);
  return true;
}
bool IPSettings::toJSON(JsonObject &obj) {
  IPAddress ipEmpty(0,0,0,0);
  obj["dhcp"] = this->dhcp;
  obj["ip"] = this->ip == ipEmpty ? "" : this->ip.toString();
  obj["gateway"] = this->gateway == ipEmpty ? "" : this->gateway.toString();
  obj["subnet"] = this->subnet == ipEmpty ? "" : this->subnet.toString();
  obj["dns1"] = this->dns1 == ipEmpty ? "" : this->dns1.toString();
  obj["dns2"] = this->dns2 == ipEmpty ? "" : this->dns2.toString();
  return true;  
}
void IPSettings::toJSON(JsonResponse &json) {
  IPAddress ipEmpty(0,0,0,0);
  json.addElem("dhcp", this->dhcp);
  json.addElem("ip", this->ip.toString().c_str());
  json.addElem("gateway", this->gateway.toString().c_str());
  json.addElem("subnet", this->subnet.toString().c_str());
  json.addElem("dns1", this->dns1.toString().c_str());
  json.addElem("dns2", this->dns2.toString().c_str());
}

bool IPSettings::save() {
  pref.begin("IP");
  pref.clear();
  pref.putBool("dhcp", this->dhcp);
  pref.putString("ip", this->ip.toString());
  pref.putString("gateway", this->gateway.toString());
  pref.putString("subnet", this->subnet.toString());
  pref.putString("dns1", this->dns1.toString());
  pref.putString("dns2", this->dns2.toString());
  pref.end();
  return true;
}
bool IPSettings::load() {
  pref.begin("IP");
  this->dhcp = pref.getBool("dhcp", true);
  char buff[16];
  if(pref.isKey("ip")) {
    pref.getString("ip", buff, sizeof(buff));
    this->ip.fromString(buff);
  }
  if(pref.isKey("gateway")) {
    pref.getString("gateway", buff, sizeof(buff));
    this->gateway.fromString(buff);
  }
  if(pref.isKey("subnet")) {
    pref.getString("subnet", buff, sizeof(buff));
    this->subnet.fromString(buff);
  }
  if(pref.isKey("dns1")) {
    pref.getString("dns1", buff, sizeof(buff));
    this->dns1.fromString(buff);
  }
  if(pref.isKey("dns2")) {
    pref.getString("dns2", buff, sizeof(buff));
    this->dns2.fromString(buff);
  }
  LOG_DF("Preference IP Free Entries: %d\n", pref.freeEntries());
  pref.end();
  return true;
}
bool SecuritySettings::begin() {
  this->load();
  return true;
}
bool SecuritySettings::fromJSON(JsonObject &obj) {
  if(obj.containsKey("type")) this->type = static_cast<security_types>(obj["type"].as<uint8_t>());
  this->parseValueString(obj, "username", this->username, sizeof(this->username));
  this->parseSecretString(obj, "password", this->password, sizeof(this->password), false);
  this->parseSecretString(obj, "pin", this->pin, sizeof(this->pin), false);
  if(obj.containsKey("permissions")) this->permissions = obj["permissions"];
  return true;
}
bool SecuritySettings::toJSON(JsonObject &obj) {
  obj["type"] = static_cast<uint8_t>(this->type);
  obj["username"] = this->username;
  obj["password"] = strlen(this->password) > 0 ? SECRET_MASK : "";
  obj["hasPassword"] = strlen(this->password) > 0;
  obj["pin"] = "";
  obj["hasPin"] = strlen(this->pin) > 0;
  obj["permissions"] = this->permissions;
  return true;  
}
void SecuritySettings::toJSON(JsonResponse &json) {
  json.addElem("type", static_cast<uint8_t>(this->type));
  json.addElem("username", this->username);
  json.addElem("password", strlen(this->password) > 0 ? SECRET_MASK : "");
  json.addElem("hasPassword", strlen(this->password) > 0);
  json.addElem("pin", "");
  json.addElem("hasPin", strlen(this->pin) > 0);
  json.addElem("permissions", this->permissions);
}

bool SecuritySettings::save() {
  pref.begin("SEC");
  pref.clear();
  pref.putChar("type", static_cast<uint8_t>(this->type));
  pref.putString("username", this->username);
  pref.putString("password", this->password);
  pref.putString("pin", this->pin);
  pref.putString("secret", this->secret);
  pref.putChar("permissions", this->permissions);
  pref.end();
  return true;
}
// Le jeton d'API est un HMAC dont la clé doit rester inconnue des clients : un secret de 256 bits
// tiré au premier démarrage et conservé en NVS, jamais dérivé d'une valeur publique comme le serverId.
void SecuritySettings::ensureSecret() {
  if(strlen(this->secret) == 64) return;
  for(uint8_t i = 0; i < 8; i++) {
    uint32_t r = esp_random();
    snprintf(&this->secret[i * 8], 9, "%08lx", (unsigned long)r);
  }
  this->secret[64] = '\0';
  pref.begin("SEC");
  pref.putString("secret", this->secret);
  pref.end();
}
bool SecuritySettings::load() {
  pref.begin("SEC");
  this->type = static_cast<security_types>(pref.getChar("type", 0));
  if(pref.isKey("username")) pref.getString("username", this->username, sizeof(this->username));
  if(pref.isKey("password")) pref.getString("password", this->password, sizeof(this->password));
  if(pref.isKey("pin")) pref.getString("pin", this->pin, sizeof(this->pin));
  if(pref.isKey("secret")) pref.getString("secret", this->secret, sizeof(this->secret));
  if(pref.isKey("permissions")) this->permissions = pref.getChar("permissions", this->permissions);
  pref.end();
  this->ensureSecret();
  return true;
}
void SecuritySettings::print() {
  LOG_D("SECURITY   Type:");
  LOG_D(static_cast<uint8_t>(this->type));
  LOG_D(" Username:[");
  LOG_D(this->username);
  LOG_D("] Password:[");
  LOG_D(strlen(this->password) > 0 ? "set" : "none");
  LOG_D("] Pin:[");
  LOG_D(strlen(this->pin) > 0 ? "set" : "none");
  LOG_D("] Permissions:");
  LOG_DLN(this->permissions);
}

WifiSettings::WifiSettings() {}
bool WifiSettings::begin() {
  this->load();
  return true;
}
bool WifiSettings::fromJSON(JsonObject &obj) {
  this->parseValueString(obj, "ssid", this->ssid, sizeof(this->ssid));
  this->parseSecretString(obj, "passphrase", this->passphrase, sizeof(this->passphrase));
  if(obj["apPassphrase"].is<const char*>()) {
    const char *ap = obj["apPassphrase"].as<const char*>();
    size_t len = strlen(ap);
    if(len == 0 || (len >= 8 && len <= 63)) strlcpy(this->apPassphrase, ap, sizeof(this->apPassphrase));
  }
  if(obj.containsKey("roaming")) this->roaming = obj["roaming"];
  if(obj.containsKey("hidden")) this->hidden = obj["hidden"];
  return true;
}
bool WifiSettings::toJSON(JsonObject &obj) {
  obj["ssid"] = this->ssid;
  obj["passphrase"] = strlen(this->passphrase) > 0 ? SECRET_MASK : "";
  obj["hasPassphrase"] = strlen(this->passphrase) > 0;
  obj["apPassphrase"] = this->apPassphrase;
  obj["roaming"] = this->roaming;
  obj["hidden"] = this->hidden;
  return true;
}
void WifiSettings::toJSON(JsonResponse &json) {
  json.addElem("ssid", this->ssid);
  json.addElem("passphrase", strlen(this->passphrase) > 0 ? SECRET_MASK : "");
  json.addElem("hasPassphrase", strlen(this->passphrase) > 0);
  json.addElem("apPassphrase", this->apPassphrase);
  json.addElem("roaming", this->roaming);
  json.addElem("hidden", this->hidden);
}

bool WifiSettings::save() {
  pref.begin("WIFI");
  pref.clear();
  pref.putString("ssid", this->ssid);
  pref.putString("passphrase", this->passphrase);
  pref.putString("apPass", this->apPassphrase);
  pref.putBool("roaming", this->roaming);
  pref.putBool("hidden", this->hidden);
  pref.end();
  return true;
}
bool WifiSettings::load() {
  pref.begin("WIFI");
  pref.getString("ssid", this->ssid, sizeof(this->ssid));
  pref.getString("passphrase", this->passphrase, sizeof(this->passphrase));
  this->ssid[sizeof(this->ssid) - 1] = '\0';
  this->passphrase[sizeof(this->passphrase) - 1] = '\0';
  if(pref.isKey("apPass")) pref.getString("apPass", this->apPassphrase, sizeof(this->apPassphrase));
  this->roaming = pref.getBool("roaming", true);
  this->hidden = pref.getBool("hidden", false);
  pref.end();
  this->ensureApPassphrase();
  return true;
}
// Le point d'accès de secours n'est ouvert que tant qu'aucun réseau n'a été configuré : ensuite il est
// protégé par une clé WPA2 aléatoire, affichée dans les réglages réseau et sur le port série.
void WifiSettings::ensureApPassphrase() {
  if(strlen(this->apPassphrase) >= 8) return;
  static const char alphabet[] = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  for(uint8_t i = 0; i < 12; i++) this->apPassphrase[i] = alphabet[esp_random() % (sizeof(alphabet) - 1)];
  this->apPassphrase[12] = '\0';
  pref.begin("WIFI");
  pref.putString("apPass", this->apPassphrase);
  pref.end();
}
String WifiSettings::mapEncryptionType(int type) {
  switch(type) {
    case WIFI_AUTH_OPEN:
      return "Open";
    case WIFI_AUTH_WEP:
      return "WEP";
    case WIFI_AUTH_WPA_PSK:
      return "WPA/PSK";
    case WIFI_AUTH_WPA2_PSK:
      return "WPA2/PSK";
    case WIFI_AUTH_WPA_WPA2_PSK:
      return "WPA/WPA2/PSK";
    case WIFI_AUTH_WPA2_ENTERPRISE:
      return "WPA/Enterprise";
  }
  return "Unknown";
}
void WifiSettings::print() {
  LOG_ILN("WIFI Settings");
  LOG_I(" SSID: [");
  LOG_I(this->ssid);
  LOG_I("] PassPhrase: [");
  LOG_I(strlen(this->passphrase) > 0 ? "set" : "none");
  LOG_ILN("]");
  LOG_I(" Fallback hotspot passphrase: ");
  LOG_ILN(this->apPassphrase);
}
void WifiSettings::printNetworks() {
  int n = WiFi.scanNetworks(false, false);
  LOG_D("Scanned ");
  LOG_D(n);
  LOG_DLN(" Networks...");
  String network;
  for(int i = 0; i < n; i++) {
    if(WiFi.SSID(i).compareTo(this->ssid) == 0) LOG_I("*");
    else LOG_I(" ");
    LOG_I(i);
    LOG_I(": ");
    LOG_I(WiFi.SSID(i));
    LOG_I(" (");
    LOG_I(WiFi.RSSI(i));
    LOG_I("dBm) CH:");
    LOG_I(WiFi.channel(i));
    LOG_I(" MAC:");
    LOG_I(WiFi.BSSIDstr(i));
    LOG_ILN();
  }

}
bool WifiSettings::ssidExists(const char *ssid) {
  int n = WiFi.scanNetworks(false, true);
  for(int i = 0; i < n; i++) {
    if(WiFi.SSID(i).compareTo(ssid) == 0) return true;
  }
  return false;
}
EthernetSettings::EthernetSettings() {}
bool EthernetSettings::begin() {
  this->load();
  return true;
}
bool EthernetSettings::fromJSON(JsonObject &obj) {
  if(obj.containsKey("boardType")) this->boardType = obj["boardType"];
  if(obj.containsKey("phyAddress")) this->phyAddress = obj["phyAddress"];
  if(obj.containsKey("CLKMode")) this->CLKMode = static_cast<eth_clock_mode_t>(obj["CLKMode"]);
  if(obj.containsKey("phyType")) this->phyType = static_cast<eth_phy_type_t>(obj["phyType"]);
  if(obj.containsKey("PWRPin")) this->PWRPin = obj["PWRPin"];
  if(obj.containsKey("MDCPin")) this->MDCPin = obj["MDCPin"];
  if(obj.containsKey("MDIOPin")) this->MDIOPin = obj["MDIOPin"];
  return true;
}
bool EthernetSettings::toJSON(JsonObject &obj) {
  obj["boardType"] = this->boardType;
  obj["phyAddress"] = this->phyAddress;
  obj["CLKMode"] = static_cast<uint8_t>(this->CLKMode);
  obj["phyType"] = static_cast<uint8_t>(this->phyType);
  obj["PWRPin"] = this->PWRPin;
  obj["MDCPin"] = this->MDCPin;
  obj["MDIOPin"] = this->MDIOPin;
  return true;
}
void EthernetSettings::toJSON(JsonResponse &json) {
  json.addElem("boardType", this->boardType);
  json.addElem("phyAddress", this->phyAddress);
  json.addElem("CLKMode", static_cast<uint8_t>(this->CLKMode));
  json.addElem("phyType", static_cast<uint8_t>(this->phyType));
  json.addElem("PWRPin", this->PWRPin);
  json.addElem("MDCPin", this->MDCPin);
  json.addElem("MDIOPin", this->MDIOPin);
}

bool EthernetSettings::usesPin(uint8_t pin) {
#if CONFIG_IDF_TARGET_ESP32
  // Broches RMII fixes de l'EMAC : TXD0, TX_EN, TXD1, RXD0, RXD1, CRS_DV.
  if(pin == 19 || pin == 21 || pin == 22 || pin == 25 || pin == 26 || pin == 27) return true;
#endif
  if((this->CLKMode == 0 || this->CLKMode == 1) && pin == 0) return true;
  else if(this->CLKMode == 2 && pin == 16) return true;
  else if(this->CLKMode == 3 && pin == 17) return true;
  else if(this->PWRPin == pin) return true;
  else if(this->MDCPin == pin) return true;
  else if(this->MDIOPin == pin) return true;
  return false;  
}
bool EthernetSettings::save() {
  pref.begin("ETH");
  pref.clear();
  pref.putChar("boardType", this->boardType);
  pref.putChar("phyAddress", this->phyAddress);
  pref.putChar("phyType", static_cast<uint8_t>(this->phyType));
  pref.putChar("CLKMode", static_cast<uint8_t>(this->CLKMode));
  pref.putChar("PWRPin", this->PWRPin);
  pref.putChar("MDCPin", this->MDCPin);
  pref.putChar("MDIOPin", this->MDIOPin);
  pref.end();
  return true;
}
bool EthernetSettings::load() {
  pref.begin("ETH");
  this->boardType = pref.getChar("boardType", this->boardType);
  this->phyType = static_cast<eth_phy_type_t>(pref.getChar("phyType", ETH_PHY_LAN8720));
  this->CLKMode = static_cast<eth_clock_mode_t>(pref.getChar("CLKMode", ETH_CLOCK_GPIO0_IN));
  this->phyAddress = pref.getChar("phyAddress", this->phyAddress);
  this->PWRPin = pref.getChar("PWRPin", this->PWRPin);
  this->MDCPin = pref.getChar("MDCPin", this->MDCPin);
  this->MDIOPin = pref.getChar("MDIOPin", this->MDIOPin);
  pref.end();
  return true;
}
void EthernetSettings::print() {
  LOG_ILN("Ethernet Settings");
  LOG_IF("Board:%d PHYType:%d CLK:%d ADDR:%d PWR:%d MDC:%d MDIO:%d\n", this->boardType, this->phyType, this->CLKMode, this->phyAddress, this->PWRPin, this->MDCPin, this->MDIOPin);
}
void ConfigSettings::printAvailHeap() {
  LOG_D("Max Heap: ");
  LOG_DLN(ESP.getMaxAllocHeap());
  LOG_D("Free Heap: ");
  LOG_DLN(ESP.getFreeHeap());
  LOG_D("Min Heap: ");
  LOG_DLN(ESP.getMinFreeHeap());
}
