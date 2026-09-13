#include <WiFi.h>
#include <LittleFS.h>
#include <esp_task_wdt.h>
#include <Preferences.h>
#include <Update.h>
#include "Log.h"
#include "ConfigSettings.h"
#include "Network.h"
#include "Web.h"
#include "Sockets.h"
#include "Utils.h"
#include "Somfy.h"
#include "MQTT.h"
#include "GitOTA.h"

ConfigSettings settings;
Web webServer;
SocketEmitter sockEmit;
Network net;
rebootDelay_t rebootDelay;
SomfyShadeController somfy;
MQTTClass mqtt;
GitUpdater git;

uint32_t oldheap = 0;
// Retour arrière automatique : après CRASH_BOOTS_BEFORE_ROLLBACK démarrages consécutifs terminés par
// un plantage (panic, watchdog) sans atteindre STABLE_UPTIME_MS, l'autre partition applicative
// (firmware précédent) est réactivée. Un redémarrage volontaire ou une coupure de courant ne compte pas.
#define CRASH_BOOTS_BEFORE_ROLLBACK 3
#define STABLE_UPTIME_MS 60000UL
static bool bootMarkedStable = false;
static void checkCrashLoop() {
  esp_reset_reason_t reason = esp_reset_reason();
  bool crash = reason == ESP_RST_PANIC || reason == ESP_RST_INT_WDT || reason == ESP_RST_TASK_WDT || reason == ESP_RST_WDT;
  Preferences pref;
  pref.begin("SYS");
  uint8_t crashes = crash ? pref.getUChar("crashes", 0) + 1 : 0;
  pref.putUChar("crashes", crashes);
  if(crashes >= CRASH_BOOTS_BEFORE_ROLLBACK && Update.canRollBack()) {
    LOG_EF("%u consecutive crashes, rolling back to the previous firmware\n", crashes);
    pref.putUChar("crashes", 0);
    pref.end();
    Update.rollBack();
    ESP.restart();
  }
  pref.end();
  if(crash) LOG_EF("Boot after crash (reset reason %d), %u consecutive\n", (int)reason, crashes);
}
static void markBootStable() {
  if(bootMarkedStable || millis() < STABLE_UPTIME_MS) return;
  bootMarkedStable = true;
  Preferences pref;
  pref.begin("SYS");
  if(pref.getUChar("crashes", 0) != 0) pref.putUChar("crashes", 0);
  pref.end();
  LOG_ILN("Firmware marked stable");
}
void setup() {
  Serial.begin(115200);
  LOG_ELN();
  LOG_ELN("Startup/Boot....");
  checkCrashLoop();
  // Le watchdog est armé avant l'initialisation de la radio : un CC1101 absent ou mal câblé pouvait
  // bloquer Init() indéfiniment sans qu'aucun chien de garde ne surveille le démarrage.
  esp_task_wdt_init(7, true); //enable panic so ESP32 restarts
  esp_task_wdt_add(NULL); //add current thread to WDT watch
  LOG_ELN("Mounting File System...");
  if(LittleFS.begin()) LOG_ELN("File system mounted successfully");
  else LOG_ELN("Error mounting file system");
  settings.begin();
  if(WiFi.status() == WL_CONNECTED) WiFi.disconnect(true);
  delay(10);
  LOG_ILN();
  webServer.startup();
  webServer.begin();
  delay(1000);
  net.setup();  
  somfy.begin();
  //git.checkForUpdate();

}

void loop() {
  // put your main code here, to run repeatedly:
  //uint32_t heap = ESP.getFreeHeap();
  if(rebootDelay.reboot && millis() > rebootDelay.rebootTime) {
    LOG_I("Rebooting after ");
    LOG_I(rebootDelay.rebootTime);
    LOG_ILN("ms");
    net.end();
    ESP.restart();
    return;
  }
  uint32_t timing = millis();
  markBootStable();
  net.loop();
  if(millis() - timing > 100) LOG_IF("Timing Net: %ldms\n", millis() - timing);
  timing = millis();
  esp_task_wdt_reset();
  somfy.loop();
  if(millis() - timing > 100) LOG_IF("Timing Somfy: %ldms\n", millis() - timing);
  timing = millis();
  esp_task_wdt_reset();
  if(net.connected() || net.softAPOpened) {
    if(!rebootDelay.reboot && net.connected() && !net.softAPOpened) {
      git.loop();
      esp_task_wdt_reset();
    }
    webServer.loop();
    esp_task_wdt_reset();
    if(millis() - timing > 100) LOG_IF("Timing WebServer: %ldms\n", millis() - timing);
    esp_task_wdt_reset();
    timing = millis();
    sockEmit.loop();
    if(millis() - timing > 100) LOG_IF("Timing Socket: %ldms\n", millis() - timing);
    esp_task_wdt_reset();
    timing = millis();
  }
  if(rebootDelay.reboot && millis() > rebootDelay.rebootTime) {
    net.end();
    ESP.restart();
  }
  esp_task_wdt_reset();
}
