#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <Update.h>
#include <HTTPClient.h>
#include <mbedtls/sha256.h>
#include <esp_task_wdt.h>
#include "Log.h"
#include "ConfigSettings.h"
#include "GitOTA.h"
#include "Utils.h"
#include "Sockets.h"
#include "Somfy.h"
#include "Web.h"
#include "WResp.h"
#include "Network.h"




extern ConfigSettings settings;
extern SocketEmitter sockEmit;
extern SomfyShadeController somfy;
extern rebootDelay_t rebootDelay;
extern Web webServer;
extern Network net;



#define MAX_BUFF_SIZE 4096
#define UPDATE_ERR_OFFSET 20
#define ERR_DOWNLOAD_HTTP -40
#define ERR_DOWNLOAD_BUFFER -41
#define ERR_DOWNLOAD_CONNECTION -42
#define ERR_STREAM_TIMEOUT -43
#define ERR_CANCELLED -44
#define ERR_REDIRECT_HOST -45
#define ERR_TOO_MANY_REDIRECTS -46
#define ERR_BAD_HOST -47
#define ERR_PARSE -48
#define ERR_DIGEST -49
#define STREAM_STALL_MS 8000

// Racines de confiance des hôtes GitHub : github.com et api.github.com sont émis par Sectigo
// (Public Server Authentication Root E46), *.githubusercontent.com par Let's Encrypt dont la
// chaîne remonte à ISRG Root X1 ; DigiCert Global Root G2 est conservée en réserve. Le bundle
// complet du core (64 Ko) ne tient pas dans la partition applicative.
static const char GITHUB_ROOT_CAS[] = R"CERT(-----BEGIN CERTIFICATE-----
MIICOjCCAcGgAwIBAgIQQvLM2htpN0RfFf51KBC49DAKBggqhkjOPQQDAzBfMQsw
CQYDVQQGEwJHQjEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMTYwNAYDVQQDEy1T
ZWN0aWdvIFB1YmxpYyBTZXJ2ZXIgQXV0aGVudGljYXRpb24gUm9vdCBFNDYwHhcN
MjEwMzIyMDAwMDAwWhcNNDYwMzIxMjM1OTU5WjBfMQswCQYDVQQGEwJHQjEYMBYG
A1UEChMPU2VjdGlnbyBMaW1pdGVkMTYwNAYDVQQDEy1TZWN0aWdvIFB1YmxpYyBT
ZXJ2ZXIgQXV0aGVudGljYXRpb24gUm9vdCBFNDYwdjAQBgcqhkjOPQIBBgUrgQQA
IgNiAAR2+pmpbiDt+dd34wc7qNs9Xzjoq1WmVk/WSOrsfy2qw7LFeeyZYX8QeccC
WvkEN/U0NSt3zn8gj1KjAIns1aeibVvjS5KToID1AZTc8GgHHs3u/iVStSBDHBv+
6xnOQ6OjQjBAMB0GA1UdDgQWBBTRItpMWfFLXyY4qp3W7usNw/upYTAOBgNVHQ8B
Af8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAwNnADBkAjAn7qRa
qCG76UeXlImldCBteU/IvZNeWBj7LRoAasm4PdCkT0RHlAFWovgzJQxC36oCMB3q
4S6ILuH5px0CMk7yn2xVdOOurvulGu7t0vzCAxHrRVxgED1cf5kDW21USAGKcw==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAwDQYJKoZIhvcNAQELBQAw
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTUwNjA0MTEwNDM4
WhcNMzUwNjA0MTEwNDM4WjBPMQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJu
ZXQgU2VjdXJpdHkgUmVzZWFyY2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBY
MTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK3oJHP0FDfzm54rVygc
h77ct984kIxuPOZXoHj3dcKi/vVqbvYATyjb3miGbESTtrFj/RQSa78f0uoxmyF+
0TM8ukj13Xnfs7j/EvEhmkvBioZxaUpmZmyPfjxwv60pIgbz5MDmgK7iS4+3mX6U
A5/TR5d8mUgjU+g4rk8Kb4Mu0UlXjIB0ttov0DiNewNwIRt18jA8+o+u3dpjq+sW
T8KOEUt+zwvo/7V3LvSye0rgTBIlDHCNAymg4VMk7BPZ7hm/ELNKjD+Jo2FR3qyH
B5T0Y3HsLuJvW5iB4YlcNHlsdu87kGJ55tukmi8mxdAQ4Q7e2RCOFvu396j3x+UC
B5iPNgiV5+I3lg02dZ77DnKxHZu8A/lJBdiB3QW0KtZB6awBdpUKD9jf1b0SHzUv
KBds0pjBqAlkd25HN7rOrFleaJ1/ctaJxQZBKT5ZPt0m9STJEadao0xAH0ahmbWn
OlFuhjuefXKnEgV4We0+UXgVCwOPjdAvBbI+e0ocS3MFEvzG6uBQE3xDk3SzynTn
jh8BCNAw1FtxNrQHusEwMFxIt4I7mKZ9YIqioymCzLq9gwQbooMDQaHWBfEbwrbw
qHyGO0aoSCqI3Haadr8faqU9GY/rOPNk3sgrDQoo//fb4hVC1CLQJ13hef4Y53CI
rU7m2Ys6xt0nUW7/vGT1M0NPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNV
HRMBAf8EBTADAQH/MB0GA1UdDgQWBBR5tFnme7bl5AFzgAiIyBpY9umbbjANBgkq
hkiG9w0BAQsFAAOCAgEAVR9YqbyyqFDQDLHYGmkgJykIrGF1XIpu+ILlaS/V9lZL
ubhzEFnTIZd+50xx+7LSYK05qAvqFyFWhfFQDlnrzuBZ6brJFe+GnY+EgPbk6ZGQ
3BebYhtF8GaV0nxvwuo77x/Py9auJ/GpsMiu/X1+mvoiBOv/2X/qkSsisRcOj/KK
NFtY2PwByVS5uCbMiogziUwthDyC3+6WVwW6LLv3xLfHTjuCvjHIInNzktHCgKQ5
ORAzI4JMPJ+GslWYHb4phowim57iaztXOoJwTdwJx4nLCgdNbOhdjsnvzqvHu7Ur
TkXWStAmzOVyyghqpZXjFaH3pO3JLF+l+/+sKAIuvtd7u+Nxe5AW0wdeRlN8NwdC
jNPElpzVmbUq4JUagEiuTDkHzsxHpFKVK7q4+63SM1N95R1NbdWhscdCb+ZAJzVc
oyi3B43njTOQ5yOf+1CceWxG1bQVs5ZufpsMljq4Ui0/1lvh+wjChP4kqKOJ2qxq
4RgqsahDYVvTH9w7jXbyLeiNdd8XM2w9U/t7y0Ff/9yi0GE44Za4rF2LN9d11TPA
mRGunUHBcnWEvgJBQl9nJEiU0Zsnvgc/ubhPgXRR4Xq37Z0j4r7g1SgEEzwxA57d
emyPxgcYxn/eR44/KJ4EBs+lVDR3veyJm+kXQ99b21/+jh5Xos1AnX5iItreGCc=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIDjjCCAnagAwIBAgIQAzrx5qcRqaC7KGSxHQn65TANBgkqhkiG9w0BAQsFADBh
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBH
MjAeFw0xMzA4MDExMjAwMDBaFw0zODAxMTUxMjAwMDBaMGExCzAJBgNVBAYTAlVT
MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5j
b20xIDAeBgNVBAMTF0RpZ2lDZXJ0IEdsb2JhbCBSb290IEcyMIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuzfNNNx7a8myaJCtSnX/RrohCgiN9RlUyfuI
2/Ou8jqJkTx65qsGGmvPrC3oXgkkRLpimn7Wo6h+4FR1IAWsULecYxpsMNzaHxmx
1x7e/dfgy5SDN67sH0NO3Xss0r0upS/kqbitOtSZpLYl6ZtrAGCSYP9PIUkY92eQ
q2EGnI/yuum06ZIya7XzV+hdG82MHauVBJVJ8zUtluNJbd134/tJS7SsVQepj5Wz
tCO7TG1F8PapspUwtP1MVYwnSlcUfIKdzXOS0xZKBgyMUNGPHgm+F6HmIcr9g+UQ
vIOlCsRnKPZzFBQ9RnbDhxSJITRNrw9FDKZJobq7nMWxM4MphQIDAQABo0IwQDAP
BgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQUTiJUIBiV
5uNu5g/6+rkS7QYXjzkwDQYJKoZIhvcNAQELBQADggEBAGBnKJRvDkhj6zHd6mcY
1Yl9PMWLSn/pvtsrF9+wX3N3KjITOYFnQoQj8kVnNeyIv/iPsGEMNKSuIEyExtv4
NeF22d+mQrvHRAiGfzZ0JFrabA0UWTW98kndth/Jsw1HKj2ZL7tcu7XUIOGZX1NG
Fdtom/DzMNU+MeKNhJ7jitralj41E6Vf8PlwUHBHQRFXGU7Aj64GxJUTFy8bJZ91
8rGOmaFvE7FBcf6IKshPECBV1/MUReXgRPTqh5Uykw7+U0b6LJ3/iyK5S9kJRaTe
pLiaWN0bfVKfjllDiIGknibVb63dDcY3fe0Dkhvld1927jyNxF1WW6LZZm6zNTfl
MrY=
-----END CERTIFICATE-----
)CERT";

static const char *const GITHUB_HOSTS[] = {"github.com", "api.github.com", "raw.githubusercontent.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com"};
static bool isAllowedHost(const String &url) {
  if(!url.startsWith("https://")) return false;
  int end = url.indexOf('/', 8);
  String host = end < 0 ? url.substring(8) : url.substring(8, end);
  int colon = host.indexOf(':');
  if(colon >= 0) host = host.substring(0, colon);
  for(const char *h : GITHUB_HOSTS) if(host.equalsIgnoreCase(h)) return true;
  return host.endsWith(".githubusercontent.com") || host.endsWith(".github.com");
}
// Session HTTPS commune : certificat vérifié, délais bornés (le watchdog est à 7 s) et redirections
// suivies à la main pour n'accepter que les hôtes GitHub.
static void configureSecureSession(WiFiClientSecure &sclient, HTTPClient &https) {
  sclient.setCACert(GITHUB_ROOT_CAS);
  sclient.setHandshakeTimeout(5);
  https.setReuse(false);
  https.setConnectTimeout(5000);
  https.setTimeout(5000);
  https.setFollowRedirects(HTTPC_DISABLE_FOLLOW_REDIRECTS);
  static const char *hdrs[] = {"Location"};
  https.collectHeaders(hdrs, 1);
}
// Renvoie le code HTTP final (la session reste ouverte pour lire le corps) ou un code négatif.
static int sendGitRequest(WiFiClientSecure &sclient, HTTPClient &https, String url, const char *method) {
  for(uint8_t hop = 0; hop < 5; hop++) {
    if(!isAllowedHost(url)) return ERR_BAD_HOST;
    esp_task_wdt_reset();
    if(!https.begin(sclient, url)) return HTTPC_ERROR_CONNECTION_REFUSED;
    int code = https.sendRequest(method);
    esp_task_wdt_reset();
    if(code == HTTP_CODE_MOVED_PERMANENTLY || code == HTTP_CODE_FOUND || code == HTTP_CODE_SEE_OTHER ||
       code == HTTP_CODE_TEMPORARY_REDIRECT || code == HTTP_CODE_PERMANENT_REDIRECT) {
      String loc = https.header("Location");
      https.end();
      if(loc.startsWith("/")) loc = url.substring(0, url.indexOf('/', 8)) + loc;
      LOG_IF("Redirected to %s\n", loc.c_str());
      if(!isAllowedHost(loc)) return ERR_REDIRECT_HOST;
      url = loc;
      continue;
    }
    return code;
  }
  https.end();
  return ERR_TOO_MANY_REDIRECTS;
}
// Flux de lecture du corps HTTP : bloque sans dépasser le watchdog, déchunke si le serveur n'annonce
// pas de Content-Length et abandonne après STREAM_STALL_MS sans données.
class GitBodyStream : public Stream {
  private:
    WiFiClient *_client;
    bool _chunked;
    size_t _chunkLeft = 0;
    bool _done = false;
    bool waitData() {
      uint32_t start = millis();
      while(_client->available() <= 0) {
        if(!_client->connected()) return false;
        if(millis() - start > STREAM_STALL_MS) return false;
        esp_task_wdt_reset();
        delay(1);
      }
      return true;
    }
    bool readLine(char *buf, size_t len) {
      size_t i = 0;
      while(true) {
        if(!waitData()) return false;
        int c = _client->read();
        if(c < 0) continue;
        if(c == '\n') break;
        if(c != '\r' && i < len - 1) buf[i++] = (char)c;
      }
      buf[i] = '\0';
      return true;
    }
    bool nextChunk() {
      char line[16];
      do { if(!readLine(line, sizeof(line))) return false; } while(line[0] == '\0');
      _chunkLeft = strtoul(line, nullptr, 16);
      if(_chunkLeft == 0) { _done = true; return false; }
      return true;
    }
  public:
    GitBodyStream(HTTPClient &http) : _client(http.getStreamPtr()), _chunked(http.getSize() < 0) {}
    int available() override {
      if(_done) return 0;
      if(_chunked && _chunkLeft == 0 && !nextChunk()) return 0;
      int a = _client->available();
      return _chunked ? (int)min((size_t)a, _chunkLeft) : a;
    }
    int read() override { uint8_t b; return this->readBytes((char *)&b, 1) == 1 ? b : -1; }
    int peek() override { return available() > 0 ? _client->peek() : -1; }
    size_t write(uint8_t) override { return 0; }
    size_t readBytes(char *buffer, size_t length) override {
      size_t got = 0;
      while(got < length && !_done) {
        if(_chunked && _chunkLeft == 0 && !nextChunk()) break;
        if(!waitData()) break;
        size_t want = length - got;
        if(_chunked) want = min(want, _chunkLeft);
        int n = _client->read((uint8_t *)buffer + got, want);
        if(n <= 0) continue;
        got += n;
        if(_chunked) _chunkLeft -= n;
      }
      return got;
    }
};
void GitRelease::setAssetProperty(const char *key, const char *val) {
  if(strcmp(key, "name") == 0) {
    //LOG_ILN(val);
    if(strstr(val, "littlefs.bin")) this->hasFS = true;
    else if(strstr(val, "ino.esp32.bin")) {
      if(strlen(this->hwVersions)) strcat(this->hwVersions, ",");
      strcat(this->hwVersions, "32");
    }
    else if(strstr(val, "ino.esp32s3.bin")) {
      if(strlen(this->hwVersions)) strcat(this->hwVersions, ",");
      strcat(this->hwVersions, "s3");
    }
    else if(strstr(val, "ino.esp32s2.bin")) {
      if(strlen(this->hwVersions)) strcat(this->hwVersions, ",");
      strcat(this->hwVersions, "s2");
    }
    else if(strstr(val, "ino.esp32c3.bin")) {
      if(strlen(this->hwVersions)) strcat(this->hwVersions, ",");
      strcat(this->hwVersions, "c3");
    }
    else if(strstr(val, "ino.esp32c2.bin")) {
      if(strlen(this->hwVersions)) strcat(this->hwVersions, ",");
      strcat(this->hwVersions, "c2");
    }
    else if(strstr(val, "ino.esp32c6.bin")) {
      if(strlen(this->hwVersions)) strcat(this->hwVersions, ",");
      strcat(this->hwVersions, "c6");
    }
    else if(strstr(val, "ino.esp32h2.bin")) {
      if(strlen(this->hwVersions)) strcat(this->hwVersions, ",");
      strcat(this->hwVersions, "h2");
    }
  }
}
void GitRelease::toJSON(JsonResponse &json) {
  Timestamp ts;
  char buff[20];
  sprintf(buff, "%llu", this->id);
  json.addElem("id", buff);
  json.addElem("name", this->name);
  json.addElem("date", ts.getISOTime(this->releaseDate));
  json.addElem("draft", this->draft);
  json.addElem("preRelease", this->preRelease);
  json.addElem("main", this->main);
  json.addElem("hasFS", this->hasFS);
  json.addElem("hwVersions", this->hwVersions);
  json.beginObject("version");
  this->version.toJSON(json);
  json.endObject();
}
int16_t GitRepo::getReleases(uint8_t num) {
  uint8_t count = min((uint8_t)GIT_MAX_RELEASES, num);
  memset(this->releases, 0x00, sizeof(GitRelease) * GIT_MAX_RELEASES);
  GitRelease *main = &this->releases[GIT_MAX_RELEASES];
  main->releaseDate = Timestamp::now();
  main->id = 1;
  main->main = true;
  strcpy(main->version.name, "main");
  strcpy(main->name, "Main");
  strcpy(main->hwVersions, "32,s3");
  char url[128];
  snprintf(url, sizeof(url), "https://api.github.com/repos/rstrouse/espsomfy-rts/releases?per_page=%d&page=1", count);
  WiFiClientSecure sclient;
  HTTPClient https;
  configureSecureSession(sclient, https);
  int httpCode = sendGitRequest(sclient, https, url, "GET");
  LOG_IF("[HTTPS] GET releases... code: %d\n", httpCode);
  if(httpCode != HTTP_CODE_OK) {
    https.end();
    sclient.stop();
    return httpCode;
  }
  // Seuls les champs utiles sont conservés : le corps des notes de version (plusieurs Ko par release)
  // n'est jamais chargé en mémoire.
  StaticJsonDocument<256> filter;
  filter[0]["id"] = true;
  filter[0]["draft"] = true;
  filter[0]["prerelease"] = true;
  filter[0]["name"] = true;
  filter[0]["tag_name"] = true;
  filter[0]["published_at"] = true;
  filter[0]["assets"][0]["name"] = true;
  filter[0]["assets"][0]["digest"] = true;
  DynamicJsonDocument doc(8192);
  GitBodyStream body(https);
  DeserializationError err = deserializeJson(doc, body, DeserializationOption::Filter(filter));
  https.end();
  sclient.stop();
  if(err) {
    LOG_EF("Error parsing GitHub releases: %s\n", err.c_str());
    return ERR_PARSE;
  }
  uint8_t ndx = 0;
  for(JsonObject rel : doc.as<JsonArray>()) {
    if(ndx >= count) break;
    GitRelease *r = &this->releases[ndx++];
    r->id = rel["id"].as<uint64_t>();
    r->draft = rel["draft"] | false;
    r->preRelease = rel["prerelease"] | false;
    strlcpy(r->name, rel["name"] | "", sizeof(r->name));
    r->version.parse(rel["tag_name"] | "");
    r->releaseDate = Timestamp::parseUTCTime(rel["published_at"] | "");
    for(JsonObject asset : rel["assets"].as<JsonArray>()) {
      const char *aname = asset["name"] | "";
      r->setAssetProperty("name", aname);
      const char *digest = asset["digest"] | "";
      if(strncmp(digest, "sha256:", 7) != 0) continue;
      if(strstr(aname, "littlefs.bin")) strlcpy(r->fsDigest, digest + 7, sizeof(r->fsDigest));
      else if(strcmp(aname, GitUpdater::firmwareFileName()) == 0) strlcpy(r->fwDigest, digest + 7, sizeof(r->fwDigest));
    }
  }
  settings.printAvailHeap();
  return 0;
}
void GitRepo::toJSON(JsonResponse &json) {
  json.beginObject("fwVersion");
  settings.fwVersion.toJSON(json);
  json.endObject();
  json.beginObject("appVersion");
  settings.appVersion.toJSON(json);
  json.endObject();
  json.beginArray("releases");
  for(uint8_t i = 0; i < GIT_MAX_RELEASES + 1; i++) {
    if(this->releases[i].id == 0) continue;
    json.beginObject();
    this->releases[i].toJSON(json);
    json.endObject();
  }
  json.endArray();
}
void GitUpdater::loop() {
  if(!net.connected()) return;
  if(this->status == GIT_STATUS_READY) {
    if(settings.checkForUpdate && 
      (millis() > net.connectTime + 60000) && // Wait a minute before checking after connection.
      (this->lastCheck + 86400000 < millis() || this->lastCheck == 0) && !rebootDelay.reboot) { // 1 day
      this->checkForUpdate();
    }
  }
  else if(this->status == GIT_AWAITING_UPDATE) {
    LOG_ILN("Starting update process.........");
    this->status = GIT_UPDATING;
    this->beginUpdate(this->targetRelease);
    this->status = GIT_STATUS_READY;
    this->emitUpdateCheck();
  }
  else if(this->status == GIT_UPDATE_CANCELLING) {
    LOG_ILN("Cancelling update process..........");
    if(!this->lockFS) {
      this->status = GIT_UPDATE_CANCELLED;
      this->cancelled = true;
      this->emitUpdateCheck();
    }
  }
}
void GitUpdater::checkForUpdate() {
  if(this->status != 0) return; // If we are already checking.
  LOG_ILN("Check github for updates...");
  
  this->status = GIT_STATUS_CHECK;
  settings.printAvailHeap();  
  this->lastCheck = millis();
  if(this->checkInternet() == 0) {
    GitRepo repo;
    this->updateAvailable = false;
    this->error = repo.getReleases(2);
    if(this->error == 0) { // Get 2 releases so we can filter our pre-releases
      this->setCurrentRelease(repo);
    }
    else {
      this->emitUpdateCheck();
    }
  }
  this->status = GIT_STATUS_READY;
}
void GitUpdater::setCurrentRelease(GitRepo &repo) {
  this->updateAvailable = false;
  for(uint8_t i = 0; i < 2; i++) {
    if(repo.releases[i].draft || repo.releases[i].preRelease || repo.releases[i].id == 0) continue;
    // Compare the versions.  
    this->latest.copy(repo.releases[i].version);
    if(repo.releases[i].version.compare(settings.fwVersion) > 0) {
      // We have a new release.
      this->updateAvailable = true;
    }
    break;
  }
  this->emitUpdateCheck();
}
void GitUpdater::toJSON(JsonResponse &json) {
  json.addElem("available", this->updateAvailable);
  json.addElem("status", this->status);
  json.addElem("error", (int32_t)this->error);
  json.addElem("cancelled", this->cancelled);
  json.addElem("checkForUpdate", settings.checkForUpdate);
  json.addElem("inetAvailable", this->inetAvailable);
  json.beginObject("fwVersion");
  settings.fwVersion.toJSON(json);
  json.endObject();
  json.beginObject("appVersion");
  settings.appVersion.toJSON(json);
  json.endObject();
  json.beginObject("latest");
  this->latest.toJSON(json);
  json.endObject();
}
void GitUpdater::emitUpdateCheck(uint8_t num) {
  JsonSockEvent *json = sockEmit.beginEmit("fwStatus");
  json->beginObject();
  json->addElem("available", this->updateAvailable);
  json->addElem("status", this->status);
  json->addElem("error", (int32_t)this->error);
  json->addElem("cancelled", this->cancelled);
  json->addElem("checkForUpdate", settings.checkForUpdate);
  json->addElem("inetAvailable", this->inetAvailable);
  json->beginObject("fwVersion");
  settings.fwVersion.toJSON(json);
  json->endObject();
  json->beginObject("appVersion");
  settings.appVersion.toJSON(json);
  json->endObject();
  json->beginObject("latest");
  this->latest.toJSON(json);
  json->endObject();
  json->endObject();
  sockEmit.endEmit(num);
}
int GitUpdater::checkInternet() {
  int err = 500;
  uint32_t t = millis();
  WiFiClientSecure sclient;
  HTTPClient https;
  configureSecureSession(sclient, https);
  int httpCode = sendGitRequest(sclient, https, "https://github.com/rstrouse/ESPSomfy-RTS", "HEAD");
  if (httpCode == HTTP_CODE_OK) {
    err = 0;
    LOG_IF("Internet is Available: %ldms\n", millis() - t);
    this->inetAvailable = true;
  }
  else {
    err = httpCode;
    LOG_IF("Internet is Unavailable: %d: %ldms\n", err, millis() - t);
    this->inetAvailable = false;
  }
  https.end();
  sclient.stop();
  esp_task_wdt_reset();
  return err;
}
void GitUpdater::emitDownloadProgress(size_t total, size_t loaded, const char *evt) { this->emitDownloadProgress(255, total, loaded, evt); }
void GitUpdater::emitDownloadProgress(uint8_t num, size_t total, size_t loaded, const char *evt) {
  JsonSockEvent *json = sockEmit.beginEmit(evt);
  json->beginObject();
  json->addElem("ver", this->targetRelease);
  json->addElem("part", (int32_t)this->partition);
  json->addElem("file", this->currentFile);
  json->addElem("total", (uint32_t)total);
  json->addElem("loaded", (uint32_t)loaded);
  json->addElem("error", (uint32_t)this->error);
  json->endObject();
  sockEmit.endEmit(num);
  /*
  char buf[420];
  snprintf(buf, sizeof(buf), "{\"ver\":\"%s\",\"part\":%d,\"file\":\"%s\",\"total\":%d,\"loaded\":%d, \"error\":%d}", this->targetRelease, this->partition, this->currentFile, total, loaded, this->error);
  if(num >= 255) sockEmit.sendToClients(evt, buf);
  else sockEmit.sendToClient(num, evt, buf);
  */
  sockEmit.loop();
  webServer.loop();
}
const char *GitUpdater::firmwareFileName() {
    esp_chip_info_t ci;
    esp_chip_info(&ci);
    switch(ci.model) {
      case esp_chip_model_t::CHIP_ESP32S3: return "SomfyController.ino.esp32s3.bin";
      case esp_chip_model_t::CHIP_ESP32S2: return "SomfyController.ino.esp32s2.bin";
      case esp_chip_model_t::CHIP_ESP32C3: return "SomfyController.ino.esp32c3.bin";
      default: return "SomfyController.ino.esp32.bin";
    }
}
void GitUpdater::setFirmwareFile() { strcpy(this->currentFile, GitUpdater::firmwareFileName()); }
// Retrouve dans les releases publiées les empreintes SHA-256 des deux images d'une version.
bool GitUpdater::findReleaseDigests(const char *name, char *fwDigest, char *fsDigest) {
  fwDigest[0] = fsDigest[0] = '\0';
  GitRepo *repo = new GitRepo();
  if(!repo) return false;
  bool found = false;
  if(repo->getReleases(GIT_MAX_RELEASES) == 0) {
    for(uint8_t i = 0; i < GIT_MAX_RELEASES; i++) {
      if(repo->releases[i].id == 0 || strcmp(repo->releases[i].name, name) != 0) continue;
      strlcpy(fwDigest, repo->releases[i].fwDigest, 65);
      strlcpy(fsDigest, repo->releases[i].fsDigest, 65);
      found = true;
      break;
    }
  }
  delete repo;
  return found;
}

bool GitUpdater::beginUpdate(const char *version) {
  LOG_ILN("Begin update called...");
  if(strcmp(version, "Main") == 0)  strcpy(this->baseUrl, "https://raw.githubusercontent.com/rstrouse/ESPSomfy-RTS/master/");
  else sprintf(this->baseUrl, "https://github.com/rstrouse/ESPSomfy-RTS/releases/download/%s/", version);
  
  strcpy(this->targetRelease, version);
  this->emitUpdateCheck();
  if(strcmp(version, "Main") != 0 && strlen(this->targetFwDigest) != 64) this->findReleaseDigests(version, this->targetFwDigest, this->targetFsDigest);
  this->setFirmwareFile();
  this->partition = U_FLASH;
  this->lockFS = this->cancelled = false;
  this->error = 0;
  strlcpy(this->expectedDigest, this->targetFwDigest, sizeof(this->expectedDigest));
  this->error = this->downloadFile();
  if(this->error == 0 && !this->cancelled) {
    somfy.commit();
    strcpy(this->currentFile, "SomfyController.littlefs.bin");
    this->partition = U_SPIFFS;
    this->lockFS = true;
    strlcpy(this->expectedDigest, this->targetFsDigest, sizeof(this->expectedDigest));
    this->error = this->downloadFile();
    this->lockFS = false;
    if(this->error == 0) {
      settings.fwVersion.parse(version);
      delay(100);
      LOG_ILN("Committing Configuration...");
      somfy.commit();
    }
    rebootDelay.reboot = true;
    rebootDelay.rebootTime = millis() + 500;
  }
  this->status = GIT_UPDATE_COMPLETE;
  this->emitUpdateCheck();
  return true;
}
bool GitUpdater::recoverFilesystem() {
  sprintf(this->baseUrl, "https://github.com/rstrouse/ESPSomfy-RTS/releases/download/%s/", settings.fwVersion.name);
  strcpy(this->currentFile, "SomfyController.littlefs.bin");
  this->status = GIT_UPDATING;
  this->findReleaseDigests(settings.fwVersion.name, this->targetFwDigest, this->targetFsDigest);
  strlcpy(this->expectedDigest, this->targetFsDigest, sizeof(this->expectedDigest));
  this->partition = U_SPIFFS;
  this->lockFS = true;
  this->error = this->downloadFile();
  this->lockFS = false;
  if(this->error == 0) {
    delay(100);
    LOG_ILN("Committing Configuration...");
    somfy.commit();
  }
  this->status = GIT_UPDATE_COMPLETE;
  rebootDelay.reboot = true;
  rebootDelay.rebootTime = millis() + 500;
  return true;
}
int16_t GitUpdater::downloadFile() {
  LOG_IF("Begin update %s\n", this->currentFile);
  WiFiClientSecure sclient;
  HTTPClient https;
  configureSecureSession(sclient, https);
  char url[196];
  snprintf(url, sizeof(url), "%s%s", this->baseUrl, this->currentFile);
  LOG_ILN(url);
  int httpCode = sendGitRequest(sclient, https, url, "GET");
  if(httpCode != HTTP_CODE_OK) {
    https.end();
    sclient.stop();
    LOG_EF("Invalid HTTP Code: %d\n", httpCode);
    return (int16_t)httpCode;
  }
  int len = https.getSize();
  if(len <= 0) {
    https.end();
    sclient.stop();
    LOG_ELN("Unknown update size");
    return ERR_DOWNLOAD_HTTP;
  }
  LOG_IF("[HTTPS] GET... code: %d - %d\n", httpCode, len);
  if(!Update.begin(len, this->partition)) {
    Update.printError(Serial);
    https.end();
    sclient.stop();
    return -(Update.getError() + UPDATE_ERR_OFFSET);
  }
  uint8_t *buff = (uint8_t *)malloc(MAX_BUFF_SIZE);
  if(!buff) {
    LOG_ELN("Unable to allocate memory for update!!!");
    Update.abort();
    https.end();
    sclient.stop();
    return ERR_DOWNLOAD_BUFFER;
  }
  mbedtls_sha256_context sha;
  mbedtls_sha256_init(&sha);
  mbedtls_sha256_starts_ret(&sha, 0);
  GitBodyStream body(https);
  size_t total = 0;
  uint8_t pct = 0;
  int16_t result = 0;
  this->emitDownloadProgress(len, total);
  while(total < (size_t)len) {
    if(this->cancelled && !this->lockFS) { result = ERR_CANCELLED; break; }
    size_t n = body.readBytes((char *)buff, min((size_t)MAX_BUFF_SIZE, (size_t)len - total));
    if(n == 0) {
      LOG_ELN("Stream timeout!!!");
      result = ERR_STREAM_TIMEOUT;
      break;
    }
    if(Update.write(buff, n) != n) {
      Update.printError(Serial);
      result = -(Update.getError() + UPDATE_ERR_OFFSET);
      break;
    }
    mbedtls_sha256_update_ret(&sha, buff, n);
    total += n;
    uint8_t p = (uint8_t)((total * 100ULL) / (size_t)len);
    if(p != pct) {
      pct = p;
      LOG_IF("LEN:%d TOTAL:%d %d%%\n", len, total, pct);
      this->emitDownloadProgress(len, total);
    }
  }
  free(buff);
  https.end();
  sclient.stop();
  uint8_t digest[32];
  char hex[65];
  mbedtls_sha256_finish_ret(&sha, digest);
  mbedtls_sha256_free(&sha);
  for(size_t i = 0; i < sizeof(digest); i++) snprintf(&hex[i * 2], 3, "%02x", digest[i]);
  if(result == 0) {
    if(strlen(this->expectedDigest) == 64) {
      if(strcasecmp(hex, this->expectedDigest) != 0) {
        LOG_EF("Integrity check failed for %s: expected %s got %s\n", this->currentFile, this->expectedDigest, hex);
        result = ERR_DIGEST;
      }
    }
    else LOG_IF("No digest published for %s, integrity not verified\n", this->currentFile);
  }
  if(result != 0) {
    Update.abort();
    if(this->partition == U_SPIFFS) somfy.commit();
    LOG_EF("Error downloading %s: %d\n", this->currentFile, result);
    return result;
  }
  if(!Update.end(true)) {
    Update.printError(Serial);
    if(this->partition == U_SPIFFS) somfy.commit();
    return -(Update.getError() + UPDATE_ERR_OFFSET);
  }
  LOG_IF("Update %s complete\n", this->currentFile);
  esp_task_wdt_reset();
  return 0;
}
