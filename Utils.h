#ifndef utils_h
#define utils_h
#include <Arduino.h>


#define DEBUG_SOMFY Serial




[[maybe_unused]] static void SETCHARPROP(char *prop, const char *value, size_t size) {strncpy(prop, value, size); prop[size - 1] = '\0';}
/*
namespace util { 
  // Createa a custom to_string function.  C++ can be annoying
  // with all the trailing 0s on number formats.
  template <typename T> std::string to_string(const T& t) {
    std::string str{std::to_string (t)};
    int offset{1};
    if (str.find_last_not_of('0') == str.find('.')) {
      offset = 0;     
    }
    str.erase ( str.find_last_not_of('0') + 1, std::string::npos ); 
    str.erase ( str.find_last_not_of('.') + 1, std::string::npos );    
    return str; 
  } 
}
*/

static void _ltrim(char *str) {
  int s = 0, j, k = 0;
  int e = strlen(str);
  while(s < e && (str[s] == ' ' || str[s] == '\n' || str[s] == '\r' || str[s] == '\t' || str[s] == '"')) s++;
  if(s > 0) {
    for(j = s; j < e; j++) {
      str[k] = str[j];
      k++;
    }
    str[k] = '\0';
  }
  //if(s > 0) strcpy(str, &str[s]);
}
static void _rtrim(char *str) {
  int e = strlen(str) - 1;
  while(e >= 0 && (str[e] == ' ' || str[e] == '\n' || str[e] == '\r' || str[e] == '\t' || str[e] == '"')) {str[e] = '\0'; e--;}
}
[[maybe_unused]] static void _trim(char *str) { _ltrim(str); _rtrim(str); }
// Copie un nom saisi par l'utilisateur (pièce, volet, groupe) en retirant ce qui casserait le fichier
// de configuration (virgule, guillemet, retour à la ligne) ou permettrait une injection HTML dans
// l'interface (< > & ' \). Les caractères de contrôle sont ignorés.
[[maybe_unused]] static void sanitizeName(char *dest, const char *src, size_t size) {
  size_t j = 0;
  if(src) {
    for(size_t i = 0; src[i] != '\0' && j < size - 1; i++) {
      unsigned char c = (unsigned char)src[i];
      if(c < 0x20 || c == 0x7F || strchr("<>&\"',\\", c)) continue;
      dest[j++] = (char)c;
    }
  }
  dest[j] = '\0';
  _trim(dest);
}
// Comparaisons de temps robustes au débordement de millis() (49,7 jours) : toujours soustraire
// l'instant de départ, jamais comparer des sommes.
[[maybe_unused]] static inline bool elapsed(uint32_t since, uint32_t interval) { return (uint32_t)(millis() - since) >= interval; }
[[maybe_unused]] static inline bool reached(uint32_t when) { return (int32_t)(millis() - when) >= 0; }
struct rebootDelay_t {
  bool reboot = false;
  int rebootTime = 0;
  bool closed = false;
};
[[maybe_unused]] static bool toBoolean(const char *str, bool def) {
  if(!str) return def;
  if(strlen(str) == 0) return def;
  else if(str[0] == 't' || str[0] == 'T' || str[0] == '1') return true;
  else if(str[0] == 'f' || str[0] == 'F' || str[0] == '0') return false;
  return def;
}

class Timestamp {
  char _timeBuffer[128];
  public:
    time_t getUTC();
    time_t getUTC(time_t epoch);
    char * getISOTime();
    char * getISOTime(time_t epoch);
    char * formatISO(struct tm *dt, int tz);
    int tzOffset();
    static time_t parseUTCTime(const char *buff);
    static time_t mkUTCTime(struct tm *dt);
    static int calcTZOffset(time_t *dt);
    static time_t now();
    static unsigned long epoch();
};
#endif
