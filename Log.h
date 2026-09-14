#ifndef ESPSOMFY_LOG_H
#define ESPSOMFY_LOG_H
#include <Arduino.h>
// Journalisation série par niveaux. Les traces de débogage (trames radio, requêtes web, détails de
// persistance) ne sont pas compilées par défaut : elles coûtaient près de 30 Ko de flash sur une
// partition applicative pleine à 99 %.
//   0 : aucune trace
//   1 : erreurs uniquement
//   2 : erreurs et cycle de vie (démarrage, réseau, MQTT, OTA)  -- défaut
//   3 : tout
// Compiler avec --build-property "build.extra_flags=-DESPSOMFY_LOG_LEVEL=3" pour le débogage complet.
#ifndef ESPSOMFY_LOG_LEVEL
#define ESPSOMFY_LOG_LEVEL 2
#endif
#define LOG_NOOP do {} while(0)
#if ESPSOMFY_LOG_LEVEL >= 1
#define LOG_E(...) Serial.print(__VA_ARGS__)
#define LOG_ELN(...) Serial.println(__VA_ARGS__)
#define LOG_EF(...) Serial.printf(__VA_ARGS__)
#else
#define LOG_E(...) LOG_NOOP
#define LOG_ELN(...) LOG_NOOP
#define LOG_EF(...) LOG_NOOP
#endif
#if ESPSOMFY_LOG_LEVEL >= 2
#define LOG_I(...) Serial.print(__VA_ARGS__)
#define LOG_ILN(...) Serial.println(__VA_ARGS__)
#define LOG_IF(...) Serial.printf(__VA_ARGS__)
#else
#define LOG_I(...) LOG_NOOP
#define LOG_ILN(...) LOG_NOOP
#define LOG_IF(...) LOG_NOOP
#endif
#if ESPSOMFY_LOG_LEVEL >= 3
#define LOG_D(...) Serial.print(__VA_ARGS__)
#define LOG_DLN(...) Serial.println(__VA_ARGS__)
#define LOG_DF(...) Serial.printf(__VA_ARGS__)
#else
#define LOG_D(...) LOG_NOOP
#define LOG_DLN(...) LOG_NOOP
#define LOG_DF(...) LOG_NOOP
#endif
#endif
