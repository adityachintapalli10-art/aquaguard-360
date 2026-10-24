/*
  AquaGuard 360 - ESP32 flow meter node
  Sensor: YF-S201 style hall-effect flow sensor (F[Hz] = 7.5 * Q[L/min]; calibrate for your meter!)
  Wiring: sensor red -> 5V, black -> GND, yellow -> GPIO27 (use a divider/level shifter if the
  sensor output is 5 V; ESP32 GPIOs are 3.3 V).
  Sends flow_lpm + cumulative total_l over HTTPS every 10 s with a UTC timestamp (NTP).
*/
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include <time.h>
#include "secrets.h"

const int   FLOW_PIN        = 27;
const float PULSES_PER_L    = 450.0;   // YF-S201 ~ 450 pulses/litre; measure against a known volume
const unsigned long PERIOD  = 10000;   // ms between uploads

volatile unsigned long pulses = 0;
void IRAM_ATTR onPulse() { pulses++; }

double totalLitres = 0;
unsigned long lastSend = 0;

void connectWifi() {
  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  while (WiFi.status() != WL_CONNECTED) { delay(500); Serial.print('.'); }
  Serial.println("\nWiFi connected");
}

void syncTime() {
  configTime(0, 0, "pool.ntp.org", "time.google.com");
  time_t now = 0;
  while (now < 1700000000) { delay(500); time(&now); }   // wait for a valid clock
}

void setup() {
  Serial.begin(115200);
  pinMode(FLOW_PIN, INPUT_PULLUP);
  attachInterrupt(digitalPinToInterrupt(FLOW_PIN), onPulse, FALLING);
  connectWifi();
  syncTime();
  lastSend = millis();
}

void loop() {
  if (WiFi.status() != WL_CONNECTED) connectWifi();
  unsigned long nowMs = millis();
  if (nowMs - lastSend < PERIOD) return;

  noInterrupts(); unsigned long p = pulses; pulses = 0; interrupts();
  float dtMin   = (nowMs - lastSend) / 60000.0;
  lastSend      = nowMs;
  float litres  = p / PULSES_PER_L;
  float flowLpm = litres / dtMin;
  totalLitres  += litres;

  time_t t; time(&t);
  struct tm tmUtc; gmtime_r(&t, &tmUtc);
  char ts[24]; strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", &tmUtc);
  char body[160];
  snprintf(body, sizeof(body), "{\"ts\":\"%s\",\"flow_lpm\":%.3f,\"total_l\":%.3f}", ts, flowLpm, totalLitres);

  WiFiClientSecure client;
  // Production: pin your server's CA certificate with client.setCACert(ROOT_CA_PEM);
  // client.setInsecure() skips verification - use for local testing ONLY.
  client.setInsecure();
  HTTPClient http;
  if (http.begin(client, SERVER_URL)) {
    http.addHeader("Content-Type", "application/json");
    http.addHeader("X-API-Key", DEVICE_API_KEY);
    int code = http.POST((uint8_t*)body, strlen(body));
    Serial.printf("%s -> HTTP %d\n", body, code);
    http.end();
  }
}
