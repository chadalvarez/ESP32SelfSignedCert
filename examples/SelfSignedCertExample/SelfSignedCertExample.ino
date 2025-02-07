#include <Arduino.h>
#include <WiFi.h>
#include <LittleFS.h>
#include "ESP32SelfSignedCert.h"

// Create an instance of the library
ESP32SelfSignedCert certGenerator;

// Define certificate settings (adjust as needed)
CertSettings myCertSettings = {
    "ESP32",             // Common Name (CN)
    "MyOrganization",    // Organization (O)
    "US",                // Country (C)
    "20250101000000",    // Valid from (YYYYMMDDHHMMSS)
    "20350101000000"     // Valid to (YYYYMMDDHHMMSS)
};

void setup() {
    Serial.begin(115200);
    delay(1000);

    // Start LittleFS
    if (!certGenerator.beginFS()) {
        Serial.println("LittleFS init failed. Halting.");
        while (1) { delay(10); }
    }

    Serial.println("\n[Example] Generating Self-Signed Certificate...");

    // Generate in PEM format (true). You can also pass false for DER
    certGenerator.generateSelfSignedCertificate(true, myCertSettings,
                                                "/cert.pem",
                                                "/privkey.pem");

    Serial.println("\nDone generating certificate.");
}

void loop() {
    // ...
}
