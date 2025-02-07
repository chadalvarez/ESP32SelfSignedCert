# ESP32SelfSignedCert

This Arduino library for ESP32 provides an easy way to generate self-signed certificates using mbedtls. Certificates can be generated in PEM or DER format, saved on LittleFS, and printed to Serial.

## Installation

1. Copy this folder to your Arduino/libraries directory, ensuring the folder name is ESP32SelfSignedCert.
2. Restart Arduino IDE.
3. Under `File -> Examples -> ESP32SelfSignedCert`, open `SelfSignedCertExample.ino`.

## Usage

Configure the certificate settings (e.g., common name, organization, country, etc.). Then call `generateSelfSignedCertificate()` to generate the certificate and key. See the example for details.
