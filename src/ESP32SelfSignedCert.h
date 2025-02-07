#ifndef ESP32SELFSIGNEDCERT_H
#define ESP32SELFSIGNEDCERT_H

#include <Arduino.h>
#include <FS.h>
#include <LittleFS.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/pk.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ssl.h>
#include <mbedtls/error.h>
#include <mbedtls/asn1write.h>

// Adjust buffer sizes as needed
#define CERT_BUFFER_SIZE 2048
#define KEY_BUFFER_SIZE  2048

// Settings structure for certificate details
struct CertSettings {
    String commonName;
    String organization;
    String country;
    String validFrom; // YYYYMMDDHHMMSS
    String validTo;   // YYYYMMDDHHMMSS
};

// Class for generating self-signed certificates
class ESP32SelfSignedCert {
public:
    ESP32SelfSignedCert();
    ~ESP32SelfSignedCert();

    // Initialize LittleFS (optional convenience function)
    bool beginFS();

    // Save data to a file in LittleFS
    bool saveToFile(const char *filename, const char *data);

    // Generate a self-signed certificate
    // - usePEM: true to output in PEM format, false for DER
    // - settings: custom certificate details
    // - certFile: file path to save certificate
    // - keyFile:  file path to save private key
    void generateSelfSignedCertificate(bool usePEM,
                                       const CertSettings &settings,
                                       const char *certFile = "/cert.pem",
                                       const char *keyFile  = "/key.pem");

private:
    char certBuffer[CERT_BUFFER_SIZE];
    char keyBuffer[KEY_BUFFER_SIZE];
};

#endif // ESP32SELFSIGNEDCERT_H
