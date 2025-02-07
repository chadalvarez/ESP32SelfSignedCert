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

// Buffer sizes for certificate and key generation
#define CERT_BUFFER_SIZE 2048
#define KEY_BUFFER_SIZE  2048

/**
 * Structure containing certificate details.
 */
struct CertSettings {
    String commonName;    ///< Common Name (e.g., device name)
    String organization;  ///< Organization name
    String country;       ///< Country code (e.g., "US")
    String validFrom;     ///< Validity start time (YYYYMMDDHHMMSS)
    String validTo;       ///< Validity end time (YYYYMMDDHHMMSS)
};

/**
 * Class for generating self-signed certificates on the ESP32 using mbedTLS.
 * Certificates and keys are saved to LittleFS.
 */
class ESP32SelfSignedCert {
public:
    ESP32SelfSignedCert();
    ~ESP32SelfSignedCert();

    /**
     * Initialize the LittleFS filesystem.
     * @param format If true, format LittleFS if mounting fails.
     * @return True if LittleFS is successfully mounted, false otherwise.
     */
    bool beginFS(bool format = false);

    /**
     * Save data to a file in LittleFS.
     * @param filename The file path where data will be saved.
     * @param data A null-terminated string containing the data.
     * @return True if data is successfully saved; false otherwise.
     */
    bool saveToFile(const char *filename, const char *data);

    /**
     * Generate a self-signed certificate with the provided settings.
     * @param usePEM True to output in PEM format; false to output DER.
     * @param settings Structure containing certificate details.
     * @param certFile File path to save the generated certificate.
     * @param keyFile File path to save the generated private key.
     */
    void generateSelfSignedCertificate(bool usePEM,
                                         const CertSettings &settings,
                                         const char *certFile = "/cert.pem",
                                         const char *keyFile  = "/key.pem");

    /**
     * High-level generation function using default settings.
     * On success, the generated certificate and key are stored in internal buffers.
     * Certificates will be valid for 10 years from January 1 of the current or hardcoded year.
     * @return True if certificate generation is successful, false otherwise.
     */
    bool generate();

    /**
     * Get the generated certificate as a String.
     * @return A String containing the certificate.
     */
    String getCert();

    /**
     * Get the generated private key as a String.
     * @return A String containing the private key.
     */
    String getPrivateKey();

    /**
     * Print the contents of a file from LittleFS to Serial.
     * @param filename The file path to be printed.
     */
    void printFile(const char *filename);

    /**
     * Extract and print details from the generated certificate.
     * This function uses mbedTLS to parse the certificate stored in the internal buffer
     * and prints its details to Serial. It can be used as a means to verify that the
     * certificate was generated correctly.
     *
     * @return True if the certificate was parsed and its details extracted successfully; false otherwise.
     */
    bool extractCertDetails();

private:
    char certBuffer[CERT_BUFFER_SIZE]; ///< Buffer for the generated certificate.
    char keyBuffer[KEY_BUFFER_SIZE];     ///< Buffer for the generated private key.
};

#endif // ESP32SELFSIGNEDCERT_H
