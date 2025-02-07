#include "ESP32SelfSignedCert.h"
#include <time.h>  // For time functions used in generate()

/**
 * Constructor.
 */
ESP32SelfSignedCert::ESP32SelfSignedCert() {
    // Clear internal buffers upon initialization
    memset(certBuffer, 0, CERT_BUFFER_SIZE);
    memset(keyBuffer, 0, KEY_BUFFER_SIZE);
}

/**
 * Destructor.
 */
ESP32SelfSignedCert::~ESP32SelfSignedCert() {
    // No dynamic allocation used; nothing to free here.
}

/**
 * Initialize LittleFS.
 * If mounting fails and 'format' is true, attempt to format LittleFS.
 */
bool ESP32SelfSignedCert::beginFS(bool format) {
    if (!LittleFS.begin()) {
        Serial.println("[ESP32SelfSignedCert] Failed to mount LittleFS");
        if (format) {
            Serial.println("[ESP32SelfSignedCert] Formatting LittleFS...");
            if (LittleFS.format()) {
                Serial.println("[ESP32SelfSignedCert] Format successful. Re-mounting LittleFS...");
                if (!LittleFS.begin()) {
                    Serial.println("[ESP32SelfSignedCert] Failed to mount LittleFS after formatting");
                    return false;
                }
            } else {
                Serial.println("[ESP32SelfSignedCert] Formatting LittleFS failed");
                return false;
            }
        } else {
            return false;
        }
    }
    return true;
}

/**
 * Save a null-terminated string to a file in LittleFS.
 */
bool ESP32SelfSignedCert::saveToFile(const char *filename, const char *data) {
    File file = LittleFS.open(filename, "w");
    if (!file) {
        Serial.printf("[ESP32SelfSignedCert] Failed to open file %s for writing\n", filename);
        return false;
    }
    file.print(data);
    file.close();
    Serial.printf("[ESP32SelfSignedCert] Saved %s\n", filename);
    return true;
}

/**
 * Generate a self-signed certificate using mbedTLS with the provided settings.
 * The certificate and key are stored in the internal buffers and optionally saved
 * to LittleFS in PEM or DER format.
 */
void ESP32SelfSignedCert::generateSelfSignedCertificate(bool usePEM,
                                                        const CertSettings &settings,
                                                        const char *certFile,
                                                        const char *keyFile)
{
    // Build the subject string (e.g., "CN=ESP32,O=MyOrg,C=US")
    String subject = "CN=" + settings.commonName +
                     ",O=" + settings.organization +
                     ",C=" + settings.country;

    // Clear internal buffers
    memset(certBuffer, 0, CERT_BUFFER_SIZE);
    memset(keyBuffer, 0, KEY_BUFFER_SIZE);

    // Initialize mbedTLS contexts
    mbedtls_pk_context key;
    mbedtls_x509write_cert cert;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "self_signed_cert";

    mbedtls_pk_init(&key);
    mbedtls_x509write_crt_init(&cert);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    // Seed the random number generator
    int ret = mbedtls_ctr_drbg_seed(&ctr_drbg,
                                    mbedtls_entropy_func,
                                    &entropy,
                                    (const unsigned char *)pers,
                                    strlen(pers));
    if (ret != 0) {
        Serial.println("[ESP32SelfSignedCert] Failed to seed RNG");
        goto cleanup;
    }

    // Set up key context for a 2048-bit RSA key pair
    ret = mbedtls_pk_setup(&key, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
    if (ret != 0) {
        Serial.println("[ESP32SelfSignedCert] Failed to setup key context");
        goto cleanup;
    }
    ret = mbedtls_rsa_gen_key(mbedtls_pk_rsa(key),
                              mbedtls_ctr_drbg_random,
                              &ctr_drbg,
                              2048,
                              65537);
    if (ret != 0) {
        Serial.println("[ESP32SelfSignedCert] Failed to generate RSA key pair");
        goto cleanup;
    }

    // Set both the subject and issuer name (self-signed certificate)
    ret = mbedtls_x509write_crt_set_subject_name(&cert, subject.c_str());
    if (ret != 0) {
        Serial.printf("[ESP32SelfSignedCert] Failed to set subject name, error 0x%04X\n", -ret);
        goto cleanup;
    }
    ret = mbedtls_x509write_crt_set_issuer_name(&cert, subject.c_str());
    if (ret != 0) {
        Serial.printf("[ESP32SelfSignedCert] Failed to set issuer name, error 0x%04X\n", -ret);
        goto cleanup;
    }

    // Generate a random serial number
    unsigned char serial[16];
    mbedtls_ctr_drbg_random(&ctr_drbg, serial, sizeof(serial));

#if ESP_ARDUINO_VERSION >= ESP_ARDUINO_VERSION_VAL(3, 0, 0)
    ret = mbedtls_x509write_crt_set_serial_raw(&cert, serial, sizeof(serial));
    if (ret != 0) {
        Serial.printf("[ESP32SelfSignedCert] Failed to set serial raw, error 0x%04X\n", -ret);
        goto cleanup;
    }
#else
    // For older ESP32 Arduino versions
    {
        mbedtls_mpi serial_mpi;
        mbedtls_mpi_init(&serial_mpi);
        mbedtls_mpi_read_binary(&serial_mpi, serial, sizeof(serial));
        ret = mbedtls_x509write_crt_set_serial(&cert, &serial_mpi);
        mbedtls_mpi_free(&serial_mpi);
        if (ret != 0) {
            Serial.printf("[ESP32SelfSignedCert] Failed to set serial, error 0x%04X\n", -ret);
            goto cleanup;
        }
    }
#endif

    // Set certificate validity period (format: YYYYMMDDHHMMSS)
    ret = mbedtls_x509write_crt_set_validity(&cert,
                                             settings.validFrom.c_str(),
                                             settings.validTo.c_str());
    if (ret != 0) {
        Serial.printf("[ESP32SelfSignedCert] Failed to set validity, error 0x%04X\n", -ret);
        goto cleanup;
    }

    // Configure certificate version and hash algorithm
    mbedtls_x509write_crt_set_md_alg(&cert, MBEDTLS_MD_SHA256);
    mbedtls_x509write_crt_set_version(&cert, MBEDTLS_X509_CRT_VERSION_3);

    // Bind the key to the certificate as both subject and issuer key
    mbedtls_x509write_crt_set_subject_key(&cert, &key);
    mbedtls_x509write_crt_set_issuer_key(&cert, &key);

    // Write the certificate into the internal buffer
    if (usePEM) {
        ret = mbedtls_x509write_crt_pem(&cert,
                                        (unsigned char *)certBuffer,
                                        CERT_BUFFER_SIZE,
                                        mbedtls_ctr_drbg_random,
                                        &ctr_drbg);
    } else {
        ret = mbedtls_x509write_crt_der(&cert,
                                        (unsigned char *)certBuffer,
                                        CERT_BUFFER_SIZE,
                                        mbedtls_ctr_drbg_random,
                                        &ctr_drbg);
    }
    if (ret < 0) {
        Serial.printf("[ESP32SelfSignedCert] Failed to write certificate: -0x%04X\n", -ret);
        goto cleanup;
    }

    // Write the private key (always in PEM format) into the internal buffer
    ret = mbedtls_pk_write_key_pem(&key, (unsigned char *)keyBuffer, KEY_BUFFER_SIZE);
    if (ret != 0) {
        Serial.println("[ESP32SelfSignedCert] Failed to write private key");
        goto cleanup;
    }

    // Save certificate and key to files in LittleFS
    if (usePEM) {
        saveToFile(certFile, certBuffer);
        saveToFile(keyFile, keyBuffer);

        Serial.println("[ESP32SelfSignedCert] Certificate (PEM):\n");
        Serial.println(certBuffer);
        Serial.println("[ESP32SelfSignedCert] Private Key (PEM):\n");
        Serial.println(keyBuffer);
    } else {
        File derFile = LittleFS.open(certFile, "w");
        if (!derFile) {
            Serial.printf("[ESP32SelfSignedCert] Failed to open DER file %s\n", certFile);
        } else {
            derFile.write((uint8_t*)certBuffer, ret);
            derFile.close();
            Serial.printf("[ESP32SelfSignedCert] Saved DER certificate to %s\n", certFile);
        }
        saveToFile(keyFile, keyBuffer);

        Serial.println("[ESP32SelfSignedCert] Certificate (DER - hex format):\n");
        for (int i = 0; i < ret; i++) {
            Serial.printf("%02X", certBuffer[i] & 0xFF);
            if ((i + 1) % 16 == 0)
                Serial.println();
            else
                Serial.print(" ");
        }
        Serial.println();
    }

cleanup:
    // Free mbedTLS contexts
    mbedtls_pk_free(&key);
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_x509write_crt_free(&cert);
}

/**
 * High-level generation function that uses default certificate settings.
 * If the system time is valid, the certificate's validity is set from January 1
 * of the current year to January 1 ten years later. Otherwise, it falls back to
 * hardcoded dates (January 1, 2025 to January 1, 2035).
 */
bool ESP32SelfSignedCert::generate() {
    // Define default settings for certificate details
    CertSettings settings;
    settings.commonName   = "ESP32";
    settings.organization = "MyOrganization";
    settings.country      = "US";

    // Obtain current system time
    time_t now = time(NULL);
    struct tm timeinfo;
    localtime_r(&now, &timeinfo);
    int currentYear = timeinfo.tm_year + 1900;

    // Prepare validity date strings (format: "YYYYMMDDHHMMSS")
    char validFrom[15];
    char validTo[15];

    // Check for valid system time; use fallback dates if necessary
    if (currentYear < 2000) {
        // Fallback: January 1, 2025 to January 1, 2035
        sprintf(validFrom, "%04d0101000000", 2025);
        sprintf(validTo,   "%04d0101000000", 2035);
        Serial.printf("[ESP32SelfSignedCert] Invalid system time. Using hardcoded validity: %s to %s\n", validFrom, validTo);
    } else {
        // Use current year: validity from January 1, currentYear to January 1, currentYear+10
        sprintf(validFrom, "%04d0101000000", currentYear);
        sprintf(validTo,   "%04d0101000000", currentYear + 10);
        Serial.printf("[ESP32SelfSignedCert] Generating certificate valid from %s to %s\n", validFrom, validTo);
    }
    settings.validFrom = String(validFrom);
    settings.validTo   = String(validTo);

    // Generate certificate in PEM format and save to default file paths
    generateSelfSignedCertificate(true, settings, "/cert.pem", "/key.pem");

    // Confirm generation succeeded by checking that the internal buffers are populated
    if (strlen(certBuffer) == 0 || strlen(keyBuffer) == 0) {
        Serial.println("[ESP32SelfSignedCert] Certificate generation failed");
        return false;
    }
    return true;
}

/**
 * Return the generated certificate from the internal buffer.
 */
String ESP32SelfSignedCert::getCert() {
    return String(certBuffer);
}

/**
 * Return the generated private key from the internal buffer.
 */
String ESP32SelfSignedCert::getPrivateKey() {
    return String(keyBuffer);
}

/**
 * Print the contents of a file stored in LittleFS to Serial.
 */
void ESP32SelfSignedCert::printFile(const char *filename) {
    File file = LittleFS.open(filename, "r");
    if (!file) {
        Serial.printf("[ESP32SelfSignedCert] Failed to open file %s for reading\n", filename);
        return;
    }
    Serial.printf("[ESP32SelfSignedCert] Contents of %s:\n", filename);
    while (file.available()) {
        Serial.write(file.read());
    }
    file.close();
    Serial.println();
}

/**
 * Extract and print details from the generated certificate.
 * This function parses the certificate stored in certBuffer using mbedTLS,
 * prints a human-readable summary to Serial, and returns true if the parsing
 * and extraction were successful.
 */
bool ESP32SelfSignedCert::extractCertDetails() {
    // Ensure the certificate buffer is not empty
    if (strlen(certBuffer) == 0) {
        Serial.println("[ESP32SelfSignedCert] No certificate available for parsing.");
        return false;
    }

    mbedtls_x509_crt crt;
    mbedtls_x509_crt_init(&crt);

    // Parse the certificate from the internal PEM buffer (including the null terminator)
    int ret = mbedtls_x509_crt_parse(&crt, (const unsigned char*)certBuffer, strlen(certBuffer) + 1);
    if (ret != 0) {
        Serial.printf("[ESP32SelfSignedCert] Failed to parse certificate, error: -0x%04X\n", -ret);
        mbedtls_x509_crt_free(&crt);
        return false;
    }

    // Create a buffer to hold the certificate info
    char infoBuf[1024];
    mbedtls_x509_crt_info(infoBuf, sizeof(infoBuf) - 1, "  ", &crt);
    Serial.println("[ESP32SelfSignedCert] Certificate Details:");
    Serial.println(infoBuf);

    mbedtls_x509_crt_free(&crt);
    return true;
}
