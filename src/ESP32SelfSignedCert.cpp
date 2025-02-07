#include "ESP32SelfSignedCert.h"

ESP32SelfSignedCert::ESP32SelfSignedCert() {
    // Constructor
}

ESP32SelfSignedCert::~ESP32SelfSignedCert() {
    // Destructor
}

bool ESP32SelfSignedCert::beginFS() {
    if (!LittleFS.begin()) {
        Serial.println("[ESP32SelfSignedCert] Failed to mount LittleFS");
        return false;
    }
    return true;
}

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

void ESP32SelfSignedCert::generateSelfSignedCertificate(bool usePEM,
                                                        const CertSettings &settings,
                                                        const char *certFile,
                                                        const char *keyFile)
{

    // Configure certificate details
    String subject = "CN=" + settings.commonName +
                     ",O=" + settings.organization +
                     ",C=" + settings.country;

    // Clear buffers
    memset(certBuffer, 0, CERT_BUFFER_SIZE);
    memset(keyBuffer, 0, KEY_BUFFER_SIZE);

    mbedtls_pk_context key;
    mbedtls_x509write_cert cert;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    const char *pers = "self_signed_cert";

    // Initialize contexts
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

    // Generate a 2048-bit RSA key pair
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

    // Generate and set serial number
    unsigned char serial[16];
    mbedtls_ctr_drbg_random(&ctr_drbg, serial, sizeof(serial));

#if ESP_ARDUINO_VERSION >= ESP_ARDUINO_VERSION_VAL(3, 0, 0)
    ret = mbedtls_x509write_crt_set_serial_raw(&cert, serial, sizeof(serial));
    if (ret != 0) {
        Serial.printf("[ESP32SelfSignedCert] Failed to set serial raw, error 0x%04X\n", -ret);
        goto cleanup;
    }
#else
    // For ESP32 Arduino < v3.0.0
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

    // Validity: YYYYMMDDHHMMSS
    ret = mbedtls_x509write_crt_set_validity(&cert,
                                             settings.validFrom.c_str(),
                                             settings.validTo.c_str());
    if (ret != 0) {
        Serial.printf("[ESP32SelfSignedCert] Failed to set validity, error 0x%04X\n", -ret);
        goto cleanup;
    }

    mbedtls_x509write_crt_set_md_alg(&cert, MBEDTLS_MD_SHA256);
    mbedtls_x509write_crt_set_version(&cert, MBEDTLS_X509_CRT_VERSION_3);
    mbedtls_x509write_crt_set_subject_key(&cert, &key);
    mbedtls_x509write_crt_set_issuer_key(&cert, &key);

    // Write the certificate to buffer
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

    // Write the private key to buffer (PEM format)
    ret = mbedtls_pk_write_key_pem(&key, (unsigned char *)keyBuffer, KEY_BUFFER_SIZE);
    if (ret != 0) {
        Serial.println("[ESP32SelfSignedCert] Failed to write private key");
        goto cleanup;
    }

    // Save the results to LITTLEFS
    if (usePEM) {
        // PEM certificate
        saveToFile(certFile, certBuffer);
        // PEM private key
        saveToFile(keyFile, keyBuffer);

        Serial.println("[ESP32SelfSignedCert] Certificate (PEM):\n");
        Serial.println(certBuffer);
        Serial.println("[ESP32SelfSignedCert] Private Key (PEM):\n");
        Serial.println(keyBuffer);
    } else {
        // DER certificate (binary). 'ret' is the size in bytes
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
            if ((i + 1) % 16 == 0) Serial.println();
            else Serial.print(" ");
        }
        Serial.println();
    }

cleanup:
    // Cleanup
    mbedtls_pk_free(&key);
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_x509write_crt_free(&cert);
}
