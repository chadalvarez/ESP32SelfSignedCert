// You can verify if certs match here: <https://www.sslshopper.com/certificate-key-matcher.html>

#include "ESP32SelfSignedCert.h"

ESP32SelfSignedCert myCert;


// ALTERNATIVE: Define certificate settings (adjust as needed)
CertSettings myCertSettings = {
    "ESP32",             // Common Name (CN)
    "MyOrganization",    // Organization (O)
    "US",                // Country (C)
    "20250101000000",    // Valid from (YYYYMMDDHHMMSS)
    "20350101000000"     // Valid to (YYYYMMDDHHMMSS)
};

void setup() {
  delay(1000);
  Serial.begin(115200);

  Serial.println("\n\nGenerating Certificate...\n\n");

  // Initialize LittleFS with optional formatting
  if (!myCert.beginFS(true)) {
    Serial.println("Failed to initialize LittleFS.");
    while (true);
  }

  // Generate a self-signed certificate using default settings
  if (myCert.generate()) {
    Serial.println("Certificate generated successfully.");
  } else {
    Serial.println("Certificate generation failed.");
  }



  // ALTERNATIVE: Generate in PEM format (true). You can also pass false for DER
  //certGenerator.generateSelfSignedCertificate(true, myCertSettings, "/cert.pem", "/privkey.pem");



/*
  // Print certificate and key to Serial
  Serial.println("Certificate:");
  Serial.println(myCert.getCert());
  Serial.println("Private Key:");
  Serial.println(myCert.getPrivateKey());

  // Print contents of the saved certificate file
  myCert.printFile("/cert.pem");
/**/

  // Extract and print certificate details to validate the certificate
  if (myCert.extractCertDetails()) {
    Serial.println("Certificate details extracted successfully.");
  } else {
    Serial.println("Failed to extract certificate details.");
  }

}

void loop() {

}

