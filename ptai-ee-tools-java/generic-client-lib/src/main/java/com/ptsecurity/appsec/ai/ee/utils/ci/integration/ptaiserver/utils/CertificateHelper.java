package com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.utils;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.exceptions.ApiException;
import lombok.NonNull;
import lombok.extern.java.Log;
import org.apache.commons.io.IOUtils;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchProviderException;
import java.security.cert.*;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Enumeration;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Log
public class CertificateHelper {
    /**
     * Regular expression to extract certificate data from PEM-encoded file
     */
    protected static final Pattern parse = Pattern.compile("(?m)(?s)^-+BEGIN ([^-]+)-+$([^-]*)^-+END \\1-+$");

    /**
     * Method parses PEM-encoded string and fills resulting array with certificates
     * @param pem
     * @return
     * @throws ApiException
     */
    public static List<X509Certificate> readPem(@NonNull final String pem) throws ApiException {
        Matcher match = parse.matcher(new String(pem.getBytes(), StandardCharsets.ISO_8859_1));
        List<X509Certificate> res = new ArrayList<>();
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
            while (match.find()) {
                byte[] binaryContent = Base64.getMimeDecoder().decode(match.group(2));
                if (!"CERTIFICATE".equalsIgnoreCase(match.group(1))) continue;
                Certificate certificate = cf.generateCertificate(new ByteArrayInputStream(binaryContent));
                if (certificate instanceof X509Certificate)
                    if (certificate.getPublicKey() instanceof RSAPublicKey)
                        res.add((X509Certificate) certificate);
            }
            return res;
        } catch (NoSuchProviderException | CertificateException e) {
            throw ApiException.raise("PEM read failed", e);
        }
    }

    protected static final String SEPARATOR = System.getProperty("line.separator");
    protected static final Base64.Encoder ENCODER = Base64.getMimeEncoder(64, SEPARATOR.getBytes());

    public static InputStream cleanupCaPem(@NonNull final String pem) {
        List<X509Certificate> certificates = readPem(pem);
        if (certificates.isEmpty()) return null;

        StringBuilder builder = new StringBuilder();

        for (X509Certificate certificate : certificates) {
            try {
                byte[] encoded = certificate.getEncoded();
                builder.append("-----BEGIN CERTIFICATE-----").append(SEPARATOR);
                builder.append(ENCODER.encodeToString(encoded)).append(SEPARATOR);
                builder.append("-----END CERTIFICATE-----").append(SEPARATOR);;
            } catch (CertificateEncodingException e) {
                // TODO: Implement logging
                // log.error("Failed to encode certificate: {}", certificate.getSubjectDN().getName());
                // log.trace("Exception details:", e);
            }
        }
        return (0 == builder.length())
                ? null
                : IOUtils.toInputStream(builder.toString(), StandardCharsets.US_ASCII);
    }

    public static String trustStoreToPem(@NonNull final KeyStore trustStore) {
        try {
            StringBuilder builder = new StringBuilder();
            Enumeration<String> aliases = trustStore.aliases();
            while (aliases.hasMoreElements()) {
                String item = aliases.nextElement();
                if (!trustStore.isCertificateEntry(item)) continue;
                Certificate certificate = trustStore.getCertificate(item);
                if (certificate instanceof X509Certificate) {
                    if (certificate.getPublicKey() instanceof RSAPublicKey) {
                        X509Certificate x509 = (X509Certificate) certificate;
                        try {
                            byte[] encoded = certificate.getEncoded();
                            builder.append("-----BEGIN CERTIFICATE-----").append(SEPARATOR);
                            builder.append(ENCODER.encodeToString(encoded)).append(SEPARATOR);
                            builder.append("-----END CERTIFICATE-----").append(SEPARATOR);
                            ;
                        } catch (CertificateEncodingException e) {
                            // TODO: Implement logging
                            // log.error("Failed to encode certificate: {}", x509.getSubjectDN().getName());
                            // log.trace("Exception details:", e);
                        }
                    }
                }
            }
            return (0 == builder.length())
                    ? null
                    : builder.toString();
        } catch (KeyStoreException e) {
            // TODO: Implement logging
            // log.error("Failed to list truststore aliases");
            // log.trace("Exception details:", e);
            return null;
        }

    }
}
