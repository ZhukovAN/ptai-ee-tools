package com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.exceptions.GenericException;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.IOUtils;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.*;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Enumeration;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Slf4j
public class CertificateHelper {
    /**
     * Regular expression to extract certificate data from PEM-encoded file
     */
    protected static final Pattern parse = Pattern.compile("(?m)(?s)^-+BEGIN ([^-]+)-+$([^-]*)^-+END \\1-+$");

    /**
     * Method parses PEM-encoded string and fills resulting array with certificates
     * @param pem
     * @return
     * @throws GenericException
     */
    public static List<X509Certificate> readPem(@NonNull final String pem) throws GenericException {
        Matcher match = parse.matcher(new String(pem.getBytes(), StandardCharsets.ISO_8859_1));
        List<X509Certificate> res = new ArrayList<>();
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            while (match.find()) {
                byte[] binaryContent = Base64.getMimeDecoder().decode(match.group(2));
                if (!"CERTIFICATE".equalsIgnoreCase(match.group(1))) continue;
                Certificate certificate = cf.generateCertificate(new ByteArrayInputStream(binaryContent));
                if (certificate instanceof X509Certificate)
                    if (certificate.getPublicKey() instanceof RSAPublicKey)
                        res.add((X509Certificate) certificate);
            }
            return res;
        } catch (CertificateException e) {
            throw GenericException.raise("PEM read failed", e);
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
                builder.append("-----END CERTIFICATE-----").append(SEPARATOR);
            } catch (CertificateEncodingException e) {
                log.debug("Failed to encode certificate: {}", certificate.getSubjectDN().getName());
                log.debug("Exception details", e);
            }
        }
        return (0 == builder.length())
                ? null
                : IOUtils.toInputStream(builder.toString(), StandardCharsets.US_ASCII);
    }
}
