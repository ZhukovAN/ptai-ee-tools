package com.ptsecurity.misc.tools.helpers;

import com.ptsecurity.misc.tools.exceptions.GenericException;
import lombok.NonNull;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;

import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.cert.*;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
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
    public static List<X509Certificate> readPem(@NonNull final String pem) throws CertificateException {
        Matcher match = parse.matcher(new String(pem.getBytes(), StandardCharsets.ISO_8859_1));
        List<X509Certificate> res = new ArrayList<>();
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
    }

    protected static final String SEPARATOR = System.getProperty("line.separator");
    protected static final Base64.Encoder ENCODER = Base64.getMimeEncoder(64, SEPARATOR.getBytes());

    public static InputStream cleanupCaPem(@NonNull final String pem) throws CertificateException, CertificateEncodingException {
        List<X509Certificate> certificates = readPem(pem);
        if (certificates.isEmpty()) return null;

        StringBuilder builder = new StringBuilder();

        for (X509Certificate certificate : certificates) {
            byte[] encoded = certificate.getEncoded();
            builder.append("-----BEGIN CERTIFICATE-----").append(SEPARATOR);
            builder.append(ENCODER.encodeToString(encoded)).append(SEPARATOR);
            builder.append("-----END CERTIFICATE-----").append(SEPARATOR);
        }
        return (0 == builder.length())
                ? null
                : IOUtils.toInputStream(builder.toString(), StandardCharsets.US_ASCII);
    }

    protected static class InsecureX509TrustManager implements X509TrustManager {
        @Override
        public void checkClientTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {

        }

        @Override
        public void checkServerTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {

        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    }

    @SneakyThrows
    public static X509TrustManager createTrustManager(final String caCertsPem, boolean insecure) {
        if (insecure) return new InsecureX509TrustManager();
        // Create in-memory keystore and fill it with caCertsPem data
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(null, null);
        if (StringUtils.isNotEmpty(caCertsPem)) {
            List<X509Certificate> certs = CertificateHelper.readPem(caCertsPem);
            for (X509Certificate cert : certs)
                keyStore.setCertificateEntry(UUID.randomUUID().toString(), cert);
        }
        // To avoid trustAnchors parameter must be non-empty we need to process separately
        // empty keystore case
        if (0 == keyStore.size()) return null;
        // Init trustManagerFactory with custom CA certificates
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(keyStore);
        return (X509TrustManager) trustManagerFactory.getTrustManagers()[0];
    }
}
