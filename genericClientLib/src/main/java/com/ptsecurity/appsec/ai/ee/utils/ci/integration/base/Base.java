package com.ptsecurity.appsec.ai.ee.utils.ci.integration.base;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.exceptions.BaseClientException;
import lombok.Getter;
import lombok.Setter;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;

import javax.net.ssl.*;
import java.io.*;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Base {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Setter
    @Getter
    protected boolean verbose = false;

    @Setter
    @Getter
    protected PrintStream log = null;

    @Setter
    @Getter
    protected String logPrefix = "PTAI ";

    public void log(String value) {
        if (null != this.log)
            this.log.print(this.logPrefix + value);
    }

    public void log(String format, Object ... value) {
        this.log(String.format(format, value));
    }

    public void log(Throwable value) {
        this.log("%s\r\n", value.getMessage());
        if (this.verbose) value.printStackTrace(this.log);
    }

    @Setter
    @Getter
    protected String url = "";

    /**
     * PEM-encoded private key (with optional password protection) and optional CA certificate chain
     */
    @Setter
    @Getter
    protected String keyPem = "";

    /**
     * PEM-encoded CA certificate chain
     */
    @Setter
    @Getter
    protected String caCertsPem = "";

    @Setter
    @Getter
    protected String keyPassword = "";

    @Setter
    @Getter
    protected String keyStoreFile = "";
    @Setter
    @Getter
    protected String keyStoreType = "JKS";
    @Setter
    @Getter
    protected String keyStorePassword = "";
    @Setter
    @Getter
    protected String keyAlias = "";
    @Setter
    @Getter
    protected String trustStoreFile = "";
    @Setter
    @Getter
    protected String trustStoreType = "JKS";
    @Setter
    @Getter
    protected String trustStorePassword = "";

    @Setter
    @Getter
    protected boolean checkKu = false;
    @Setter
    @Getter
    protected boolean checkEku = false;

    protected KeyStore keyStore = null;
    protected List<X509Certificate> caCerts = new ArrayList<>();

    final static Pattern parse = Pattern.compile("(?m)(?s)^-+BEGIN ([^-]+)-+$([^-]*)^-+END \\1-+$");

    public void baseInit() throws BaseClientException {
        if (StringUtils.isEmpty(this.url)) throw new BaseClientException("URL must not be empty");

        try {
            List<RSAPrivateKey> keys = new ArrayList<>();
            List<X509Certificate> certs = new ArrayList<>();
            if (StringUtils.isNotEmpty(this.keyPem))
                this.keyStore = this.checkKey(this.keyPem, this.keyPassword);
            else if (StringUtils.isNotEmpty(this.keyStoreFile)) {
                KeyStore keyStore = KeyStore.getInstance(this.keyStoreType);
                char[] pass = StringUtils.isEmpty(this.keyStorePassword) ? "".toCharArray() : this.keyStorePassword.toCharArray();
                keyStore.load(new FileInputStream(this.keyStoreFile), pass);
                Enumeration<String> aliases = keyStore.aliases();
                while (aliases.hasMoreElements()) {
                    String alias = aliases.nextElement();
                    if (keyStore.isKeyEntry(alias)) {
                        if (!StringUtils.isEmpty(this.keyAlias))
                            if (!this.keyAlias.equals(alias)) continue;
                        if (!keyStore.entryInstanceOf(alias , KeyStore.PrivateKeyEntry.class)) continue;
                        char[] keyPass = StringUtils.isEmpty(this.keyStorePassword) ? "".toCharArray() : this.keyStorePassword.toCharArray();
                        try {
                            Key key = keyStore.getKey(alias, keyPass);
                            if (key instanceof RSAPrivateKey)
                                keys.add((RSAPrivateKey) key);
                            Certificate[] clientCerts = keyStore.getCertificateChain(alias);
                            for (Certificate cert : clientCerts)
                                if (cert instanceof X509Certificate)
                                    if (cert.getPublicKey() instanceof RSAPublicKey)
                                        certs.add((X509Certificate) cert);
                        } catch (UnrecoverableKeyException e) {
                            this.log(e);
                        }
                    } else if (keyStore.isCertificateEntry(alias)) {
                        Certificate cert = keyStore.getCertificate(alias);
                        if (cert instanceof X509Certificate)
                            if (cert.getPublicKey() instanceof RSAPublicKey)
                                certs.add((X509Certificate) cert);
                    }
                }
                this.keyStore = this.checkKey(keys, certs);
            }

            if (StringUtils.isNotEmpty(this.caCertsPem))
                this.caCerts = this.checkCaCerts(this.caCertsPem);
            else if (StringUtils.isNotEmpty(this.trustStoreFile)) {
                KeyStore trustStore = KeyStore.getInstance(this.trustStoreType);
                char[] pass = StringUtils.isEmpty(this.trustStorePassword) ? "".toCharArray() : this.trustStorePassword.toCharArray();
                trustStore.load(new FileInputStream(this.trustStoreFile), pass);
                Enumeration<String> aliases = trustStore.aliases();
                while (aliases.hasMoreElements()) {
                    String item = aliases.nextElement();
                    if (!trustStore.isCertificateEntry(item)) continue;
                    Certificate cert = trustStore.getCertificate(item);
                    if (cert instanceof X509Certificate)
                        if (cert.getPublicKey() instanceof RSAPublicKey)
                            this.caCerts.add((X509Certificate) cert);
                }
            }
        } catch (IOException | NoSuchAlgorithmException | CertificateException | KeyStoreException e) {
            throw new BaseClientException(e.getMessage(), e);
        }
    }

    public void initClients(Object ... clients) throws BaseClientException {
        try {
            for (Object client : clients) {
                Method method = client.getClass().getMethod("setBasePath", String.class);
                method.invoke(client, this.url);
                method = client.getClass().getMethod("getHttpClient");
                Object httpClient = method.invoke(client);
                method = httpClient.getClass().getMethod("setReadTimeout", long.class, TimeUnit.class);
                method.invoke(httpClient, 3600, TimeUnit.SECONDS);
                method = httpClient.getClass().getMethod("setWriteTimeout", long.class, TimeUnit.class);
                method.invoke(httpClient, 3600, TimeUnit.SECONDS);
            }
            if (!"https".equalsIgnoreCase(new URL(this.url).getProtocol())) return;

            HostnameVerifier verifier = new HostnameVerifier() {
                @Override
                public boolean verify(String hostname, SSLSession session) { return true; }
            };

            StringBuilder caCerts = new StringBuilder();
            final Base64.Encoder encoder = Base64.getMimeEncoder(64, System.getProperty("line.separator").getBytes());
            for (X509Certificate cert : this.caCerts) {
                caCerts.append("-----BEGIN CERTIFICATE-----");
                caCerts.append(System.getProperty("line.separator"));
                caCerts.append(new String(encoder.encode(cert.getEncoded())));
                caCerts.append(System.getProperty("line.separator"));
                caCerts.append("-----END CERTIFICATE-----");
                caCerts.append(System.getProperty("line.separator"));
            }
            KeyManagerFactory kmf = null;
            if (null != this.keyStore) {
                kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
                kmf.init(this.keyStore, null);
            }
            for (Object client : clients) {
                Method method;
                if (null != kmf) {
                    method = client.getClass().getMethod("setKeyManagers", KeyManager[].class);
                    KeyManager[] keyManagers = kmf.getKeyManagers();
                    method.invoke(client, new Object[]{keyManagers});
                }
                method = client.getClass().getMethod("setSslCaCert", InputStream.class);
                InputStream stream = new ByteArrayInputStream(caCerts.toString().getBytes());
                method.invoke(client, stream);
                method = client.getClass().getMethod("getHttpClient");
                Object httpClient = method.invoke(client);
                method = httpClient.getClass().getMethod("setHostnameVerifier", HostnameVerifier.class);
                method.invoke(httpClient, verifier);
            }
        } catch (NoSuchMethodException | IllegalAccessException | InvocationTargetException | CertificateEncodingException | KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException | MalformedURLException e) {
            throw new BaseClientException(e.getMessage(), e);
        }
    }

    /**
     * @param keyStore Keystore
     * @param alias Alias of certificate to check
     * @param keyPassword Key password
     * @return If certificate is good for SSL client authentication
     */
    protected boolean checkAlias(KeyStore keyStore, String alias, char[] keyPassword) {
        try {
            Key key = keyStore.getKey(
                    Optional.of(alias).orElse(""),
                    keyPassword);
            if (null == key) return false;
            X509Certificate certificate = (X509Certificate) keyStore.getCertificate(Optional.of(alias).orElse(""));
            if (null == certificate) return false;
            if (this.checkEku) {
                final String EKU_SSL_CLIENT_AUTH = "1.3.6.1.5.5.7.3.2";
                if (null == certificate.getExtendedKeyUsage()) return false;
                if (!certificate.getExtendedKeyUsage().contains(EKU_SSL_CLIENT_AUTH)) return false;
            }
            if (this.checkKu) {
                final int KU_DIGITAL_SIGNATURE = 0;
                boolean[] keyUsage = certificate.getKeyUsage();
                return (null != keyUsage) && keyUsage[KU_DIGITAL_SIGNATURE];
            }
            return true;
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException | CertificateParsingException e) {
            this.log(e.getMessage());
            return false;
        }
    }

    public List<X509Certificate> checkCaCerts(final String caCertsPem) throws BaseClientException {
        Matcher match = parse.matcher(new String(caCertsPem.getBytes(), StandardCharsets.ISO_8859_1));
        List<X509Certificate> caCerts = new ArrayList<>();
        try {
            while (match.find()) {
                byte[] binaryContent = Base64.getMimeDecoder().decode(match.group(2));
                if (!"CERTIFICATE".equalsIgnoreCase(match.group(1))) continue;
                CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
                Certificate cert = cf.generateCertificate(new ByteArrayInputStream(binaryContent));
                if (cert instanceof X509Certificate)
                    if (cert.getPublicKey() instanceof RSAPublicKey)
                        caCerts.add((X509Certificate) cert);
            }
            KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
            trustStore.load(null, null);
            int index = 0;
            for (Certificate certificate : caCerts)
                trustStore.setCertificateEntry("ca" + index++, certificate);
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(trustStore);
            return caCerts;
        } catch (NoSuchProviderException | CertificateException | KeyStoreException | IOException | NoSuchAlgorithmException e) {
            this.log(e);
            throw new BaseClientException(e.getMessage(), e);
        }
    }

    public KeyStore checkKey(final List<RSAPrivateKey> keys, final List<X509Certificate> certs) throws BaseClientException {
        try {
            // If we have a key than only one should be added
            if (1 < keys.size())
                throw new BaseClientException("More than one private key found");
            if (0 == keys.size())
                throw new BaseClientException("No private key found");
            for (X509Certificate cert : certs) {
                if (!keys.get(0).getModulus().equals(((RSAPublicKey) (cert.getPublicKey())).getModulus())) continue;
                if (this.checkKu) {
                    final int KU_DIGITAL_SIGNATURE = 0;
                    boolean[] keyUsage = cert.getKeyUsage();
                    if ((null == keyUsage) || !keyUsage[KU_DIGITAL_SIGNATURE])
                        throw new BaseClientException("Certificate KU check failed");
                }
                if (this.checkEku) {
                    final String EKU_SSL_CLIENT_AUTH = "1.3.6.1.5.5.7.3.2";
                    if (null == cert.getExtendedKeyUsage())
                        throw new BaseClientException("Certificate EKU check failed");
                    if (!cert.getExtendedKeyUsage().contains(EKU_SSL_CLIENT_AUTH))
                        throw new BaseClientException("Certificate EKU check failed");
                }
                KeyStore keyStore = KeyStore.getInstance("PKCS12", "BC");
                keyStore.load(null, null);
                keyStore.setKeyEntry("SSL", keys.get(0), null, new Certificate[]{cert});
                KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
                kmf.init(keyStore, null);
                return keyStore;
            }
            throw new BaseClientException("Certificate not found for private key");
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException | NoSuchProviderException | UnrecoverableKeyException e) {
            this.log(e);
            throw new BaseClientException(e.getMessage(), e);
        }
    }

    public KeyStore checkKey(final String keyPem, final String keyPassword) throws BaseClientException {
        Matcher match = parse.matcher(new String(keyPem.getBytes(), StandardCharsets.ISO_8859_1));
        List<RSAPrivateKey> keys = new ArrayList<>();
        List<X509Certificate> certs = new ArrayList<>();
        try {
            while (match.find()) {
                byte[] binaryContent = Base64.getMimeDecoder().decode(match.group(2));
                if ("CERTIFICATE".equalsIgnoreCase(match.group(1))) {
                    CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
                    Certificate cert = cf.generateCertificate(new ByteArrayInputStream(binaryContent));
                    if (cert instanceof X509Certificate)
                        if (cert.getPublicKey() instanceof RSAPublicKey)
                            certs.add((X509Certificate) cert);
                } else if ("PRIVATE KEY".equalsIgnoreCase(match.group(1))) {
                    KeyFactory kf = KeyFactory.getInstance("RSA", "BC");
                    PrivateKey key = kf.generatePrivate(new PKCS8EncodedKeySpec(binaryContent));
                    if (key instanceof RSAPrivateKey)
                        keys.add((RSAPrivateKey) key);
                } else if ("ENCRYPTED PRIVATE KEY".equalsIgnoreCase(match.group(1))) {
                    try (PEMParser keyReader = new PEMParser(new StringReader(match.group(0)))) {
                        JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
                        char[] pass = StringUtils.isEmpty(keyPassword) ? "".toCharArray() : keyPassword.toCharArray();
                        InputDecryptorProvider decryptionProv = new JceOpenSSLPKCS8DecryptorProviderBuilder().build(pass);
                        Object keyPair = keyReader.readObject();
                        if (keyPair instanceof PKCS8EncryptedPrivateKeyInfo) {
                            PrivateKeyInfo keyInfo;
                            keyInfo = ((PKCS8EncryptedPrivateKeyInfo) keyPair).decryptPrivateKeyInfo(decryptionProv);
                            PrivateKey key = converter.getPrivateKey(keyInfo);
                            if (key instanceof RSAPrivateKey)
                                keys.add((RSAPrivateKey) key);
                        }
                    }
                }
            }
            return checkKey(keys, certs);
        } catch (NoSuchProviderException | CertificateException | IOException | NoSuchAlgorithmException | InvalidKeySpecException | PKCSException | OperatorCreationException e) {
            this.log(e);
            throw new BaseClientException(e.getMessage(), e);
        }
    }
}
