package com.ptsecurity.appsec.ai.ee.utils.ci.integration.base;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.exceptions.BaseClientException;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.java.Log;
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
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Log
public class Base {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    protected static boolean jceFixApplied = false;

    @Setter
    @Getter
    protected boolean verbose = false;

    @Setter
    @Getter
    protected PrintStream consoleLog = null;

    @Setter
    @Getter
    protected String logPrefix = "[PTAI] ";

    public void log(String value) {
        if (null != this.consoleLog)
            this.consoleLog.print(this.logPrefix + value);
    }

    public void log(String format, Object ... value) {
        this.log(String.format(format, value));
    }

    public void log(Throwable value) {
        if (StringUtils.isNotEmpty(value.getMessage()))
            this.log("%s\r\n", value.getMessage());
        if (this.verbose) value.printStackTrace(this.consoleLog);
    }

    protected void removeCryptographyRestrictions() {
        if (!isRestrictedCryptography()) {
            log.log(Level.INFO, "No need to fix JCE");
            jceFixApplied = true;
            return;
        }
        try {
            /*
             * Do the following, but with reflection to bypass access checks:
             *
             * JceSecurity.isRestricted = false;
             * JceSecurity.defaultPolicy.perms.clear();
             * JceSecurity.defaultPolicy.add(CryptoAllPermission.INSTANCE);
             */
            final Class jceSecurity = Class.forName("javax.crypto.JceSecurity");
            final Class cryptoPermissions = Class.forName("javax.crypto.CryptoPermissions");
            final Class cryptoAllPermission = Class.forName("javax.crypto.CryptoAllPermission");
            final Field isRestrictedField = jceSecurity.getDeclaredField("isRestricted");
            isRestrictedField.setAccessible(true);
            final Field modifiersField = Field.class.getDeclaredField("modifiers");
            modifiersField.setAccessible(true);
            modifiersField.setInt(isRestrictedField, isRestrictedField.getModifiers() & ~Modifier.FINAL);
            if (isRestrictedField.getBoolean(null))
                isRestrictedField.set(null, false);
            final Field defaultPolicyField = jceSecurity.getDeclaredField("defaultPolicy");
            defaultPolicyField.setAccessible(true);
            final PermissionCollection defaultPolicy = (PermissionCollection) defaultPolicyField.get(null);
            final Field perms = cryptoPermissions.getDeclaredField("perms");
            perms.setAccessible(true);
            ((Map<?, ?>)perms.get(defaultPolicy)).clear();
            final Field instance = cryptoAllPermission.getDeclaredField("INSTANCE");
            instance.setAccessible(true);
            defaultPolicy.add((Permission)instance.get(null));
            jceFixApplied = true;
        } catch (final Exception e) {
            log.log(Level.SEVERE, "Restrictions removal failed", e);
            jceFixApplied = false;
        }
    }
    private static boolean isRestrictedCryptography() {
        // This matches Oracle Java 7 and 8, but not Java 9 or OpenJDK.
        final String name = System.getProperty("java.runtime.name");
        final String ver = System.getProperty("java.version");
        return "Java(TM) SE Runtime Environment".equals(name)
                && (null != ver)
                && (ver.startsWith("1.7") || ver.startsWith("1.8"));
    }
}
