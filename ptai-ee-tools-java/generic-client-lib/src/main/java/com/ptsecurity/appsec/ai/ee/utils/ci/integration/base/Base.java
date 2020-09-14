package com.ptsecurity.appsec.ai.ee.utils.ci.integration.base;

import lombok.Getter;
import lombok.NonNull;
import lombok.Setter;
import lombok.extern.java.Log;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.PrintStream;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.security.Permission;
import java.security.PermissionCollection;
import java.security.Security;
import java.util.Map;
import java.util.logging.Level;

@Log
public class Base {
    public static final String DEFAULT_SAST_FOLDER = ".ptai";
    public static final String DEFAULT_PTAI_NODE_NAME = "ptai";
    public static final String DEFAULT_PTAI_URL = "https://ptai.domain.org:443";
    public static final String DEFAULT_PREFIX = "[PT AI] ";

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    protected static boolean jceFixApplied = false;

    @Setter
    protected boolean verbose = false;

    @Setter
    @Getter
    protected PrintStream console = null;

    @Setter
    @Getter
    protected String prefix = DEFAULT_PREFIX;

    public void out(String value) {
        if (null == console) return;
        if (StringUtils.isEmpty(value)) return;
        console.println(null == prefix ? value : prefix + value);
        log.info(null == prefix ? value : prefix + value);
    }

    public final void out(String format, Object ... value) {
        out(String.format(format, value));
    }

    public void out(@NonNull final String message, @NonNull final Exception e) {
        out(message);
        if (StringUtils.isEmpty(e.getMessage())) out(e.getMessage());
        log.log(Level.SEVERE, message, e);
        if (verbose && null != console) e.printStackTrace(console);
    }

    public void verbose(String value) {
        if (verbose) out(value);
    }

    public final void verbose(String format, Object ... value) {
        verbose(String.format(format, value));
    }

    public void verbose(@NonNull final String message, @NonNull final Exception e) {
        out(message);
        if (StringUtils.isEmpty(e.getMessage())) out(e.getMessage());
        log.log(Level.SEVERE, message, e);
        if (verbose && null != console) e.printStackTrace(console);
    }

    protected void removeCryptographyRestrictions() {
        if (!isRestrictedCryptography()) {
            log.fine("No need to fix JCE");
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
        } catch (Exception e) {
            log.info("Restrictions removal failed");
            log.log(Level.FINE, e.getMessage(), e);
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
