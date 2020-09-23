package com.ptsecurity.appsec.ai.ee.utils.ci.integration.base;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.exceptions.ApiException;
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
    @NonNull
    protected String prefix = DEFAULT_PREFIX;

    protected void out(final String value) {
        if (null == value) return;
        if (null != console) console.println(prefix + value);
    }

    protected void exception(@NonNull final String message, @NonNull final Exception e, @NonNull final Level level) {
        Exception cause = e;
        String details = null;
        if (e instanceof ApiException) {
            ApiException apiException = (ApiException) e;
            cause = apiException.getInner();
            details = apiException.getDetails();
        }
        log.log(level, message, cause);
        if (StringUtils.isNotEmpty(details)) log.log(level, details);

        if (null == console) return;

        out(message);
        if (verbose)
            // No need to output exception message to console as it will
            // be printed as part of printStackTrace call
            cause.printStackTrace(console);
        else
            out(cause.getMessage());
        out(details);
    }

    public void info(final String value) {
        log.info(value);
        out(value);
    }

    public void info(@NonNull final String format, final Object ... values) {
        info(String.format(format, values));
    }

    public void warning(final String value) {
        log.warning(value);
        out(value);
    }

    public void warning(@NonNull final String message, @NonNull final Exception e) {
        exception(message, e, Level.WARNING);
    }

    public void severe(final String value) {
        log.severe(value);
        out(value);
    }

    public void severe(@NonNull final String message, @NonNull final Exception e) {
        exception(message, e, Level.SEVERE);
    }

    public void fine(final String value) {
        log.fine(value);
        if (verbose) out(value);
    }

    public void fine(@NonNull final String format, final Object ... values) {
        fine(String.format(format, values));
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
