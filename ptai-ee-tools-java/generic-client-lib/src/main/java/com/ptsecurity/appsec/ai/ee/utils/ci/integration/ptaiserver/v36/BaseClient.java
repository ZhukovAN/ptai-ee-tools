package com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36;

import com.ptsecurity.appsec.ai.ee.ptai.server.filesstore.v36.StoreApi;
import com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.v36.LicenseApi;
import com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.v36.ProjectsApi;
import com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.v36.ReportsApi;
import com.ptsecurity.appsec.ai.ee.ptai.server.scanscheduler.v36.ScanAgentApi;
import com.ptsecurity.appsec.ai.ee.ptai.server.scanscheduler.v36.ScanApi;
import com.ptsecurity.appsec.ai.ee.ptai.server.systemmanagement.v36.HealthCheckApi;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.Base;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.exceptions.ApiException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.jwt.JwtResponse;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.utils.ApiClientHelper;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.utils.CertificateHelper;
import lombok.Getter;
import lombok.NonNull;
import lombok.Setter;
import lombok.SneakyThrows;
import org.apache.commons.lang3.StringUtils;

import java.io.FileInputStream;
import java.nio.file.Path;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Callable;

public class BaseClient extends Base {
    protected static final int TIMEOUT = 3600 * 1000;

    @Getter
    protected final ProjectsApi projectsApi = new ProjectsApi(new com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.ApiClient());

    @Getter
    protected final ReportsApi reportsApi = new ReportsApi(new com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.ApiClient());

    @Getter
    protected final LicenseApi licenseApi = new LicenseApi(new com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.ApiClient());

    @Getter
    protected final ScanApi scanApi = new ScanApi(new com.ptsecurity.appsec.ai.ee.ptai.server.scanscheduler.ApiClient());

    @Getter
    protected final ScanAgentApi scanAgentApi = new ScanAgentApi(new com.ptsecurity.appsec.ai.ee.ptai.server.scanscheduler.ApiClient());

    @Getter
    protected final StoreApi storeApi = new StoreApi(new com.ptsecurity.appsec.ai.ee.ptai.server.filesstore.ApiClient());

    @Getter
    protected final HealthCheckApi healthCheckApi = new HealthCheckApi(new com.ptsecurity.appsec.ai.ee.ptai.server.systemmanagement.ApiClient());

    @Getter
    protected final List<Object> apis = new ArrayList<>();

    public BaseClient() {
        super();
        apis.addAll(Arrays.asList(projectsApi, reportsApi, licenseApi, scanApi, scanAgentApi, storeApi, healthCheckApi));
    }

    /**
     * Currently owned JWT. This JWT token shared by all the APIs and managed by their JwtAuthenticators
     */
    @Getter
    protected JwtResponse JWT = null;

    public void setJWT(@NonNull final JwtResponse JWT) {
        this.JWT = JWT;
        for (Object api : apis) {
            ApiClientHelper helper = new ApiClientHelper(api).init();
            helper.setApiKeyPrefix("Bearer");
            helper.setApiKey(JWT.getAccessToken());
        }
    }

    @Getter
    protected String url = "";

    public void setUrl(@NonNull final String url) {
        this.url = StringUtils.removeEnd(url.trim(), "/");
    }

    @Setter
    @Getter
    @NonNull
    protected String token = null;

    @Getter
    @Setter
    protected int timeout = TIMEOUT;

    /**
     * PEM-encoded CA certificate chain
     */
    @Setter
    @Getter
    @NonNull
    protected String caCertsPem = "";

    public void init() {
        ApiClientHelper.initClientApis(this, apis);
    }

    @SneakyThrows
    public void setCaCertsJks(@NonNull final Path jks) {
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(new FileInputStream(jks.toFile()), "".toCharArray());
        caCertsPem = CertificateHelper.trustStoreToPem(keyStore);
    }

    protected static <V> V callApi(Callable<V> call, String errorMessage) throws ApiException {
        try {
            return call.call();
        } catch (Exception e) {
            throw ApiException.raise(errorMessage, e);
        }
    }

    /**
     * Need to implement our own Runnable that throws checked Exception
     */
    @FunctionalInterface
    public interface Runnable {
        void run() throws Exception;
    }

    public static void callApi(Runnable call, String errorMessage) throws ApiException {
        callApi(() -> {
            call.run();
            return null;
        }, errorMessage);
    }
}
