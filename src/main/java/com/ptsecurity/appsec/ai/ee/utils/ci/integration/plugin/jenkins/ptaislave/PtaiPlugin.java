package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave;

import com.cloudbees.plugins.credentials.domains.DomainSpecification;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ptsecurity.appsec.ai.ee.ptai.server.filesstore.rest.StoreApi;
import com.ptsecurity.appsec.ai.ee.ptai.server.gateway.ApiResponse;
import com.ptsecurity.appsec.ai.ee.ptai.server.gateway.rest.AgentAuthApi;
import com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.rest.Project;
import com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.rest.ProjectsApi;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.auth.Auth;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.auth.CredentialsAuth;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.auth.TokenAuth;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.descriptor.PtaiPluginDescriptor;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.exceptions.PtaiException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.utils.*;
import com.ptsecurity.appsec.ai.ee.utils.ci.jenkins.server.ApiException;
import com.ptsecurity.appsec.ai.ee.utils.ci.jenkins.server.rest.FreeStyleBuild;
import com.ptsecurity.appsec.ai.ee.utils.ci.jenkins.server.rest.FreeStyleProject;
import com.ptsecurity.appsec.ai.ee.utils.ci.jenkins.server.rest.RemoteAccessApi;
import hudson.AbortException;
import hudson.FilePath;
import hudson.Launcher;
import hudson.Util;
import hudson.model.*;
import hudson.tasks.Builder;
import jenkins.model.Jenkins;
import jenkins.tasks.SimpleBuildStep;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.ToString;
import lombok.extern.slf4j.Slf4j;
import org.kohsuke.stapler.DataBoundConstructor;
import org.parboiled.common.StringUtils;

import javax.annotation.Nonnull;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLSession;
import java.io.*;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.apache.commons.lang3.StringUtils.trimToNull;

@Slf4j
@ToString
public class PtaiPlugin extends Builder implements SimpleBuildStep {
    private static final String consolePrefix = Messages.console_message_prefix();

    @Getter
    private String sastConfigName;

    @Getter
    private String uiProject;

    @Getter
    private boolean failIfSastFailed;

    @Getter
    private boolean failIfSastUnstable;

    @Getter
    private String sastAgentNodeName;

    @Getter
    private boolean verbose;

    @Getter
    private ArrayList<PtaiTransfer> transfers;

    public final void setTransfers(final ArrayList<PtaiTransfer> transfers) {
        if (transfers == null)
            this.transfers = new ArrayList<PtaiTransfer>();
        else
            this.transfers = transfers;
    }

    @DataBoundConstructor
    public PtaiPlugin(final String sastConfigName,
                      final String uiProject,
                      final boolean failIfSastFailed,
                      final boolean failIfSastUnstable,
                      final String sastAgentNodeName,
                      final boolean verbose,
                      final ArrayList<PtaiTransfer> transfers) {
        this.sastConfigName = sastConfigName;
        this.uiProject = uiProject;
        this.failIfSastFailed = failIfSastFailed;
        this.failIfSastUnstable = failIfSastUnstable;
        this.verbose = verbose;
        this.sastAgentNodeName = sastAgentNodeName;
        this.transfers = transfers;
    }

    private TreeMap<String, String> getEnvironmentVariables(final Run<?, ?> build, final TaskListener listener) {
        try {
            final TreeMap<String, String> env = build.getEnvironment(listener);
            if (build instanceof AbstractBuild) {
                env.putAll(((AbstractBuild) build).getBuildVariables());
            }
            return env;
        } catch (Exception e) {
            throw new RuntimeException(Messages.exception_failedToGetEnvVars(), e);
        }
    }

    protected void verboseLog(TaskListener listener, String format, Object... args) {
        if (!this.verbose) return;
        log(listener, format, args);
    }

    protected void log(TaskListener listener, String format, Object... args) {
        listener.getLogger().print(consolePrefix + String.format(format, args));
    }

    static class JenkinsJsonParameter {
        @AllArgsConstructor
        static class NameValuePair {
            @Getter
            private String name;
            @Getter
            private String value;
        }
        @Getter
        private List<NameValuePair> parameter = new ArrayList<NameValuePair>();

        public NameValuePair add(String name, String value) {
            NameValuePair res = new NameValuePair(name, value);
            parameter.add(res);
            return res;
        }
    }
    static enum PtaiResult {
        FAILURE, UNSTABLE, SUCCESS;
    }

    @Override
    public void perform(@Nonnull Run<?, ?> build, @Nonnull FilePath workspace, @Nonnull Launcher launcher, @Nonnull TaskListener listener) throws InterruptedException, IOException {
        Jenkins jenkins = Jenkins.get();
        final BuildEnv currentBuildEnv = new BuildEnv(getEnvironmentVariables(build, listener), workspace, build.getTimestamp());
        final BuildEnv targetBuildEnv = null;
        final BuildInfo buildInfo = new BuildInfo(currentBuildEnv, targetBuildEnv);
        buildInfo.setEffectiveEnvironmentInBuildInfo();

        FileUploader uploader = new FileUploader(listener, transfers, buildInfo);
        String zipFileName = workspace.act(uploader);
        log(listener, "Zipped file: %s", zipFileName);

        PtaiSastConfig cfg = getDescriptor().getSastConfig(sastConfigName);
        if (StringUtils.isEmpty(cfg.getSastConfigPtaiHostUrl()))
            throw new AbortException("PT AI host URL must be set up");
        if (StringUtils.isEmpty(cfg.getSastConfigPtaiCert()))
            throw new AbortException("PT AI client certificate must be set up");
        if (StringUtils.isEmpty(cfg.getSastConfigPtaiCertPwd()))
            throw new AbortException("PT AI client key must be set up");
        if (StringUtils.isEmpty(cfg.getSastConfigPtaiCaCerts()))
            throw new AbortException("PT AI CA certificates must be set up");

        // Connect to PT AI server
        HostnameVerifier hostnameVerifier = new HostnameVerifier() {
            @Override
            public boolean verify(String hostname, SSLSession session) {
                return true;
            }
        };

        AgentAuthApi authApi = new AgentAuthApi(new com.ptsecurity.appsec.ai.ee.ptai.server.gateway.ApiClient());
        ProjectsApi prjApi = new ProjectsApi(new com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.ApiClient());
        StoreApi storeApi = new StoreApi(new com.ptsecurity.appsec.ai.ee.ptai.server.filesstore.ApiClient());

        authApi.getApiClient().setBasePath(cfg.getSastConfigPtaiHostUrl());
        prjApi.getApiClient().setBasePath(cfg.getSastConfigPtaiHostUrl());
        storeApi.getApiClient().setBasePath(cfg.getSastConfigPtaiHostUrl());

        byte[] decodedBytes = Base64.getDecoder().decode(cfg.getSastConfigPtaiCert().replaceAll("\n", ""));
        char[] certPwd = cfg.getSastConfigPtaiCertPwd().toCharArray();
        KeyStore appKeyStore = null;
        ApiResponse<String> authToken = null;
        try (InputStream certStream = new ByteArrayInputStream(decodedBytes)) {
            // Set certificates and keys for mutual PT AI EE server authentication
            appKeyStore = KeyStore.getInstance("PKCS12");
            appKeyStore.load(certStream, certPwd);
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(appKeyStore, certPwd);
            authApi.getApiClient().setKeyManagers(kmf.getKeyManagers());
            prjApi.getApiClient().setKeyManagers(kmf.getKeyManagers());
            storeApi.getApiClient().setKeyManagers(kmf.getKeyManagers());
            // Due to ApiClient specific keyManagers must be set before CA certificates
            authApi.getApiClient().setSslCaCert(new ByteArrayInputStream(cfg.getSastConfigPtaiCaCerts().getBytes()));
            prjApi.getApiClient().setSslCaCert(new ByteArrayInputStream(cfg.getSastConfigPtaiCaCerts().getBytes()));
            storeApi.getApiClient().setSslCaCert(new ByteArrayInputStream(cfg.getSastConfigPtaiCaCerts().getBytes()));
            authApi.getApiClient().getHttpClient().setHostnameVerifier(hostnameVerifier);
            prjApi.getApiClient().getHttpClient().setHostnameVerifier(hostnameVerifier);
            storeApi.getApiClient().getHttpClient().setHostnameVerifier(hostnameVerifier);
            // Try to authenticate
            authToken = authApi.apiAgentAuthSigninGetWithHttpInfo("Agent");
            if (StringUtils.isEmpty(authToken.getData()))
                throw new AbortException("PT AI server authentication failed");
            verboseLog(listener,"Auth token: %s", authToken.getData());

            // Search for project
            prjApi.getApiClient().setApiKeyPrefix("Bearer");
            prjApi.getApiClient().setApiKey(authToken.getData());
            com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.ApiResponse<List<Project>> projects = prjApi.apiProjectsGetWithHttpInfo(true);
            UUID projectId = null;
            String uiPrj = Util.replaceMacro(this.uiProject, buildInfo.getEnvVars());
            uiPrj = Util.fixEmptyAndTrim(uiPrj);

            for (Project prj : projects.getData())
                if (uiPrj.equals(prj.getName())) {
                    projectId = prj.getId();
                    break;
                }
            if (null == projectId)
                throw new AbortException("PT AI project not found");
            verboseLog(listener,"Project ID: %s", projectId.toString());
            // Upload project sources
            storeApi.getApiClient().setApiKeyPrefix("Bearer");
            storeApi.getApiClient().setApiKey(authToken.getData());
            com.ptsecurity.appsec.ai.ee.ptai.server.filesstore.ApiResponse<Void> res = storeApi.apiStoreSourcesByProjectIdPostWithHttpInfo(
                    projectId,
                    new File(zipFileName),
                    null,null,null,null,null,null);
            verboseLog(listener,"File upload result: %d", res.getStatusCode());
            if (200 != res.getStatusCode())
                throw new AbortException("Project upload failed");
            // Let's start analysis
            PtaiJenkinsApiClient apiClient = new PtaiJenkinsApiClient();
            RemoteAccessApi jenkinsApi = new RemoteAccessApi(apiClient);
            jenkinsApi.getApiClient().setBasePath(cfg.getSastConfigJenkinsHostUrl());
            // Set authentication parameters
            Auth jenkinsAuth = cfg.getSastConfigJenkinsAuth();
            if (null == jenkinsAuth)
                throw new AbortException("Jenkins authentication mode is not set");
            if (jenkinsAuth instanceof CredentialsAuth) {
                Item item = jenkins.getItem("/");
                apiClient.setApiKeyPrefix("Authorization");
                CredentialsAuth auth = (CredentialsAuth)jenkinsAuth;
                String tuple = auth.getUserName(item) + ":" + auth.getPassword(item);
                verboseLog(listener, "Password authentication tuple: %s", tuple);
                byte[] encoded = org.apache.commons.codec.binary.Base64.encodeBase64(tuple.getBytes("UTF-8"));
                String apiKey = "Basic " + new String(encoded, "UTF-8");
                verboseLog(listener, "Password authentication key: %s", apiKey);
                apiClient.setApiKey(apiKey);
            } else if (jenkinsAuth instanceof TokenAuth) {
                apiClient.setApiKeyPrefix("Authorization");
                TokenAuth auth = (TokenAuth)jenkinsAuth;
                String tuple = auth.getUserName() + ":" + auth.getApiToken();
                verboseLog(listener, "Token authentication tuple: %s", tuple);
                byte[] encoded = org.apache.commons.codec.binary.Base64.encodeBase64(tuple.getBytes("UTF-8"));
                String apiKey = "Basic " + new String(encoded, "UTF-8");
                verboseLog(listener, "Token authentication key: %s", apiKey);
                apiClient.setApiKey(apiKey);
            }
            // Autogenerated Jenkins API does not support folders so we need to
            // hack job name
            String jobName = apiClient.convertJobName(cfg.getSastConfigJenkinsJobName());
            FreeStyleProject prj = jenkinsApi.getJob(jobName);
            Integer buildNumber = prj.getNextBuildNumber();
            JenkinsJsonParameter params = new JenkinsJsonParameter();
            params.add("PTAI_PROJECT_NAME", uiPrj);
            params.add("PTAI_NODE_NAME", sastAgentNodeName);
            ObjectMapper objectMapper = new ObjectMapper();
            // Start SAST job
            jenkinsApi.postJobBuild(jobName, objectMapper.writeValueAsString(params), null, null);
            FreeStyleBuild sastBuild = null;
            do {
                try {
                    // There may be a situation where build is not started yet, so we'll get an "not found" exception
                    sastBuild = jenkinsApi.getJobBuild(jobName, buildNumber.toString());
                    if (null != sastBuild) {
                        log(listener, "%s job started", cfg.getSastConfigJenkinsJobName());
                        break;
                    } else
                        throw new PtaiException("SAST job build is null");
                } catch (ApiException e) {
                    if (404 == e.getCode()) {
                        log(listener, "Wait 5 seconds for %s job to start", cfg.getSastConfigJenkinsJobName());
                        Thread.sleep(5000);
                        continue;
                    }
                    log(listener, "%s job start failed: %s", cfg.getSastConfigJenkinsJobName(), e.getMessage());
                    throw new PtaiException(e.getMessage());
                }
            } while (true);
            // Wait till SAST job is complete
            int start = 0;
            Pattern p = Pattern.compile("^Finished: (FAILURE)|(UNSTABLE)|(SUCCESS)$");
            PtaiResult sastJobRes = PtaiResult.UNSTABLE;
            do {
                sastBuild = jenkinsApi.getJobBuild(jobName, buildNumber.toString());
                if (null == sastBuild) break;
                com.ptsecurity.appsec.ai.ee.utils.ci.jenkins.server.ApiResponse<String> sastJobLog;
                sastJobLog = jenkinsApi.getJobProgressiveTextWithHttpInfo(jobName, buildNumber.toString(), String.valueOf(start));
                if (200 != sastJobLog.getStatusCode()) break;
                // Just to simplify processing of optional headers array
                int pos = start;
                try {
                    pos = Integer.parseInt(sastJobLog.getHeaders().get("X-Text-Size").get(0));
                } catch (Exception e) {
                    break;
                }
                if (pos != start) {
                    log(listener, "%s", sastJobLog.getData());
                    start = pos;
                }
                Thread.sleep(1000);
                if (StringUtils.isEmpty(sastBuild.getResult())) continue;
                try {
                    sastJobRes = PtaiResult.valueOf(sastBuild.getResult());
                    break;
                } catch (Exception e) {
                    continue;
                }
            } while (true);
            // Save results
            for (String sastResType : Arrays.asList( "json", "html" )) {
                try {
                    String sastJson = jenkinsApi.getJobBuildArtifact(jobName, buildNumber.toString(), "REPORTS/report." + sastResType);
                    workspace.child("sast.report." + sastResType).write(sastJson, "UTF-8");
                } catch (Exception e) {
                    log(listener, "%s.%s\r\n", "Failed to download report", sastResType);
                }
            }
            if (failIfSastFailed && PtaiResult.FAILURE.equals(sastJobRes))
                throw new AbortException("SAST is failed");
            if (failIfSastUnstable && PtaiResult.UNSTABLE.equals(sastJobRes))
                throw new AbortException("SAST is unstable");
        } catch (NoSuchAlgorithmException | KeyStoreException | CertificateException | UnrecoverableKeyException e) {
            log(listener, "Certificate problem: %s", e.getMessage());
            throw new AbortException("Certificate problem");
        } catch (ApiException | com.ptsecurity.appsec.ai.ee.ptai.server.gateway.ApiException | com.ptsecurity.appsec.ai.ee.ptai.server.filesstore.ApiException | com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.ApiException e) {
            log(listener, "API exception: %s", e.getMessage());
            throw new AbortException("API client create failed");
        }
    }

    protected void fixup(final Run<?, ?> build, final BuildInfo buildInfo) {
        // provide a hook for the plugin impl to get at other internals - ie Hudson.getInstance is null when remote from a publisher!!!!!
        // as is Exceutor.currentExecutor, Computer.currentComputer - it's a wilderness out there!
    }

    @Override
    public PtaiPluginDescriptor getDescriptor() {
        return Jenkins.get().getDescriptorByType(PtaiPluginDescriptor.class);
    }

    public PtaiSastConfig getSastConfig(final String sastConfigName) {
        return getDescriptor().getSastConfig(sastConfigName);
    }

    protected static String getCurrentItem(Run<?, ?> run, String currentItem){
        String runItem = null;
        String curItem = trimToNull(currentItem);
        if(run != null && run.getParent() != null)
            runItem = trimToNull(run.getParent().getFullName());

        if(runItem != null && curItem != null) {
            if(runItem.equals(curItem)) {
                return runItem;
            } else {
                throw new IllegalArgumentException(String.format("Current Item ('%s') and Parent Item from Run ('%s') differ!", curItem, runItem));
            }
        } else if(runItem != null) {
            return runItem;
        } else if(curItem != null) {
            return curItem;
        } else {
            throw new IllegalArgumentException("Both null, Run and Current Item!");
        }
    }
}