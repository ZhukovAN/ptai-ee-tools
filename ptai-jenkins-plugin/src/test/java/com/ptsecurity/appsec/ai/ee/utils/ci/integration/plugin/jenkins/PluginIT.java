package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins;

import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.CredentialsStore;
import com.cloudbees.plugins.credentials.SystemCredentialsProvider;
import com.cloudbees.plugins.credentials.domains.Domain;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanResult;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.client.BaseAstIT;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain.AdvancedSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.credentials.Credentials;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.credentials.CredentialsImpl;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.localconfig.ConfigCustom;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.scansettings.ScanSettingsUi;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.serversettings.ServerSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.workmode.WorkModeSync;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.workmode.subjobs.Base;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.workmode.subjobs.export.RawJson;
import hudson.ExtensionList;
import hudson.FilePath;
import hudson.model.FreeStyleBuild;
import hudson.model.FreeStyleProject;
import hudson.model.Result;
import hudson.scm.SCM;
import lombok.SneakyThrows;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.ExtractResourceSCM;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.EnableJenkins;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.AbstractTool.DEFAULT_LOG_PREFIX;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.AbstractJob.DEFAULT_OUTPUT_FOLDER;

@DisplayName("Execute Jenkins jobs that use PT AI plugin")
@EnableJenkins
public class PluginIT extends BaseAstIT {

    private CredentialsStore systemStore;
    private Credentials credentials;

    @SneakyThrows
    protected void initCredentials(JenkinsRule jenkins) {
        SystemCredentialsProvider.ProviderImpl system = ExtensionList.lookup(CredentialsProvider.class).get(SystemCredentialsProvider.ProviderImpl.class);
        systemStore = system.getStore(jenkins.getInstance());
        // Create PT AI credentials
        credentials = new CredentialsImpl(CredentialsScope.GLOBAL, UUID.randomUUID().toString(), "", BaseAstIT.TOKEN, "");
        systemStore.addCredentials(Domain.global(), credentials);
    }

    @SneakyThrows
    protected void finiCredentials() {
        for (com.cloudbees.plugins.credentials.Credentials c : systemStore.getCredentials(Domain.global()))
            systemStore.removeCredentials(Domain.global(), c);
    }

    @SneakyThrows
    @Test
    @Tag("integration")
    @DisplayName("Execute simple SAST job for PHP smoke medium")
    public void scanPhpSmokeMedium(JenkinsRule jenkins) {
        initCredentials(jenkins);
        // Create project and set source code location
        java.net.URL sourcesPack = getClass().getClassLoader().getResource(BaseAstIT.PHP_SMOKE_MEDIUM.getCode());
        SCM scm = new ExtractResourceSCM(sourcesPack);
        String projectName = "project-" + UUID.randomUUID();
        FreeStyleProject project = jenkins.createFreeStyleProject(projectName);
        project.setScm(scm);

        // Create PT AI plugin settings
        ScanSettingsUi scanSettings = new ScanSettingsUi("php-smoke-ui");

        ServerSettings serverSettings = new ServerSettings(BaseAstIT.URL, credentials.getId(), true);
        ConfigCustom configCustom = new ConfigCustom(serverSettings);

        ArrayList<Base> subJobs = new ArrayList<>();
        RawJson rawJsonSubJob = new RawJson("raw-" + UUID.randomUUID() + ".json", "");
        subJobs.add(rawJsonSubJob);
        WorkModeSync workMode = new WorkModeSync(subJobs);

        ArrayList<Transfer> transfers = new ArrayList<>();
        transfers.add(new Transfer());

        Plugin ptai = new Plugin(scanSettings, configCustom, workMode, AdvancedSettings.getDefault().toString(), false, false, transfers);
        project.getBuildersList().add(ptai);

        FreeStyleBuild build = project.scheduleBuild2(0).get();

        // As we don't set AST policy assessment step in plugin settings, build is to succeed
        Assertions.assertEquals(Result.SUCCESS, build.getResult());
        // Check if report was generated
        FilePath rawJsonFile = build.getWorkspace().child(DEFAULT_OUTPUT_FOLDER).child(rawJsonSubJob.getFileName());
        Assertions.assertTrue(rawJsonFile.exists());
        ObjectMapper mapper = createFaultTolerantObjectMapper();
        ScanResult scanResult = mapper.readValue(rawJsonFile.read(), ScanResult.class);

        // Check log entries
        List<String> log = build.getLog(100);
        Assertions.assertTrue(log.stream()
                .map(s -> s.replace(DEFAULT_LOG_PREFIX, "").trim())
                .anyMatch(s -> s.matches("^Scan finished, project name: " + scanResult.getProjectName() + ", project id: " + scanResult.getProjectId() + ", result id: " + scanResult.getId() + "$")));

        finiCredentials();
    }
}
