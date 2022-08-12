package com.ptsecurity.appsec.ai.ee.utils.ci.integration.client;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ptsecurity.appsec.ai.ee.scan.progress.Stage;
import com.ptsecurity.appsec.ai.ee.scan.reports.Reports;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBriefDetailed;
import com.ptsecurity.appsec.ai.ee.scan.settings.Policy;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.AbstractApiClient;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.Factory;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.exceptions.GenericException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.GenericAstJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.operations.AbstractFileOperations;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.operations.AstOperations;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.operations.FileOperations;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.tasks.GenericAstTasks;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.tasks.ProjectTasks;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.test.BaseTest;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.FileCollector;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.json.BaseJsonHelper;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.json.JsonSettingsHelper;
import lombok.Getter;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.experimental.SuperBuilder;
import org.apache.commons.io.FileUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.UUID;

import static com.ptsecurity.appsec.ai.ee.scan.reports.Reports.Locale.EN;

public abstract class BaseAstIT extends BaseClientIT {
    @Getter
    public static class Project {
        @Getter
        protected final String name;
        @Getter
        protected final String settings;

        protected final String sourcesZipResourceName;

        @TempDir
        protected Path code = null;

        public Path getCode() {
            if (null == code)
                code = extractPackedResourceFile(sourcesZipResourceName);
            return code;
        }


        protected Path zip = null;

        public Path getZip() {
            if (null == zip) {
                Path sources = getCode();
                zip = BaseTest.zipFile(sources);
            }
            return zip;
        }

        @SneakyThrows
        private Project(@NonNull final String name, @NonNull final String sourcesZipResourceName, @NonNull final String settingsResourceName) {
            this.name = name;
            String genericSettings = getResourceString(settingsResourceName);
            this.settings = new JsonSettingsHelper(genericSettings).projectName(name).verifyRequiredFields().serialize();
            this.sourcesZipResourceName = sourcesZipResourceName;
        }
        @SneakyThrows
        public Project setup(final String policy) {
            // As projects share same set of settings there's need to modify project name in JSON
            AbstractApiClient client = Factory.client(CONNECTION_SETTINGS());
            ProjectTasks projectTasks = new Factory().projectTasks(client);
            projectTasks.setupFromJson(settings, policy, (projectId) -> {
                GenericAstTasks genericAstTasks = new Factory().genericAstTasks(client);
                genericAstTasks.upload(projectId, getZip().toFile());
            });
            return this;
        }

        @SneakyThrows
        public Project setup() {
            return setup(null);
        }
    }

    public static final Project JAVA_APP01 = new Project(
            JAVA_APP01_PROJECT_NAME,
            "code/java-app01.zip",
            "json/scan/settings/settings.java-app01.aiproj");

    public static final Project JAVA_OWASP_BENCHMARK = new Project(JAVA_OWASP_BENCHMARK_PROJECT_NAME, "code/java-owasp-benchmark.7z", "json/scan/settings/settings.java-app01.aiproj");
    public static final Project PHP_OWASP_BRICKS = new Project(PHP_OWASP_BRICKS_PROJECT_NAME, "code/php-owasp-bricks.7z", "json/scan/settings/settings.php-smoke.aiproj");
    public static final Project PHP_SMOKE_MISC = new Project(PHP_SMOKE_MISC_PROJECT_NAME, "code/php-smoke-misc.zip", "json/scan/settings/settings.php-smoke.aiproj");
    public static final Project PHP_SMOKE_MEDIUM = new Project(PHP_SMOKE_MEDIUM_PROJECT_NAME, "code/php-smoke-medium.zip", "json/scan/settings/settings.php-smoke.aiproj");
    public static final Project PHP_SMOKE_HIGH = new Project(PHP_SMOKE_HIGH_PROJECT_NAME, "code/php-smoke-high.zip", "json/scan/settings/settings.php-smoke.aiproj");
    public static final Project PHP_SMOKE_MULTIFLOW = new Project(PHP_SMOKE_MULTIFLOW_PROJECT_NAME, "code/php-smoke-multiflow.zip", "json/scan/settings/settings.php-smoke.aiproj");
    public static final Project JAVASCRIPT_VNWA = new Project(JAVASCRIPT_VNWA_PROJECT_NAME, "code/javascript-vnwa.7z", "json/scan/settings/settings.javascript-vnwa.aiproj");
    public static final Project CSHARP_WEBGOAT = new Project(CSHARP_WEBGOAT_PROJECT_NAME, "code/csharp-webgoat.zip", "json/scan/settings/settings.csharp-webgoat.aiproj");

    public static final Project[] ALL = new Project[] { JAVA_APP01, JAVA_OWASP_BENCHMARK, PHP_OWASP_BRICKS, PHP_SMOKE_MISC, PHP_SMOKE_MEDIUM, PHP_SMOKE_HIGH, PHP_SMOKE_MULTIFLOW, JAVASCRIPT_VNWA, CSHARP_WEBGOAT };

    @RequiredArgsConstructor
    public static class PolicyHelper {
        @Getter
        protected final String json;
        @Getter
        protected final Policy[] policy;

        @SneakyThrows
        public static PolicyHelper fromResource(@NonNull final String name) {
            String json = getResourceString(name);
            Policy[] policy = createFaultTolerantObjectMapper().readValue(json, Policy[].class);
            return new PolicyHelper(json, policy);
        }

        protected Path path = null;

        @SneakyThrows
        public Path getPath() {
            if (null == path) {
                path = Files.createTempFile(TEMP_FOLDER(), "ptai-", "-policy");
                ObjectMapper mapper = BaseJsonHelper.createObjectMapper();
                mapper.writeValue(path.toFile(), policy);
            }
            return path;
        }
    }

    public static final PolicyHelper GENERIC_POLICY = PolicyHelper.fromResource("json/scan/settings/policy.generic.json");

    protected Reports.Report report;
    protected Reports.RawData rawData;

    @BeforeEach
    @SneakyThrows
    public void pre() {
        report = Reports.Report.builder()
                .fileName(UUID.randomUUID() + ".html")
                .template(Reports.Report.DEFAULT_TEMPLATE_NAME.get(EN))
                .build();

        rawData = Reports.RawData.builder()
                .fileName(UUID.randomUUID() + ".json")
                .build();
    }

    @SuperBuilder
    public static class TestAstOperations implements AstOperations {
        protected GenericAstJob owner;

        protected Path sources;

        @Override
        public File createZip() throws GenericException {
            return FileCollector.collect(null, sources.toFile(), owner);
        }

        @Override
        public void scanStartedCallback(@NonNull UUID projectId, @NonNull UUID scanResultId) throws GenericException {
            System.out.println("Project " + projectId + " scan started. Result Id is " + scanResultId);
        }

        @Override
        public void scanCompleteCallback(@NonNull ScanBrief scanBrief, @NonNull final ScanBriefDetailed.Performance performance) throws GenericException {
            System.out.println("Project scan finished");
        }
    }

    @SuperBuilder
    public static class TestFileOperations extends AbstractFileOperations implements FileOperations {
        protected GenericAstJob owner;

        protected Path destination;

        @Override
        protected void saveInMemoryData(@NonNull String name, byte[] data) {
            Assertions.assertDoesNotThrow(() -> FileUtils.writeByteArrayToFile(destination.resolve(name).toFile(), data));
        }
    }
}
