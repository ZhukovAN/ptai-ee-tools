package com.ptsecurity.appsec.ai.ee.utils.ci.integration.client;

import com.ptsecurity.appsec.ai.ee.scan.reports.Reports;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBriefDetailed;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.AbstractApiClient;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.Factory;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.exceptions.GenericException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.GenericAstJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.operations.AbstractFileOperations;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.operations.AstOperations;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.operations.FileOperations;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.tasks.ProjectTasks;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.test.BaseTest;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.FileCollector;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.json.JsonSettingsHelper;
import lombok.*;
import lombok.experimental.SuperBuilder;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.UUID;

import static com.ptsecurity.appsec.ai.ee.scan.reports.Reports.Locale.EN;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.test.utils.TempFile.PREFIX;

public abstract class BaseAstIT extends BaseClientIT {
    @Getter
    public static class Project {
        protected final String name;
        protected final String settings;
        @TempDir
        protected final Path code;

        @SneakyThrows
        private Project(@NonNull final String name, @NonNull final String sourcesZipResourceName, @NonNull final String settingsResourceName) {
            this.name = name;
            String genericSettings = getResourceString(settingsResourceName);
            this.settings = new JsonSettingsHelper(genericSettings).projectName(name).verifyRequiredFields().serialize();
            this.code = extractPackedResourceFile(sourcesZipResourceName);
            setupProject(this);
        }
    }

    public static final Project JAVA_APP01 = new Project(
            "junit-java-app01",
            "code/java-app01.zip",
            "json/scan/settings/settings.java-app01.aiproj");

    public static final Project JAVA_OWASP_BENCHMARK = new Project("junit-java-owasp-benchmark", "code/java-owasp-benchmark.7z", "json/scan/settings/settings.java-app01.aiproj");
    public static final Project PHP_OWASP_BRICKS = new Project("junit-php-owasp-bricks", "code/php-owasp-bricks.7z", "json/scan/settings/settings.php-smoke.aiproj");
    public static final Project PHP_SMOKE_MISC = new Project("junit-php-smoke-misc", "code/php-smoke-misc.zip", "json/scan/settings/settings.php-smoke.aiproj");
    public static final Project PHP_SMOKE_MEDIUM = new Project("junit-php-smoke-medium", "code/php-smoke-medium.zip", "json/scan/settings/settings.php-smoke.aiproj");
    public static final Project PHP_SMOKE_HIGH = new Project("junit-php-smoke-high", "code/php-smoke-high.zip", "json/scan/settings/settings.php-smoke.aiproj");
    public static final Project PHP_SMOKE_MULTIFLOW = new Project("junit-php-smoke-multiflow", "code/php-smoke-multiflow.zip", "json/scan/settings/settings.php-smoke.aiproj");

    @SneakyThrows
    public static void setupProject(@NonNull final Project project, final String policy) {
        // As projects share same set of settings there's need to modify project name in JSON
        AbstractApiClient client = Factory.client(CONNECTION_SETTINGS());
        ProjectTasks projectTasks = new Factory().projectTasks(client);
        projectTasks.setupFromJson(project.getSettings(), policy);
    }

    @SneakyThrows
    public static void setupProject(@NonNull final Project project) {
        setupProject(project, null);
    }

    @SneakyThrows
    public static String getDefaultPolicy() {
        InputStream inputStream = getResourceStream("json/scan/settings/policy.generic.json");
        return IOUtils.toString(inputStream, StandardCharsets.UTF_8);
    }

    protected Reports.Report report;
    protected Reports.Data data;
    protected Reports.RawData rawData;

    @BeforeEach
    @SneakyThrows
    public void pre() {
        report = Reports.Report.builder()
                .format(Reports.Report.Format.HTML)
                .fileName(UUID.randomUUID() + ".html")
                .locale(EN)
                .template(Reports.Report.DEFAULT_TEMPLATE_NAME.get(EN))
                .build();

        data = Reports.Data.builder()
                .format(Reports.Data.Format.JSON)
                .fileName(UUID.randomUUID() + ".json")
                .locale(EN)
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
