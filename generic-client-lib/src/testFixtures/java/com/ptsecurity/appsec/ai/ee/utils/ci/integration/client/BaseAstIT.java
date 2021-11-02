package com.ptsecurity.appsec.ai.ee.utils.ci.integration.client;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ptsecurity.appsec.ai.ee.scan.reports.Reports;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBriefDetailed;
import com.ptsecurity.appsec.ai.ee.scan.settings.AiProjScanSettings;
import com.ptsecurity.appsec.ai.ee.scan.settings.Policy;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.AbstractApiClient;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.Factory;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.exceptions.GenericException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.GenericAstJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.operations.AstOperations;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.operations.FileOperations;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.tasks.ProjectTasks;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.FileCollector;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.json.JsonSettingsHelper;
import lombok.*;
import lombok.experimental.SuperBuilder;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;

import java.io.File;
import java.io.InputStream;
import java.nio.file.Path;
import java.util.Map;
import java.util.UUID;

import static com.ptsecurity.appsec.ai.ee.scan.reports.Reports.Locale.EN;

public abstract class BaseAstIT extends BaseClientIT {
    @RequiredArgsConstructor
    @Getter @Setter
    public static class Project {
        protected final String name;
        protected final String code;
        protected final String settings;
    }

    public static final Project JAVA_APP01 = new Project("junit-it-java-app01", "code/java-app01.7z", "json/scan/settings/settings.java-app01.aiproj");
    public static final Project PHP_SMOKE_MISC = new Project("junit-it-php-smoke-misc", "code/php-smoke-misc.7z", "json/scan/settings/settings.php-smoke.aiproj");
    public static final Project PHP_SMOKE_MEDIUM = new Project("junit-it-php-smoke-medium", "code/php-smoke-medium.7z", "json/scan/settings/settings.php-smoke.aiproj");
    public static final Project PHP_SMOKE_HIGH = new Project("junit-it-php-smoke-high", "code/php-smoke-high.7z", "json/scan/settings/settings.php-smoke.aiproj");

    public Path getSourcesRoot(@NonNull final Project project) {
        return getPackedResourceFile(project.code);
    }

    @SneakyThrows
    public static void setupProject(@NonNull final Project project, final Policy[] policy) {
        AiProjScanSettings settings = JsonSettingsHelper.verify(getResourceString(project.getSettings()));
        if (!JAVA_APP01.equals(project))
            settings.setProjectName(project.getName());

        AbstractApiClient client = Factory.client(CONNECTION_SETTINGS);
        ProjectTasks projectTasks = new Factory().projectTasks(client);
        projectTasks.setupFromJson(settings, policy);
    }

    @SneakyThrows
    public static Policy[] getDefaultPolicy() {
        InputStream inputStream = getResourceStream("json/scan/settings/policy.generic.json");
        ObjectMapper mapper = createFaultTolerantObjectMapper();
        return mapper.readValue(inputStream, Policy[].class);
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

        @Override
        public String replaceMacro(@NonNull String value, Map<String, String> replacements) {
            return value;
        }
    }

    @SuperBuilder
    public static class TestFileOperations implements FileOperations {
        protected GenericAstJob owner;

        protected Path destination;

        public void saveArtifact(@NonNull String name, @NonNull File data) {
            Assertions.assertDoesNotThrow(() -> FileUtils.moveFile(data, destination.resolve(name).toFile()));
        }

        public void saveArtifact(@NonNull String name, byte[] data) {
            Assertions.assertDoesNotThrow(() -> FileUtils.writeByteArrayToFile(destination.resolve(name).toFile(), data));
        }
    }
}
