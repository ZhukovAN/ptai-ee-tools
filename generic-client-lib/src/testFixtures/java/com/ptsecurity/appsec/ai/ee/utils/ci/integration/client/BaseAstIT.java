package com.ptsecurity.appsec.ai.ee.utils.ci.integration.client;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ptsecurity.appsec.ai.ee.scan.reports.Reports;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBriefDetailed;
import com.ptsecurity.appsec.ai.ee.scan.settings.Policy;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Project;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ProjectTemplate;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.AbstractApiClient;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.Factory;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.GenericAstJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.operations.AbstractFileOperations;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.operations.AstOperations;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.operations.FileOperations;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.tasks.GenericAstTasks;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.tasks.ProjectTasks;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.FileCollector;
import com.ptsecurity.misc.tools.TempFile;
import com.ptsecurity.misc.tools.exceptions.GenericException;
import lombok.Getter;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.experimental.SuperBuilder;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.FileUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.TestInfo;

import java.io.File;
import java.nio.file.Path;
import java.util.UUID;

import static com.ptsecurity.appsec.ai.ee.scan.reports.Reports.Locale.EN;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.ProjectTemplate.randomClone;
import static com.ptsecurity.misc.tools.helpers.BaseJsonHelper.createObjectMapper;
import static com.ptsecurity.misc.tools.helpers.ResourcesHelper.getResourceString;

@Slf4j
public abstract class BaseAstIT extends BaseClientIT {
    @SneakyThrows
    @NonNull
    public static Project setupProjectFromTemplate(@NonNull final ProjectTemplate.ID templateId) {
        return setupProjectFromTemplate(templateId, null);
    }

    @NonNull
    public static Project setupProjectFromTemplate(@NonNull final ProjectTemplate.ID templateId, final String policy) {
        ProjectTemplate randomTemplateInstance = randomClone(templateId);
        return setupProject(randomTemplateInstance, policy);
    }

    @SneakyThrows
    @NonNull
    public static Project setupProject(@NonNull final ProjectTemplate projectTemplate) {
        return setupProject(projectTemplate, null);
    }

    @NonNull
    public static Project setupProject(@NonNull final ProjectTemplate projectTemplate, final String policy) {
        AbstractApiClient client = Factory.client(CONNECTION_SETTINGS());
        ProjectTasks projectTasks = new Factory().projectTasks(client);
        log.trace("Setup {} project from JSON-defined settings", projectTemplate.getName());
        UUID resultProjectId = projectTasks.setupFromJson(projectTemplate.getSettings().toJson(), policy, (projectId) -> {
            GenericAstTasks genericAstTasks = new Factory().genericAstTasks(client);
            genericAstTasks.upload(projectId, projectTemplate.getZip().toFile());
        }).getProjectId();
        return Project.builder()
                .id(resultProjectId)
                .name(projectTemplate.getName())
                .settings(projectTemplate.getSettings())
                .sourcesZipResourceName(projectTemplate.getSourcesZipResourceName())
                .build();
    }

    @RequiredArgsConstructor
    public static class PolicyHelper {
        @Getter
        protected final String json;
        @Getter
        protected final Policy[] policy;

        @SneakyThrows
        public static PolicyHelper fromResource(@NonNull final String name) {
            String json = getResourceString(name);
            Policy[] policy = createObjectMapper().readValue(json, Policy[].class);
            return new PolicyHelper(json, policy);
        }

        protected Path path = null;

        @SneakyThrows
        public Path getPath() {
            if (null == path) {
                path = TempFile.createFile().toPath();
                ObjectMapper mapper = createObjectMapper();
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
    public void pre(@NonNull final TestInfo testInfo) {
        super.pre(testInfo);
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
        public void saveArtifact(@NonNull String name, @NonNull File file) {
            Assertions.assertDoesNotThrow(() -> FileUtils.copyFile(file, destination.resolve(name).toFile()));
        }

        @Override
        protected void saveInMemoryData(@NonNull String name, byte[] data) {
            Assertions.assertDoesNotThrow(() -> FileUtils.writeByteArrayToFile(destination.resolve(name).toFile(), data));
        }
    }
}
