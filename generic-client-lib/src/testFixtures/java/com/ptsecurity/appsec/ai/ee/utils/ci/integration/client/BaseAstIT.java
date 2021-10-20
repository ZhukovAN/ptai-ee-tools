package com.ptsecurity.appsec.ai.ee.utils.ci.integration.client;

import com.ptsecurity.appsec.ai.ee.scan.reports.Reports;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBriefDetailed;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.exceptions.GenericException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.GenericAstJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.operations.AstOperations;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.operations.FileOperations;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.FileCollector;
import lombok.NonNull;
import lombok.experimental.SuperBuilder;
import org.apache.commons.io.FileUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;

import java.io.File;
import java.nio.file.Path;
import java.util.Map;
import java.util.UUID;

import static com.ptsecurity.appsec.ai.ee.scan.reports.Reports.Locale.EN;

public abstract class BaseAstIT extends BaseClientIT {
    protected Reports.Report report;
    protected Reports.Data data;
    protected Reports.RawData rawData;

    @BeforeEach
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
