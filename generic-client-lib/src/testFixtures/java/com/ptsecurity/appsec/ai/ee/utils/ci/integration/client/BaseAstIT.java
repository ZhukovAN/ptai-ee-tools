package com.ptsecurity.appsec.ai.ee.utils.ci.integration.client;

import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.exceptions.GenericException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.GenericAstJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.operations.AstOperations;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.operations.FileOperations;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.FileCollector;
import lombok.NonNull;
import lombok.experimental.SuperBuilder;
import org.apache.commons.io.FileUtils;
import org.junit.jupiter.api.Assertions;

import java.io.File;
import java.nio.file.Path;
import java.util.Map;
import java.util.UUID;

public class BaseAstIT extends BaseClientIT {
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
        public void scanCompleteCallback(@NonNull ScanBrief scanBrief) throws GenericException {
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
