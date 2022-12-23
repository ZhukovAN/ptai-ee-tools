package com.ptsecurity.appsec.ai.ee.utils.ci.integration;

import com.ptsecurity.appsec.ai.ee.helpers.json.JsonSettingsHelper;
import com.ptsecurity.misc.tools.helpers.ArchiveHelper;
import lombok.*;
import lombok.extern.slf4j.Slf4j;

import java.nio.file.Path;
import java.util.UUID;

import static com.ptsecurity.misc.tools.helpers.ArchiveHelper.extractResourceFile;
import static com.ptsecurity.misc.tools.helpers.ResourcesHelper.getResourceString;

@Slf4j
@Getter
@Builder
@AllArgsConstructor
public class Project {
    private static final String PREFIX = "junit-";

    public static final Project JAVA_APP01 = new Project("java-app01");
    public static final Project JAVA_OWASP_BENCHMARK = new Project("java-owasp-benchmark");
    public static final Project PHP_OWASP_BRICKS = new Project("php-owasp-bricks");
    public static final Project PHP_SMOKE = new Project("php-smoke");
    public static final Project JAVASCRIPT_VNWA = new Project("javascript-vnwa");
    public static final Project CSHARP_WEBGOAT = new Project("csharp-webgoat");
    public static final Project PYTHON_DSVW = new Project("python-dsvw");
    public static final Project C_SARD_101_000_149_064 = new Project("c-sard-testsuite-101-000-149-064");

    public static final Project[] ALL = new Project[] { JAVA_APP01, JAVA_OWASP_BENCHMARK, PHP_OWASP_BRICKS, PHP_SMOKE, JAVASCRIPT_VNWA, CSHARP_WEBGOAT, PYTHON_DSVW, C_SARD_101_000_149_064 };
    public static final Project[] TINY = new Project[] { JAVA_APP01, PHP_SMOKE, JAVASCRIPT_VNWA, CSHARP_WEBGOAT, PYTHON_DSVW, C_SARD_101_000_149_064 };

    @Getter
    @Setter
    protected String name;

    @Getter
    @Setter
    protected String settings;

    @Getter
    protected final String sourcesZipResourceName;

    @Builder.Default
    protected Path code = null;

    public Path getCode() {
        if (null == code)
            code = extractResourceFile(sourcesZipResourceName);
        return code;
    }

    @Builder.Default
    protected Path zip = null;

    public Path getZip() {
        if (null == zip) {
            Path sources = getCode();
            zip = ArchiveHelper.packDataZip(sources);
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

    private Project(@NonNull final String name) {
        this(PREFIX + name, "code/" + name + ".7z", "json/scan/settings/settings." + name + ".aiproj");
    }

    public Project randomClone() {
        String cloneName = UUID.randomUUID().toString();
        log.trace("Randomized cloned project name {}", cloneName);
        JsonSettingsHelper settingsHelper = new JsonSettingsHelper(settings).projectName(cloneName);
        return Project.builder()
                .name(cloneName)
                .settings(settingsHelper.serialize())
                .sourcesZipResourceName(sourcesZipResourceName).build();
    }
}

