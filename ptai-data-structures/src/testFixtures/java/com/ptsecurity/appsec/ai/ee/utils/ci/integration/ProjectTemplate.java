package com.ptsecurity.appsec.ai.ee.utils.ci.integration;

import com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings;
import com.ptsecurity.misc.tools.BaseTest;
import com.ptsecurity.misc.tools.helpers.ArchiveHelper;
import lombok.*;
import lombok.experimental.SuperBuilder;
import lombok.extern.slf4j.Slf4j;

import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;

import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.ProjectTemplate.ID.PHP_SMOKE;
import static com.ptsecurity.misc.tools.helpers.ArchiveHelper.extractResourceFile;
import static com.ptsecurity.misc.tools.helpers.ResourcesHelper.getResourceString;

@Slf4j
@Getter
@SuperBuilder
@AllArgsConstructor
public class ProjectTemplate {
    public enum ID {
        JAVA_APP01,
        JAVA_OWASP_BENCHMARK,
        PHP_OWASP_BRICKS,
        PHP_SMOKE,
        JAVASCRIPT_VNWA,
        CSHARP_WEBGOAT,
        PYTHON_DSVW,
        C_SARD_101_000_149_064
    }

    private static final Map<ID, ProjectTemplate> TEMPLATES = new HashMap<>();

    static {
        TEMPLATES.put(ID.JAVA_APP01, new ProjectTemplate("java-app01"));
        TEMPLATES.put(ID.JAVA_OWASP_BENCHMARK, new ProjectTemplate("java-owasp-benchmark"));
        TEMPLATES.put(ID.PHP_OWASP_BRICKS, new ProjectTemplate("php-owasp-bricks"));
        TEMPLATES.put(PHP_SMOKE, new ProjectTemplate("php-smoke"));
        TEMPLATES.put(ID.JAVASCRIPT_VNWA, new ProjectTemplate("javascript-vnwa"));
        TEMPLATES.put(ID.CSHARP_WEBGOAT, new ProjectTemplate("csharp-webgoat"));
        TEMPLATES.put(ID.PYTHON_DSVW, new ProjectTemplate("python-dsvw"));
        TEMPLATES.put(ID.C_SARD_101_000_149_064, new ProjectTemplate("c-sard-testsuite-101-000-149-064"));
    }

    public static final ID[] TINY = new ID[] { ID.JAVA_APP01, ID.PHP_SMOKE, ID.JAVASCRIPT_VNWA, ID.CSHARP_WEBGOAT, ID.PYTHON_DSVW, ID.C_SARD_101_000_149_064 };

    @Getter
    @Setter
    protected String name;

    @Getter
    @Setter
    protected UnifiedAiProjScanSettings settings;

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
    private ProjectTemplate(@NonNull final String name, @NonNull final String sourcesZipResourceName, @NonNull final String settingsResourceName) {
        this.name = name;
        this.settings = UnifiedAiProjScanSettings.loadSettings(getResourceString(settingsResourceName));
        this.sourcesZipResourceName = sourcesZipResourceName;
    }

    private ProjectTemplate(@NonNull final String name) {
        this("junit-" + name, "code/" + name + ".7z", "json/scan/settings/legacy/settings." + name + ".json");
    }

    public static ProjectTemplate getTemplate(@NonNull final ProjectTemplate.ID sourceTemplate) {
        return TEMPLATES.get(sourceTemplate);
    }

    public static ProjectTemplate randomClone(@NonNull final ProjectTemplate.ID sourceTemplate, @NonNull final String projectName) {
        ProjectTemplate projectTemplate = TEMPLATES.get(sourceTemplate);
        log.trace("Cloned project name {}", projectName);
        String json = projectTemplate.getSettings().toJson();
        UnifiedAiProjScanSettings randomSettings = UnifiedAiProjScanSettings.loadSettings(json);
        randomSettings.setProjectName(projectName);

        return ProjectTemplate.builder()
                .name(projectName)
                .settings(randomSettings)
                .sourcesZipResourceName(projectTemplate.getSourcesZipResourceName()).build();
    }
    public static ProjectTemplate randomClone(@NonNull final ProjectTemplate.ID sourceTemplate) {
        ProjectTemplate projectTemplate = TEMPLATES.get(sourceTemplate);
        return randomClone(sourceTemplate, BaseTest.randomProjectName(projectTemplate.getName()));
    }
}

