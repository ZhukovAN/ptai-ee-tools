package com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v40.tasks;

import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief.ScanSettings.Language;
import com.ptsecurity.appsec.ai.ee.scan.settings.AiProjScanSettings;
import com.ptsecurity.appsec.ai.ee.scan.settings.Policy;
import com.ptsecurity.appsec.ai.ee.server.v40.legacy.model.*;
import com.ptsecurity.appsec.ai.ee.server.v40.projectmanagement.ApiException;
import com.ptsecurity.appsec.ai.ee.server.v40.projectmanagement.model.BaseProjectSettingsModel;
import com.ptsecurity.appsec.ai.ee.server.v40.projectmanagement.model.ProjectLight;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.AbstractApiClient;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v40.converters.AiProjConverter;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain.TokenCredentials;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.exceptions.GenericException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.tasks.ProjectTasks;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.json.JsonPolicyHelper;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.http.HttpStatus;

import java.util.*;

import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.CallHelper.call;

@Slf4j
public class ProjectTasksImpl extends AbstractTaskImpl implements ProjectTasks {
    /**
     * When we need to create project using AIPROJ file we need to define enabled 
     * and disabled patterns. The list of available patterns may be downloaded 
     * from /api/Configs/pmPatterns endpoint. Each pattern includes programmingLanguages 
     * field that is a binary AND of PatternLanguage item values
     */
    @RequiredArgsConstructor
    public enum PatternLanguage {
        NONE(0),
        /**
         * 0x00040000
         */
        VB(262144),
        DOTNET(1),
        /**
         * 0x00020000
         */
        CSHARP(131072),
        PHP(2),
        JAVA(4),
        HTML(8),
        /**
         * 0x00000010
         */
        JAVASCRIPT(16),
        /**
         * 0x00000040
         */
        SANDBOX(64),
        /**
         * 0x00000080
         */
        BINARY(128),
        /**
         * 0x00000100
         */
        PLSQL(256),
        /**
         * 0x00000200
         */
        TSQL(512),
        /**
         * 0x00008000
         */
        MYSQL(32768),
        /**
         * 0x00000400
         */
        ASPX(1024),
        /**
         * 0x00000800
         */
        C(2048),
        /**
         * 0x00001000
         */
        CPLUSPLUS(4096),
        /**
         * 0x00002000
         */
        OBJECTIVEC(8192),
        /**
         * 0x00004000
         */
        SWIFT(16384),
        /**
         * 0x00010000
         */
        PYTHON(65536),
        /**
         * 0x00080000
         */
        GO(524288),
        /**
         * 0x00100000
         */
        KOTLIN(1048576);

        private final int value;
    }

    /**
     * See Messages.DataContracts.LanguageExtensions::LangGroupToLangMapping
     */
    public static Map<Language, Set<PatternLanguage>> LANGUAGE_GROUP = new HashMap<>();
    static {
        LANGUAGE_GROUP.put(Language.PHP, Collections.singleton(PatternLanguage.PHP));
        LANGUAGE_GROUP.put(Language.JAVA, Collections.singleton(PatternLanguage.JAVA));
        LANGUAGE_GROUP.put(Language.CSHARP, Collections.singleton(PatternLanguage.CSHARP));
        LANGUAGE_GROUP.put(Language.VB, Collections.singleton(PatternLanguage.VB));
        LANGUAGE_GROUP.put(Language.JS, Collections.singleton(PatternLanguage.JAVASCRIPT));
        LANGUAGE_GROUP.put(Language.PYTHON, Collections.singleton(PatternLanguage.PYTHON));
        LANGUAGE_GROUP.put(Language.OBJECTIVEC, Collections.singleton(PatternLanguage.OBJECTIVEC));
        LANGUAGE_GROUP.put(Language.SWIFT, Collections.singleton(PatternLanguage.SWIFT));
        LANGUAGE_GROUP.put(Language.KOTLIN, Collections.singleton(PatternLanguage.KOTLIN));
        LANGUAGE_GROUP.put(Language.GO, Collections.singleton(PatternLanguage.GO));
        LANGUAGE_GROUP.put(Language.SQL, new HashSet<>(Arrays.asList(PatternLanguage.MYSQL, PatternLanguage.PLSQL, PatternLanguage.TSQL)));
        LANGUAGE_GROUP.put(Language.CPP, new HashSet<>(Arrays.asList(PatternLanguage.C, PatternLanguage.CPLUSPLUS)));
    }

    public ProjectTasksImpl(@NonNull final AbstractApiClient client) {
        super(client);
    }

    public UUID searchProject(
            @NonNull final String name) throws GenericException {
        ProjectLight projectLight = searchProjectLight(name);
        return (null != projectLight) ? projectLight.getId() : null;
    }

    protected ProjectLight searchProjectLight(
            @NonNull final String name) throws GenericException {
        log.debug("Looking for project with name {}", name);
        ProjectLight projectLight = call(
                () -> {
                    try {
                        return client.getProjectsApi().apiProjectsLightNameGet(name);
                    } catch (ApiException e) {
                        log.trace("PT AI v.4.0 API returns HTTP status 204 if there's no project with given name {}", name);
                        if (HttpStatus.SC_NO_CONTENT == e.getCode()) return null;
                        throw e;
                    }
                },
                "PT AI project search failed");
        if (null == projectLight) {
            log.debug("Project not found");
            return null;
        } else {
            log.debug("Project found, id is {}", projectLight.getId());
            return projectLight;
        }
    }

    public String searchProject(
            @NonNull final UUID id) throws GenericException {
        log.debug("Looking for project with id {}", id);
        String result = call(
                () -> {
                    try {
                        return client.getProjectsApi().apiProjectsProjectIdNameGet(id);
                    } catch (ApiException e) {
                        log.trace("PT AI v.4.0 API returns HTTP status 204 if there's no project with given Id {}", id);
                        if (HttpStatus.SC_NO_CONTENT == e.getCode()) return null;
                        throw e;
                    }
                },
                "PT AI project search failed");
        if (null == result)
            log.debug("Project not found");
        else
            log.debug("Project found, name is {}", result);
        return result;
    }

    @Override
    public UUID getLatestAstResult(@NonNull UUID id) throws GenericException {
        ScanResult scanResult = call(
                () -> client.getLegacyProjectsApi().apiProjectsProjectIdScanResultsLastGet(id),
                "PT AI project latest scan result search failed");
        return (null == scanResult) ? null : scanResult.getId();
    }

    @Override
    @NonNull
    public UUID getLatestCompleteAstResult(@NonNull UUID id) throws GenericException {
        List<ScanResult> scanResults = call(
                () -> client.getLegacyProjectsApi().apiProjectsProjectIdScanResultsGet(id, AuthScopeType.ACCESSTOKEN),
                "PT AI project scan results load failed");
        ScanResult result = scanResults.stream()
                .filter(r -> null != r.getProgress())
                .filter(r -> Stage.DONE.equals(r.getProgress().getStage()))
                .findAny()
                .orElseThrow(() -> GenericException.raise("Project finished scan results are not found", new IllegalArgumentException(id.toString())));
        return result.getId();
    }

    public UUID setupFromJson(@NonNull final AiProjScanSettings settings, final Policy[] policy) throws GenericException {
        if (StringUtils.isEmpty(settings.getProjectName()))
            throw GenericException.raise("Project name in JSON settings must not be empty", new IllegalArgumentException());

        // PT AI server API doesn't create project if DisabledPatterms and EnabledPatterns
        // are missing even if scanAppType have no PmTaint. So we need at least pass empty
        // arrays and use predefined enabled / disabled pattern lists
        List<String> defaultEnabledPatterns = new ArrayList<>();
        List<String> defaultDisabledPatterns = new ArrayList<>();
        List<com.ptsecurity.appsec.ai.ee.server.v40.legacy.model.PmPattern> patterns = call(
                () -> client.getLegacyConfigsApi().apiConfigsPmPatternsGet(),
                "PT AI patterns load failed");
        Set<PatternLanguage> languages = LANGUAGE_GROUP.get(settings.getProgrammingLanguage());
        long languageMask = 0;
        for (PatternLanguage pl : languages) languageMask |= pl.value;
        for (PmPattern pmPattern : patterns) {
            Long patternLanguages = pmPattern.getProgrammingLanguages();
            if (null == patternLanguages) {
                log.warn("PM pattern programming languages is null for {}", pmPattern);
                continue;
            }
            if (0 == (patternLanguages & languageMask)) {
                // Pattern can't be applied to this language. Add it to disabledPatterns
                defaultDisabledPatterns.add(pmPattern.getKey());
                log.debug("Added default disabled pattern {}", pmPattern.getKey());
            } else {
                defaultEnabledPatterns.add(pmPattern.getKey());
                log.debug("Added default enabled pattern {}", pmPattern.getKey());
            }
        }
        final V40ScanSettings scanSettings = AiProjConverter.convert(settings, defaultEnabledPatterns, defaultDisabledPatterns);

        final UUID projectId;
        final ProjectLight projectLight = searchProjectLight(settings.getProjectName());
        if (null == projectLight) {
            com.ptsecurity.appsec.ai.ee.server.v40.legacy.model.CreateProjectModel createProjectModel = new com.ptsecurity.appsec.ai.ee.server.v40.legacy.model.CreateProjectModel();
            createProjectModel.setName(settings.getProjectName());
            createProjectModel.setScanSettings(scanSettings);
            com.ptsecurity.appsec.ai.ee.server.v40.legacy.model.Project project = call(
                    () -> client.getLegacyProjectsApi().apiProjectsPost(createProjectModel),
                    "PT AI project create failed");
            projectId = project.getId();
            log.debug("Project {} created, ID = {}", settings.getProjectName(), projectLight);
        } else {
            projectId = projectLight.getId();
            scanSettings.setId(projectLight.getSettingsId());
            call(
                    () -> client.getLegacyProjectsApi().apiProjectsProjectIdScanSettingsPut(projectId, scanSettings),
                    "PT AI project settings update failed");
        }

        String policyJson = (null == policy) ? "" : JsonPolicyHelper.serialize(policy);
        call(
                () -> client.getLegacyProjectsApi().apiProjectsProjectIdPoliciesRulesPut(projectId, policyJson),
                "PT AI project policy assignment failed");
        return projectId;
    }

    @Override
    public void deleteProject(@NonNull UUID id) throws GenericException {
        call(() -> client.getLegacyProjectsApi().apiProjectsProjectIdDelete(id), "PT AI project delete failed");
    }

    @Override
    @NonNull
    public List<Pair<UUID, String>> listProjects() throws GenericException {
        // PT AI v.3.6 supports project list load:
        // without details - if API token authentication used
        // with details - if login / password authentication used
        boolean withoutDetails = client.getConnectionSettings().getCredentials() instanceof TokenCredentials;
        List<ProjectLight> projects = call(() -> client.getProjectsApi().apiProjectsGet(false), "PT AI project list read failed");
        List<Pair<UUID, String>> res = new ArrayList<>();
        for (ProjectLight project : projects)
            res.add(Pair.of(project.getId(), project.getName()));
        return res;
    }
}
