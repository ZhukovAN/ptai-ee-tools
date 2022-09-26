package com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v411.tasks;

import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief.ScanSettings.Language;
import com.ptsecurity.appsec.ai.ee.scan.settings.Policy;
import com.ptsecurity.appsec.ai.ee.scan.settings.v411.AiProjScanSettings;
import com.ptsecurity.appsec.ai.ee.server.v411.legacy.model.*;
import com.ptsecurity.appsec.ai.ee.server.v411.projectmanagement.ApiException;
import com.ptsecurity.appsec.ai.ee.server.v411.projectmanagement.model.BaseProjectSettingsModel;
import com.ptsecurity.appsec.ai.ee.server.v411.projectmanagement.model.ExtendedBlackBoxSettingsModel;
import com.ptsecurity.appsec.ai.ee.server.v411.projectmanagement.model.PatchBlackBoxSettingsModel;
import com.ptsecurity.appsec.ai.ee.server.v411.projectmanagement.model.ProjectLight;
import com.ptsecurity.appsec.ai.ee.server.v411.projectmanagement.model.ProjectSettingsModel;
import com.ptsecurity.appsec.ai.ee.server.v411.projectmanagement.model.SecurityPoliciesModel;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.AbstractApiClient;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v411.converters.AiProjConverter;
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
import java.util.function.Consumer;

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
        LANGUAGE_GROUP.put(Language.JAVASCRIPT, Collections.singleton(PatternLanguage.JAVASCRIPT));
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
                        // TODO: Replace with apiProjectsLightNameGet when PT AI issue will be fixed
                        return client.getProjectsApi().apiProjectsGet(true).stream().filter(p -> Objects.requireNonNull(p.getName()).equals(name)).findAny().orElse(null);
                        // return client.getProjectsApi().apiProjectsLightNameGet(name);
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

    public JsonParseBrief setupFromJson(@NonNull final String jsonSettings, final String jsonPolicy, @NonNull final Consumer<UUID> uploader) throws GenericException {
        log.trace("Parse settings and policy");
        // Check if JSON settings and policy are defined correctly. Throw an exception if there are problems
        AiProjScanSettings settings = (StringUtils.isEmpty(jsonSettings))
                ? null
                : AiProjConverter.verify(jsonSettings);
        if (null == settings)
            throw GenericException.raise("JSON settings must not be empty", new IllegalArgumentException());
        if (StringUtils.isEmpty(settings.getProjectName()))
            throw GenericException.raise("Project name in JSON settings must not be empty", new IllegalArgumentException());

        Policy[] policy = (StringUtils.isEmpty(jsonPolicy))
                ? null
                : JsonPolicyHelper.verify(jsonPolicy);

        BaseProjectSettingsModel defaultSettings = call(
                client.getProjectsApi()::apiProjectsDefaultSettingsGet,
                "Failed to get default PT AI project settings");
        BaseProjectSettingsModel projectSettings = AiProjConverter.convert(settings, defaultSettings);

        final UUID projectId;
        final ProjectLight projectLight = searchProjectLight(settings.getProjectName());
        if (null == projectLight) {
            log.trace("Create project {} as there's no such project name in PT AI", settings.getProjectName());
            projectId = call(() -> client.getProjectsApi().apiProjectsBasePost(projectSettings), "PT AI project create failed");
            log.debug("Project {} created, ID = {}", settings.getProjectName(), projectId);
        } else
            projectId = projectLight.getId();

        uploader.accept(projectId);

        log.trace("Get existing PT AI project generic settings");
        ProjectSettingsModel projectSettingsModel = call(
                () -> client.getProjectsApi().apiProjectsProjectIdSettingsGet(projectId),
                "Failed to get PT AI project generic settings");
        log.trace("Apply AIPROJ-defined project generic settings");
        AiProjConverter.apply(settings, projectSettingsModel);
        log.trace("Save modified settings");
        call(() -> client.getProjectsApi().apiProjectsProjectIdSettingsPut(projectId, projectSettingsModel),
                "Update PT AI project generic settings failed");

        log.trace("Get existing PT AI project blackbox settings");
        ExtendedBlackBoxSettingsModel blackBoxSettingsModel = call(
                () -> client.getProjectsApi().apiProjectsProjectIdBlackBoxSettingsGet(projectId),
                "Failed to get PT AI project blackbox settings");
        log.trace("Apply AIPROJ-defined project blackbox settings");
        final PatchBlackBoxSettingsModel patch = AiProjConverter.apply(blackBoxSettingsModel, new PatchBlackBoxSettingsModel());
        AiProjConverter.apply(settings, patch);
        log.trace("Save modified blackbox settings");
        call(() -> client.getProjectsApi().apiProjectsProjectIdBlackBoxSettingsPatch(projectId, patch),
                "Update PT AI project blackbox settings failed");

        log.trace("Get existing PT AI project security policy");
        SecurityPoliciesModel securityPoliciesModel = call(
                () -> client.getProjectsApi().apiProjectsProjectIdSecurityPoliciesGet(projectId),
                "failed to get PT AI project security policies");
        log.trace("Apply security policy");
        AiProjConverter.apply(policy, securityPoliciesModel);
        call(
                () -> client.getProjectsApi().apiProjectsProjectIdSecurityPoliciesPut(projectId, securityPoliciesModel),
                "PT AI project policy assignment failed");

        return JsonParseBrief.builder()
                .projectId(projectId)
                .projectName(settings.getProjectName())
                .incremental(true)
                .build();
    }

    @Override
    public void deleteProject(@NonNull UUID id) throws GenericException {
        call(() -> client.getProjectsApi().apiProjectsProjectIdDelete(id), "PT AI project delete failed");
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
