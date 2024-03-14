package com.ptsecurity.appsec.ai.ee.server.v470;

import com.ptsecurity.appsec.ai.ee.server.v470.api.model.*;
import com.ptsecurity.appsec.ai.ee.server.v470.helpers.ApiHelper;
import com.ptsecurity.misc.tools.BaseTest;
import lombok.extern.slf4j.Slf4j;

import java.util.Collections;
import java.util.UUID;

import static com.ptsecurity.appsec.ai.ee.server.helpers.AbstractApiHelper.TokenType.CI;
import static com.ptsecurity.appsec.ai.ee.server.helpers.AbstractApiHelper.TokenType.ROOT;
import static com.ptsecurity.appsec.ai.ee.server.helpers.AbstractApiHelper.checkApiCall;
import static com.ptsecurity.appsec.ai.ee.server.v470.helpers.ApiHelper.PROJECTS;
import static com.ptsecurity.appsec.ai.ee.server.v470.helpers.ApiHelper.STORE;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.ProjectTemplate.ID.PHP_SMOKE;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.ProjectTemplate.getTemplate;
import static com.ptsecurity.misc.tools.helpers.CallHelper.call;
import static org.junit.jupiter.api.Assertions.assertNotNull;

@Slf4j
public abstract class AbstractTest extends BaseTest {
    protected static final ApiHelper API = new ApiHelper();
    protected static final String PROJECT_NAME = randomProjectName(getTemplate(PHP_SMOKE).getName());
    protected static UUID PROJECT_ID;

    public static void init() {
        BaseTest.init();
    }

    protected static void authenticate() {
        API.authenticate();
    }

    protected static void createTestProject() {
        log.trace("Test get default project settings");
        ApiHelper.setJwt(CI);
        DefaultProjectSettingsModel defaultProjectSettings = call(
                com.ptsecurity.appsec.ai.ee.server.v470.helpers.ApiHelper.PROJECTS::apiProjectsDefaultSettingsGet,
                "Get default project settings API call failed");


        log.trace("Test project creation");
        CreateProjectSettingsModel projectSettings = new CreateProjectSettingsModel()
                .id(defaultProjectSettings.getId())
                .name(PROJECT_NAME)
                .languages(Collections.singletonList(ProgrammingLanguageGroup.PHP))
                .whiteBox(new WhiteBoxSettingsModel()
                        .searchForVulnerableComponentsEnabled(false)
                        .patternMatchingEnabled(false)
                        .staticCodeAnalysisEnabled(false)
                        .searchForConfigurationFlawsEnabled(true))
                .projectUrl(defaultProjectSettings.getProjectUrl())
                .blackBox(defaultProjectSettings.getBlackBox())
                .blackBoxEnabled(defaultProjectSettings.getBlackBoxEnabled());

        PROJECT_ID = call(
                () -> PROJECTS.apiProjectsBasePost(projectSettings),
                "Base project create API call failed");
        assertNotNull(PROJECT_ID);

        call(
                () -> STORE.apiStoreProjectIdSourcesPost(PROJECT_ID, true, true, getTemplate(PHP_SMOKE).getZip().toFile()),
                "Zipped project sources store API call failed");

        call(() -> {
            ProjectSettingsModel settings = PROJECTS.apiProjectsProjectIdSettingsGet(PROJECT_ID);
            ProjectSettingsUpdatedModel projectSettingsUpdatedModel = new ProjectSettingsUpdatedModel()
                    .projectName(settings.getProjectName())
                    .languages(settings.getLanguages())
                    .whiteBoxSettings(settings.getWhiteBoxSettings());
            PROJECTS.apiProjectsProjectIdSettingsPut(PROJECT_ID, projectSettingsUpdatedModel);
        }, "Update PT AI project generic settings failed");
    }

    public static void deleteTestProject() {
        log.trace("Check project delete calls");
        assertNotNull(PROJECT_ID);
        checkApiCall(() -> PROJECTS.apiProjectsProjectIdDelete(PROJECT_ID), ROOT);
    }
}