package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.charts;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief.ApiVersion;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanResult;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ProjectTemplate;
import com.ptsecurity.misc.tools.BaseTest;
import com.ptsecurity.misc.tools.helpers.ResourcesHelper;
import lombok.SneakyThrows;
import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.ProjectTemplate.getTemplate;
import static com.ptsecurity.misc.tools.helpers.BaseJsonHelper.createObjectMapper;

class ChartDataModelTest extends BaseTest {
    @Test
    @SneakyThrows
    public void testJsonConversion() {
        ObjectMapper mapper = createObjectMapper();
        for (ApiVersion version : ApiVersion.values()) {
            if (version.isDeprecated()) continue;
            ProjectTemplate projectTemplate = getTemplate(ProjectTemplate.ID.PHP_OWASP_BRICKS);
            String json = ResourcesHelper.getResource7ZipString("json/scan/result/" + version.name().toLowerCase() + "/" + projectTemplate.getName() + ".json.7z");
            Assertions.assertFalse(StringUtils.isEmpty(json));
            ScanResult scanResult = mapper.readValue(json, ScanResult.class);
        }
        // StackedAreaChartDataModel model = StackedAreaChartDataModel.create(issuesModelList);
        /*
        TypeReference<Map<String,IssuesModel>> typeRef = new TypeReference<Map<String,IssuesModel>>() {};
        Map<String, IssuesModel> issuesModelMap = Assertions.assertDoesNotThrow(
                () -> mapper.readValue(new FileInputStream(issuesFile.toFile()), typeRef),
                "IssuesModel test data load failed");

        List<Triple<Integer, LocalDateTime, IssuesModel>> issuesModelList = new ArrayList<>();
        int counter = 0;
        for (String key : issuesModelMap.keySet())
            issuesModelList.add(new ImmutableTriple<>(counter++, LocalDateTime.parse(key, DateTimeFormatter.ISO_DATE_TIME), issuesModelMap.get(key)));
        StackedAreaChartDataModel model = StackedAreaChartDataModel.create(issuesModelList);
        JSONObject jsonObject = BaseJsonChartDataModel.convertObject(model);
        System.out.println(jsonObject);

         */
    }
}