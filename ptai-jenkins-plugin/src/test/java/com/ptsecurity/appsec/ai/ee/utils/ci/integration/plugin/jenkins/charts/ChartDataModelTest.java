package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.charts;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanResult;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.test.BaseTest;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.json.BaseJsonHelper;
import lombok.SneakyThrows;
import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.InputStream;

class ChartDataModelTest extends BaseTest {
    @Test
    @SneakyThrows
    public void testJsonConversion() {
        ObjectMapper mapper = createFaultTolerantObjectMapper();
        for (Connection.Version version : Connection.Version.values()) {
            if (version == Connection.Version.V42) continue;
            String json = extractSevenZippedSingleStringFromResource("json/scan/result/" + version.name().toLowerCase() + "/" + PHP_OWASP_BRICKS_PROJECT_NAME + ".json.7z");
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