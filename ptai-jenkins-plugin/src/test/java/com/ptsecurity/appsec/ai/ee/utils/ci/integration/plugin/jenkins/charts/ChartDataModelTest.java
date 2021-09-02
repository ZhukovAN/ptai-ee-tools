package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.charts;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanResult;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.test.BaseTest;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.json.BaseJsonHelper;
import lombok.SneakyThrows;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.InputStream;

class ChartDataModelTest extends BaseTest {
    @Test
    @SneakyThrows
    public void testJsonConversion() {
        ObjectMapper mapper = BaseJsonHelper.createObjectMapper();
        InputStream inputStream = getResourceStream("json/scan/result/php-bricks.json");
        Assertions.assertNotNull(inputStream);
        ScanResult scanResult = mapper.readValue(inputStream, ScanResult.class);
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