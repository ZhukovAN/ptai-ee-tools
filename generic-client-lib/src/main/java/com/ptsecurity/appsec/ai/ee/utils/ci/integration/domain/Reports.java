package com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.exceptions.GenericException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.StringHelper;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.json.BaseJsonHelper;
import lombok.ToString;
import org.apache.commons.lang3.StringUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.CallHelper.call;

@ToString(callSuper = true)
public class Reports extends com.ptsecurity.appsec.ai.ee.scan.reports.Reports {
    /**
     * Method performs report settings validation."Validation" means that no PT AI server
     * interactions are performed at this stage. Reports checked against duplication of file names
     * @return "This" instance of reports being checked
     * @throws GenericException Exception that contains info about validation problems
     */
    public Reports validate() throws GenericException {
        // Check if all the report templates are defined
        if (report.stream().map(Report::getTemplate).anyMatch(StringUtils::isEmpty))
            throw GenericException.raise("There are one or more empty templates", new IllegalArgumentException());
        // Check if all the report file names are unique
        List<String> names = Stream.concat(report.stream(), data.stream())
                .map(AbstractReport::getFileName).collect(Collectors.toList());
        if (null != raw)
            names.addAll(raw.stream().map(RawData::getFileName).collect(Collectors.toList()));
        // All file names are added to names list, let's count unique names
        Map<String, Long> counters = names.stream()
                .collect(Collectors.groupingBy(n -> n, Collectors.counting()));
        List<String> duplicates = new ArrayList<>();
        for (String name : counters.keySet())
            if (1 < counters.get(name)) duplicates.add(name);

        if (duplicates.isEmpty()) return this;

        throw GenericException.raise(
                "Duplicate output file names found",
                new IllegalArgumentException("Duplicates are " + StringHelper.joinListGrammatically(duplicates)));
    }

    public static IssuesFilter validateJsonFilter(String json) throws GenericException {
        return call(
                () -> BaseJsonHelper.createObjectMapper().readValue(json, IssuesFilter.class),
                "JSON filter settings parse failed");
    }

    /**
     * Method loads and validates reporting settings from JSON string
     * @param json String that contains JSON-defined reporting settings
     * @return Validated reports instance that corresponds JSON data
     * @throws GenericException Exception that contains error info if
     * JSON load / parse / validation was failed
     */
    public static Reports validateJsonReports(final String json) throws GenericException {
        return load(json).validate();
    }

    /**
     * Method loads JSON-defined reporting settings from string
     * @param json String that contains JSON-defined reporting settings
     * @return Reports instance that corresponds JSON data
     * @throws GenericException Exception that contains error info if JSON load / parse was failed
     */
    public static Reports load(String json) throws GenericException {
        return call(
                () -> BaseJsonHelper.createObjectMapper().readValue(json, Reports.class),
                Resources.i18n_ast_result_reporting_json_message_file_parse_failed());
    }
}
