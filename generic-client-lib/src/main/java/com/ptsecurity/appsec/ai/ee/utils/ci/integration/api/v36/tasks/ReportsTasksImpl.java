package com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v36.tasks;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ptsecurity.appsec.ai.ee.scan.reports.Reports;
import com.ptsecurity.appsec.ai.ee.scan.reports.Reports.Data;
import com.ptsecurity.appsec.ai.ee.scan.reports.Reports.Locale;
import com.ptsecurity.appsec.ai.ee.scan.reports.Reports.RawData;
import com.ptsecurity.appsec.ai.ee.scan.reports.Reports.Report;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanResult;
import com.ptsecurity.appsec.ai.ee.server.v36.projectmanagement.model.ReportGenerateModel;
import com.ptsecurity.appsec.ai.ee.server.v36.projectmanagement.model.ReportTemplateModel;
import com.ptsecurity.appsec.ai.ee.server.v36.projectmanagement.model.ReportType;
import com.ptsecurity.appsec.ai.ee.server.v36.projectmanagement.model.UserReportParameters;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.AbstractApiClient;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.Factory;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v36.converters.ReportsConverter;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.exceptions.GenericException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.GenericAstJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.operations.FileOperations;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.tasks.GenericAstTasks;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.tasks.ReportsTasks;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.ReportUtils;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.ScanResultHelper;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.StringHelper;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.json.BaseJsonHelper;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.ImmutableTriple;
import org.apache.commons.lang3.tuple.Triple;
import org.apache.commons.text.similarity.CosineDistance;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.CallHelper.call;

@Slf4j
@SuppressWarnings("unused")
public class ReportsTasksImpl extends AbstractTaskImpl implements ReportsTasks {
    @SuppressWarnings("unused")
    public ReportsTasksImpl(@NonNull final AbstractApiClient client) {
        super(client);
    }

    public void check(@NonNull final Reports reports)  {
        // Check what templates defined in reports are missing on server
        List<ImmutablePair<Locale, String>> missingTemplates = new ArrayList<>();
        // We will download all the templates for supported locales to give hint to user in case of typo in template name
        List<ImmutablePair<Locale, String>> existingTemplates = new ArrayList<>();
        fine("Checking report templates existence");
        for (Locale locale : Locale.values()) {
            // Get all templates for given locale
            List<String> templates = call(
                    () -> client.getReportsApi().apiReportsTemplatesGet(locale.getValue(), false),
                    "PT AI report templates list read failed")
                    .stream()
                    .map(ReportTemplateModel::getName)
                    .collect(Collectors.toList());
            for (String template : templates) existingTemplates.add(new ImmutablePair<>(locale, template));
            // Check if all the required report templates are present in list
            reports.getReport().stream()
                    .filter(r -> locale.equals(r.locale))
                    .map(Report::getTemplate)
                    .forEach(t -> {
                        if (!templates.contains(t)) missingTemplates.add(new ImmutablePair<>(locale, t));
                    });
        }
        if (missingTemplates.isEmpty()) return;

        // Let's give user a hint about most similar template names. To do that
        // we will calculate cosine distance between each of existing templates
        // and user value
        for (ImmutablePair<Locale, String> missing : missingTemplates) {
            List<Triple<Double, Locale, String>> distances = new ArrayList<>();
            for (ImmutablePair<Locale, String> existing : existingTemplates)
                distances.add(new ImmutableTriple<>(
                        new CosineDistance().apply(missing.right, existing.right), existing.left, existing.right));
            distances.sort(Comparator.comparing(Triple::getLeft));
            info(
                    "No '%s' [%s] template name found. Most similar existing template is '%s' [%s] with %.1f%% similarity",
                    missing.right, missing.left, distances.get(0).getRight(), distances.get(0).getMiddle(),
                    100 - distances.get(0).getLeft() * 100);
        }

        List<String> missingTemplateNames = missingTemplates.stream()
                .map(ImmutablePair::getRight)
                .collect(Collectors.toList());

        throw GenericException.raise(
                "Not all report templates are exist on server",
                new IllegalArgumentException("Missing reports are " + StringHelper.joinListGrammatically(missingTemplateNames)));
    }

    @Override
    public void check(@NonNull Report report) throws GenericException {
        // Check what templates defined in reports are missing on server
        // We will download all the templates for supported locales to give hint to user in case of typo in template name
        List<ImmutablePair<Locale, String>> existingTemplates = new ArrayList<>();
        fine("Checking report templates existence");
        for (Locale locale : Locale.values()) {
            // Get all templates for given locale
            List<String> templates = call(
                    () -> client.getReportsApi().apiReportsTemplatesGet(locale.getValue(), false),
                    "PT AI report templates list read failed")
                    .stream()
                    .map(ReportTemplateModel::getName)
                    .collect(Collectors.toList());
            for (String template : templates) existingTemplates.add(new ImmutablePair<>(locale, template));
            // Check if report template is present in list
            if (templates.contains(report.getTemplate())) return;
        }

        // Let's give user a hint about most similar template names. To do that
        // we will calculate cosine distance between each of existing templates
        // and user value
        List<Triple<Double, Locale, String>> distances = new ArrayList<>();
        for (ImmutablePair<Locale, String> existing : existingTemplates)
            distances.add(new ImmutableTriple<>(
                    new CosineDistance().apply(report.getTemplate(), existing.right), existing.left, existing.right));
        distances.sort(Comparator.comparing(Triple::getLeft));
        info(
                "No '%s' [%s] template name found. Most similar existing template is '%s' [%s] with %.1f%% similarity",
                report.getTemplate(), report.getLocale(), distances.get(0).getRight(), distances.get(0).getMiddle(),
                100 - distances.get(0).getLeft() * 100);

        throw GenericException.raise(
                "Report template does not exist on server",
                new IllegalArgumentException("Missing template: " + report.getTemplate()));
    }

    @Override
    public void check(@NonNull Data data) throws GenericException {}

    @Override
    public void check(@NonNull RawData rawData) throws GenericException {}

    @Override
    public void check(Reports.@NonNull Sarif sarif) throws GenericException {

    }

    @Override
    public void check(Reports.@NonNull SonarGiif sonarGiif) throws GenericException {

    }

    /**
     * Generate reports for specific AST result. As this method may be called both
     * for AST job and for CLI reports generation we need to explicitly check reports
     * and not to imply that such check will be done as a first step in
     * calling {@link GenericAstJob#execute()} method
     * @param projectId PT AI project ID
     * @param scanResultId PT AI AST result ID
     * @param reports Reports to be generated. These reports are explicitly checked
     *                as this method may be called directly as not the part
     *                of {@link GenericAstJob#execute()} call
     * @throws GenericException Exception that contains details about failed report validation / generation
     */
    @Override
    public void generate(@NonNull final UUID projectId, @NonNull final UUID scanResultId, @NonNull final Reports reports, @NonNull final FileOperations fileOps) throws GenericException {

        log.trace("Validate and check reports to be generated");
        final Reports checkedReports = ReportUtils.validate(reports);
        check(checkedReports);

        UUID dummyTemplate = getDummyReportTemplateId(Locale.EN);
        final AtomicReference<UUID> finalProjectId = new AtomicReference<>(projectId);

        Stream.concat(checkedReports.getData().stream(), checkedReports.getReport().stream())
                .forEach(r -> {
                    File reportFile;
                    try {
                        if (r instanceof Report) {
                            Report report = (Report) r;
                            reportFile = generateReport(
                                    finalProjectId.get(), scanResultId,
                                    report.getTemplate(), report.getLocale(),
                                    report.getFormat(), report.getFilters());
                        } else if (r instanceof Data) {
                            Data data = (Data) r;
                            reportFile = generateReport(
                                    finalProjectId.get(), scanResultId,
                                    dummyTemplate, data.getLocale(),
                                    data.getFormat(), data.getFilters());
                        } else return;
                        log.trace("Report generated to temp file {}", reportFile.toPath());
                        byte[] data = call(
                                () -> Files.readAllBytes(reportFile.toPath()),
                                "Report data read failed");
                        // Method generateReport uses temporal file so we do not need to remove it manually
                        call(
                                () -> fileOps.saveArtifact(r.getFileName(), data),
                                "Report file save failed");
                    } catch (GenericException e) {
                        warning(e);
                    }
                });
        if (null != checkedReports.getRaw()) {
            // Save raw JSON report
            GenericAstTasks genericAstTasks = new Factory().genericAstTasks(client);
            ScanResult scanResult = genericAstTasks.getScanResult(projectId, scanResultId);
            final ObjectMapper mapper = BaseJsonHelper.createObjectMapper();
            File json = call(
                    () -> {
                        Path temp = Files.createTempFile("ptai-", "-scanresult");
                        log.debug("Created file {} for temporal raw scan result store", temp);
                        mapper.writeValue(temp.toFile(), scanResult);
                        log.debug("Raw scan result data saved to {}", temp);
                        return temp.toFile();
                    }, "Raw scan result save failed");
            for (RawData raw : checkedReports.getRaw())
                call(() -> fileOps.saveArtifact(raw.getFileName(), json), "Raw JSON result save failed");
            log.debug("Deleting temporal raw scan results file {}", json.getAbsolutePath());
            call(json::delete, "Temporal file " + json.getAbsolutePath() + " delete failed", true);
        }
    }

    @Override
    public void generate(@NonNull UUID projectId, @NonNull UUID scanResultId, @NonNull Report report, @NonNull FileOperations fileOps) throws GenericException {
        File reportFile = generateReport(
                projectId, scanResultId,
                report.getTemplate(), report.getLocale(),
                report.getFormat(), report.getFilters());
        log.trace("Report generated to temp file {}", reportFile.toPath());
        byte[] data = call(
                () -> Files.readAllBytes(reportFile.toPath()),
                "Report data read failed");
        // Method generateReport uses temporal file so we do not need to remove it manually
        call(
                () -> fileOps.saveArtifact(report.getFileName(), data),
                "Report file save failed");
    }

    @Override
    public void generate(@NonNull UUID projectId, @NonNull UUID scanResultId, @NonNull Data data, @NonNull FileOperations fileOps) throws GenericException {
        UUID dummyTemplate = getDummyReportTemplateId(Locale.EN);
        File reportFile = generateReport(
                projectId, scanResultId,
                dummyTemplate, data.getLocale(),
                data.getFormat(), data.getFilters());
        log.trace("Report generated to temp file {}", reportFile.toPath());
        byte[] reportData = call(
                () -> Files.readAllBytes(reportFile.toPath()),
                "Report data read failed");
        // Method generateReport uses temporal file so we do not need to remove it manually
        call(
                () -> fileOps.saveArtifact(data.getFileName(), reportData),
                "Report file save failed");
    }

    @Override
    public void generate(@NonNull UUID projectId, @NonNull UUID scanResultId, @NonNull RawData rawData, @NonNull FileOperations fileOps) throws GenericException {
        // Save raw JSON report
        GenericAstTasks genericAstTasks = new Factory().genericAstTasks(client);
        ScanResult scanResult = genericAstTasks.getScanResult(projectId, scanResultId);
        ScanResultHelper.apply(scanResult, rawData.getFilters());
        final ObjectMapper mapper = BaseJsonHelper.createObjectMapper();
        File json = call(
                () -> {
                    Path temp = Files.createTempFile("ptai-", "-scanresult");
                    log.debug("Created file {} for temporal raw scan result store", temp);
                    mapper.writeValue(temp.toFile(), scanResult);
                    log.debug("Raw scan result data saved to {}", temp);
                    return temp.toFile();
                }, "Raw scan result save failed");
        call(() -> fileOps.saveArtifact(rawData.getFileName(), json), "Raw JSON result save failed");
        log.debug("Deleting temporal raw scan results file {}", json.getAbsolutePath());
        call(json::delete, "Temporal file " + json.getAbsolutePath() + " delete failed", true);
    }

    @Override
    public UUID getDummyReportTemplateId(@NonNull Locale locale) throws GenericException {
        List<ReportTemplateModel> templates = call(
                () -> client.getReportsApi().apiReportsTemplatesGet(locale.getValue(), false),
                "PT AI report templates list read failed");
        return templates.stream()
                .filter(t -> ReportType.PLAINREPORT.equals(t.getType()))
                .findAny()
                .map(ReportTemplateModel::getId)
                .orElseThrow(() -> GenericException.raise("Built-in PT AI report template missing", new IllegalArgumentException(ReportType.PLAINREPORT.getValue())));
    }

    @Override
    public File generateReport(
            @NonNull UUID projectId, @NonNull UUID scanResultId, @NonNull UUID templateId,
            @NonNull Locale locale, @NonNull Report.Format type,
            Reports.IssuesFilter filters) throws GenericException {
        log.trace("Create report generation model");
        ReportGenerateModel model = new ReportGenerateModel()
                .parameters(new UserReportParameters()
                        .includeDFD(true)
                        .includeGlossary(true)
                        .useFilters(null != filters)
                        .formatType(ReportsConverter.convert(type))
                        .reportTemplateId(templateId)
                        .saveAsPath(""))
                .scanResultId(scanResultId)
                .projectId(projectId)
                .localeId(locale.getValue());
        if (null != filters) model.setFilters(ReportsConverter.convert(filters));
        fine("Generating report for project %s, scan result %s. Report template %s, type %s, locale %s", projectId, scanResultId, templateId, type, locale);
        return call(
                () -> client.getReportsApi().apiReportsGeneratePost(model),
                "Report generation failed");
    }

    @Override
    public File generateReport(
            @NonNull UUID projectId, @NonNull UUID scanResultId, @NonNull UUID templateId,
            @NonNull Locale locale, @NonNull Data.Format type,
            Reports.IssuesFilter filters) throws GenericException {
        ReportGenerateModel model = new ReportGenerateModel()
                .parameters(new UserReportParameters()
                        .includeDFD(true)
                        .includeGlossary(true)
                        .useFilters(null != filters)
                        .formatType(ReportsConverter.convert(type))
                        .reportTemplateId(templateId)
                        .saveAsPath(""))
                .scanResultId(scanResultId)
                .projectId(projectId)
                .localeId(locale.getValue());
        if (null != filters) model.setFilters(ReportsConverter.convert(filters));
        fine("Generating report for project %s, scan result %s. Report template %s, type %s, locale %s", projectId, scanResultId, templateId, type, locale);
        return call(
                () -> client.getReportsApi().apiReportsGeneratePost(model),
                "Report generation failed");
    }

    @Override
    public List<String> listReportTemplates(Locale locale)  throws GenericException {
        List<ReportTemplateModel> reportTemplateModels = call(
                () -> client.getReportsApi().apiReportsTemplatesGet(locale.getValue(), false),
                "PT AI report templates list read failed");
        return reportTemplateModels.stream().map(ReportTemplateModel::getName).collect(Collectors.toList());
    }

    protected File generateReport(
            @NonNull UUID projectId, @NonNull UUID scanResultId, @NonNull String template,
            @NonNull Locale locale, @NonNull Data.Format type,
            Reports.IssuesFilter filters) throws GenericException {
        // Get all report templates for given locale
        List<ReportTemplateModel> templates = call(
                () -> client.getReportsApi().apiReportsTemplatesGet(locale.getValue(), false),
                "PT AI report templates list read failed");
        ReportTemplateModel templateModel = templates.stream().filter(t -> template.equalsIgnoreCase(t.getName())).findAny().orElse(null);
        if (null == templateModel || null == templateModel.getId())
            throw GenericException.raise("Report generation failed", new IllegalArgumentException("PT AI template " + template + " not found"));
        return generateReport(projectId, scanResultId, templateModel.getId(), locale, type, filters);
    }

    protected File generateReport(
            @NonNull UUID projectId, @NonNull UUID scanResultId, @NonNull String template,
            @NonNull Locale locale, @NonNull Report.Format type,
            Reports.IssuesFilter filters) throws GenericException {
        // Get all report templates for given locale
        log.trace("Load all report templates to find one with {} name", template);
        List<ReportTemplateModel> templates = call(
                () -> client.getReportsApi().apiReportsTemplatesGet(locale.getValue(), false),
                "PT AI report templates list read failed");
        ReportTemplateModel templateModel = templates.stream().filter(t -> template.equalsIgnoreCase(t.getName())).findAny().orElse(null);
        if (null == templateModel || null == templateModel.getId())
            throw GenericException.raise("Report generation failed", new IllegalArgumentException("PT AI template " + template + " not found"));
        return generateReport(projectId, scanResultId, templateModel.getId(), locale, type, filters);
    }
}
