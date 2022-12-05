package com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v42.tasks;

import com.contrastsecurity.sarif.SarifSchema210;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ptsecurity.appsec.ai.ee.scan.reports.Reports;
import com.ptsecurity.appsec.ai.ee.scan.reports.Reports.*;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanResult;
import com.ptsecurity.appsec.ai.ee.server.v42.api.model.*;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.AbstractApiClient;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.Factory;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.exceptions.GenericException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.GenericAstJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.subjobs.export.SonarGiif.SonarGiifReport;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.operations.FileOperations;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.tasks.GenericAstTasks;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.tasks.ReportsTasks;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.*;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.json.BaseJsonHelper;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.commons.text.similarity.CosineDistance;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

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
        List<String> missingTemplates = new ArrayList<>();
        // We will download all the templates for supported locales to give hint to user in case of typo in template name
        List<String> existingTemplates = new ArrayList<>();
        fine("Checking report templates existence");
        for (Locale locale : Locale.values()) {
            // Get all templates for given locale
            List<String> templates = call(
                    () -> client.getReportsApi().apiReportsTemplatesGet(locale.getValue(), false),
                    "PT AI report templates list read failed")
                    .stream()
                    .map(ReportTemplateModel::getName)
                    .collect(Collectors.toList());
            existingTemplates.addAll(templates);
        }
        // Check if all the required report templates are present in list
        reports.getReport().stream()
                .map(Report::getTemplate)
                .forEach(t -> {
                    if (!existingTemplates.contains(t)) missingTemplates.add(t);
                });
        if (missingTemplates.isEmpty()) return;

        // Let's give user a hint about most similar template names. To do that
        // we will calculate cosine distance between each of existing templates
        // and user value
        for (String missing : missingTemplates) {
            List<ImmutablePair<Double, String>> distances = new ArrayList<>();
            for (String existing : existingTemplates)
                distances.add(new ImmutablePair<>(
                        new CosineDistance().apply(missing, existing),
                        existing));
            distances.sort(Comparator.comparing(Pair::getLeft));
            info(
                    "No '%s' template name found. Most similar existing template is '%s' [%s] with %.1f%% similarity",
                    missing, distances.get(0).getRight(), distances.get(0).getLeft(),
                    100 - distances.get(0).getLeft() * 100);
        }

        throw GenericException.raise(
                "Not all report templates are exist on server",
                new IllegalArgumentException("Missing reports are " + StringHelper.joinListGrammatically(missingTemplates)));
    }

    @Override
    public void check(@NonNull Report report) throws GenericException {
        // Check what templates defined in reports are missing on server
        // We will download all the templates for supported locales to give hint to user in case of typo in template name
        List<String> existingTemplates = new ArrayList<>();
        fine("Checking report templates existence");
        for (Locale locale : Locale.values()) {
            // Get all templates for given locale
            List<String> templates = call(
                    () -> client.getReportsApi().apiReportsTemplatesGet(locale.getValue(), false),
                    "PT AI report templates list read failed")
                    .stream()
                    .map(ReportTemplateModel::getName)
                    .collect(Collectors.toList());
            existingTemplates.addAll(templates);
            // Check if report template is present in list
            if (templates.contains(report.getTemplate())) return;
        }

        // Let's give user a hint about most similar template names. To do that
        // we will calculate cosine distance between each of existing templates
        // and user value
        List<Pair<Double, String>> distances = new ArrayList<>();
        for (String existing : existingTemplates)
            distances.add(new ImmutablePair<>(
                    new CosineDistance().apply(report.getTemplate(), existing), existing));
        distances.sort(Comparator.comparing(Pair::getLeft));
        info(
                "No '%s' template name found. Most similar existing template is '%s' with %.1f%% similarity",
                report.getTemplate(), distances.get(0).getRight(),
                100 - distances.get(0).getLeft() * 100);

        throw GenericException.raise(
                "Report template does not exist on server",
                new IllegalArgumentException("Missing template: " + report.getTemplate()));
    }

    @Override
    public void check(@NonNull RawData rawData) throws GenericException {}

    @Override
    public void check(@NonNull Sarif sarif) throws GenericException {}

    @Override
    public void check(Reports.@NonNull SonarGiif sonarGiif) throws GenericException {}

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
    public void exportAdvanced(@NonNull final UUID projectId, @NonNull final UUID scanResultId, @NonNull final Reports reports, @NonNull final FileOperations fileOps) throws GenericException {

        log.trace("Validate and check reports to be generated");
        final Reports checkedReports = ReportUtils.validate(reports);
        check(checkedReports);

        UUID dummyTemplate = getDummyReportTemplateId(Locale.EN);

        // final AtomicReference<UUID> finalProjectId = new AtomicReference<>(projectId);
        List<Object> allReports = new ArrayList<>();
        allReports.addAll(checkedReports.getReport());
        allReports.addAll(checkedReports.getRaw());
        allReports.addAll(checkedReports.getSarif());
        allReports.addAll(checkedReports.getSonarGiif());
        for (Object item : allReports) {
            try {
                if (item instanceof Report) {
                    Report report = (Report) item;
                    exportReport(projectId, scanResultId, report, fileOps);
                } else if (item instanceof RawData) {
                    RawData rawData = (RawData) item;
                    exportRawJson(projectId, scanResultId, rawData, fileOps);
                } else if (item instanceof Sarif) {
                    Sarif sarif = (Sarif) item;
                    exportSarif(projectId, scanResultId, sarif, fileOps);
                } else if (item instanceof SonarGiif) {
                    SonarGiif sonarGiif = (SonarGiif) item;
                    exportSonarGiif(projectId, scanResultId, sonarGiif, fileOps);
                }
            } catch (GenericException e) {
                warning(e);
            }
        }
    }

    @Override
    public void exportReport(@NonNull UUID projectId, @NonNull UUID scanResultId, @NonNull Report report, @NonNull FileOperations fileOps) throws GenericException {
        fine("Started: HTML report generation for project id: %s, scan result id: %s, template: %s", projectId, scanResultId, report.getTemplate());

        log.trace("Load all report templates to find one with {} name", report.getTemplate());

        ReportTemplateModel templateModel = null;
        Locale templateLocale = null;

        for (Locale locale : Locale.values()) {
            List<ReportTemplateModel> templates = call(
                    () -> client.getReportsApi().apiReportsTemplatesGet(locale.getValue(), false),
                    "PT AI report templates list read failed");
            templateModel = templates.stream().filter(t -> report.getTemplate().equalsIgnoreCase(t.getName())).findAny().orElse(null);
            if (null == templateModel || null == templateModel.getId()) continue;
            templateLocale = locale;
            log.trace("Template {} found, id is {}, locale {}", report.getTemplate(), templateModel.getId(), locale);
            break;
        }
        if (null == templateModel || null == templateLocale)
            throw GenericException.raise("Report generation failed", new IllegalArgumentException("PT AI template " + report.getTemplate() + " not found"));

        log.trace("Create report generation model and apply filters");
        ReportGenerateModel model = new ReportGenerateModel()
                .parameters(new UserReportParametersModel()
                        .includeDFD(report.isIncludeDfd())
                        .includeGlossary(report.isIncludeGlossary())
                        // TODO: there's no report filters support in 4.2
                        // .useFilters(null != report.getFilters())
                        .formatType(ReportFormatType.CUSTOM)
                        .reportTemplateId(templateModel.getId()))
                .scanResultId(scanResultId)
                .projectId(projectId)
                .localeId(templateLocale.getValue());
        // TODO: there's no report filters support in 4.2
        // if (null != report.getFilters()) model.setFilters(ReportsConverter.convert(report.getFilters()));
        log.trace("Call report generation API");
        File file = call(
                () -> client.getReportsApi().apiReportsGeneratePost(model),
                "Report generation failed");
        log.trace("Report saved to temp file {}", file.toPath());
        call(
                () -> fileOps.saveArtifact(report.getFileName(), file),
                "Report file save failed");
        log.debug("Deleting temp file {}", file.getAbsolutePath());
        call(file::delete, "Temporal file " + file.getAbsolutePath() + " delete failed", true);
        fine("Finished: HTML report generation for project id: %s, scan result id: %s, template: %s", projectId, scanResultId, report.getTemplate());
    }

    @Override
    public void exportRawJson(@NonNull UUID projectId, @NonNull UUID scanResultId, @NonNull RawData rawData, @NonNull FileOperations fileOps) throws GenericException {
        fine("Started: raw JSON data export for project id: %s, scan result id: %s", projectId, scanResultId);
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
        fine("Finished: raw JSON data export for project id: %s, scan result id: %s", projectId, scanResultId);
    }

    @Override
    public void exportSarif(@NonNull UUID projectId, @NonNull UUID scanResultId, @NonNull Sarif sarif, @NonNull FileOperations fileOps) throws GenericException {
        fine("Started: SARIF report generation for project id: %s, scan result id: %s", projectId, scanResultId);

        GenericAstTasks genericAstTasks = new Factory().genericAstTasks(client);
        ScanResult scanResult = genericAstTasks.getScanResult(projectId, scanResultId);
        ScanResultHelper.apply(scanResult, sarif.getFilters());

        SarifSchema210 sarifSchema = com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.subjobs.export.Sarif.convert(scanResult, true);
        try (TempFile temporalReportFile = TempFile.createFile()) {
            CallHelper.call(
                    () -> BaseJsonHelper.createObjectMapper().writerWithDefaultPrettyPrinter().writeValue(temporalReportFile.toFile(), sarifSchema),
                    "SARIF report serialization failed");
            call(() -> fileOps.saveArtifact(sarif.getFileName(), temporalReportFile.toFile()), "SARIF report save failed");
        }
        fine("Finished: SARIF report generation for project id: %s, scan result id: %s", projectId, scanResultId);
    }

    @Override
    public void exportSonarGiif(@NonNull UUID projectId, @NonNull UUID scanResultId, @NonNull SonarGiif sonarGiif, @NonNull FileOperations fileOps) throws GenericException {
        fine("Started: SonarQube GIIF report generation for project id: %s, scan result id: %s", projectId, scanResultId);

        GenericAstTasks genericAstTasks = new Factory().genericAstTasks(client);
        ScanResult scanResult = genericAstTasks.getScanResult(projectId, scanResultId);
        ScanResultHelper.apply(scanResult, sonarGiif.getFilters());

        SonarGiifReport giifReport = com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.subjobs.export.SonarGiif.convert(scanResult);
        try (TempFile temporalReportFile = TempFile.createFile()) {
            CallHelper.call(
                    () -> BaseJsonHelper.createObjectMapper().writerWithDefaultPrettyPrinter().writeValue(temporalReportFile.toFile(), giifReport),
                    "SonarQube GIIF report serialization failed");
            call(() -> fileOps.saveArtifact(sonarGiif.getFileName(), temporalReportFile.toFile()), "SonarQube GIIF report save failed");
        }
        fine("Finished: SonarQube GIIF report generation for project id: %s, scan result id: %s", projectId, scanResultId);
    }

    protected UUID getDummyReportTemplateId(@NonNull Locale locale) throws GenericException {
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
    public List<String> listReportTemplates(Locale locale)  throws GenericException {
        List<ReportTemplateModel> reportTemplateModels = call(
                () -> client.getReportsApi().apiReportsTemplatesGet(locale.getValue(), false),
                "PT AI report templates list read failed");
        return reportTemplateModels.stream().map(ReportTemplateModel::getName).collect(Collectors.toList());
    }
}
