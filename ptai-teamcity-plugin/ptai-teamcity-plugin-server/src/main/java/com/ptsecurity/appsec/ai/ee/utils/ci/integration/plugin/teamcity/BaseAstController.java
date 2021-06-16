package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.service.AstSettingsService;
import jetbrains.buildServer.controllers.ActionErrors;
import jetbrains.buildServer.controllers.BaseFormXmlController;
import jetbrains.buildServer.controllers.XmlResponseUtil;
import lombok.NonNull;
import org.jdom.Element;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.List;
import java.util.stream.Collectors;

public class BaseAstController extends BaseFormXmlController {
    @Override
    protected ModelAndView doGet(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response) {
        return null;
    }

    @Override
    protected void doPost(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response, @NonNull Element xmlResponse) {

    }

    protected void saveVerificationResults(@NonNull final Element xml, @NonNull final AstSettingsService.VerificationResults results) {
        ActionErrors errors = new ActionErrors();
        results.stream().filter(p -> null != p.getLeft()).forEach(e -> errors.addError(e.getLeft(), e.getRight()));
        writeErrors(xml, errors);

        List<String> details = results.stream().map(p -> ((null == p.getLeft()) ? "[INFO] " : "[ERROR] ") + p.getRight()).collect(Collectors.toList());
        addDetails(xml, details);

        XmlResponseUtil.writeTestResult(xml, results.getResult());
    }

    /**
     * Method puts list of diagnostic messages into XML response
     * @param xml XML response where results are to be published
     * @param details List of diagnostic messages
     */
    private static void addDetails(
            @NonNull final Element xml,
            @NonNull final List<String> details) {
        Element detailsElement = xml.getChild("testConnectionDetails");
        if (null == detailsElement) {
            detailsElement = new Element("testConnectionDetails");
            xml.addContent(detailsElement);
        }
        for (String line : details) {
            final Element element = new Element("line");
            detailsElement.addContent(element);
            element.addContent(line);
        }
    }
}
