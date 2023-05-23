package com.ptsecurity.appsec.ai.ee.helpers.aiproj;

import com.jayway.jsonpath.Configuration;
import com.jayway.jsonpath.JsonPath;
import com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings;
import com.ptsecurity.appsec.ai.ee.scan.settings.aiproj.v11.Version;
import com.ptsecurity.appsec.ai.ee.scan.settings.v11.AiProjScanSettings;
import com.ptsecurity.misc.tools.exceptions.GenericException;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static java.lang.Boolean.TRUE;
import static org.apache.commons.lang3.StringUtils.isNotEmpty;

@Slf4j
public class AiProjHelper {
    @AllArgsConstructor
    @Getter
    public static class JavaParametersParseResult {
        protected String prefixes;
        protected String other;
    }

    /**
     * @param javaParameters Java CLI parameters that are passed to Java scanning core
     * @return CLI parameters split into two parts: {@link JavaParametersParseResult#prefixes user package prefixes}
     * and {@link JavaParametersParseResult#other remaining part of CLI}
     */
    public static JavaParametersParseResult parseJavaParameters(final String javaParameters) {
        if (StringUtils.isEmpty(javaParameters)) return null;
        log.trace("Split Java parameters string using 'quote-safe' regular expression");
        String[] parameters = javaParameters.split("(\"[^\"]*\")|(\\S+)");
        if (0 == parameters.length) return null;
        log.trace("Parse Java parameters");
        List<String> commands = new ArrayList<>();
        Map<String, List<String>> arguments = new HashMap<>();
        for (int i = 0 ; i < parameters.length ; i++) {
            log.trace("Iterate through commands");
            if (!parameters[i].startsWith("-")) continue;
            if (parameters.length - 1 == i)
                // If this is last token just add it as command
                commands.add(parameters[i]);
            else if (parameters[i + 1].startsWith("-"))
                // Next token is a command too
                commands.add(parameters[i]);
            else {
                List<String> argumentValues = new ArrayList<>();
                for (int j = i + 1; j < parameters.length; j++)
                    if (!parameters[j].startsWith("-")) argumentValues.add(parameters[j]); else break;
                arguments.put(parameters[i], argumentValues);
            }
        }
        String prefixes = "";
        StringBuilder commandBuilder = new StringBuilder();
        for (String cmd : commands) {
            if ("-upp".equals(cmd) || "--user-package=prefix".equals(cmd))
                if (arguments.containsKey(cmd) && 1 == arguments.get(cmd).size())
                    prefixes = arguments.get(cmd).get(0);
                else {
                    commandBuilder.append(cmd).append(" ");
                    if (arguments.containsKey(cmd))
                        commandBuilder.append(String.join(" ", arguments.get(cmd))).append(" ");
                }
        }
        return new JavaParametersParseResult(prefixes, commandBuilder.toString().trim());
    }

    /**
     * In PT AI v.4.1 solution file is to be defined as "./solution.sln" instead of "solution.sln"
     * @param solutionFile Initial solution file name
     * @return Fixed solution file name
     */
    public static String fixSolutionFile(final String solutionFile) {
        String res = solutionFile;
        // noinspection ConstantConditions
        do {
            if (StringUtils.isEmpty(solutionFile)) break;
            res = solutionFile.trim();
            if (solutionFile.startsWith("./")) break;
            log.trace("Fix solution file name {}", solutionFile);
            res = "./" + solutionFile;
            log.trace("Fixed solution file name is {}", solutionFile);
        } while (false);
        return res;
    }

    public static UnifiedAiProjScanSettings load(@NonNull final String data) throws GenericException {
        Object json = Configuration.defaultConfiguration().jsonProvider().parse(data);
        String version = JsonPath.read(json, "$.Version");
        if (isNotEmpty(version)) {
            log.trace("Detected AIPROJ version {}", version);
            if (Version._1_1.value().equals(version))
                return new AiProjScanSettings().load(data);
            else if (Version._1_0.value().equals(version)) {
                return null;
            } else
                throw GenericException.raise("AIPROJ parse failed", new IllegalArgumentException("Unsupported AIPROJ version " + version));
        } else if (null != JsonPath.read(json, "$.ScanModules")) {
            log.trace("Parse AIPROJ as v.1.0 as there's no version, but ScanModules are defined");
            return null;
        } else {
            log.trace("Parse legacy AIPROJ as there's no version and no ScanModules are defined");
            return null;
        }
    }
}
