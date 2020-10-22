package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.utils.FileCollector;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.utils.StringHelper;
import org.apache.tools.ant.DirectoryScanner;

import java.util.Arrays;
import java.util.List;

/**
 * Class contains constants that are used as a hints in UI
 */
public class Hints {
    public static final String RUNNER = "PT AI AST scan";

    public static final String URL =
            "PT AI server URL. By default, PT AI server using secure port 8443." +
                    "<br>" +
                    "For example: https://ptai.domain.org:8443";
    public static final String TOKEN = "PT AI API token to use";
    public static final String CERTIFICATES =
            "PEM-encoded PT AI server CA certificate chain." +
                    "<br>" +
                    "You may keep this field empty if PT AI server certificates are " +
                    "issued by CA from your JDK&nbsp;truststore";

    public static final String SERVER_SETTINGS = "Choose how PT AI server connection settings are defined";
    public static final String SERVER_SETTINGS_GLOBAL = "Global scope defined PT AI server config";
    public static final String SERVER_SETTINIGS_LOCAL = "Task scope defined PT AI server config";

    public static final String AST_SETTINGS = "Choose how AST settings are defined";
    public static final String AST_SETTINGS_JSON = "JSON-defined settings";
    public static final String AST_SETTINGS_UI = "PT AI viewer-defined settings";

    public static final String PROJECT_NAME = "Project name as it defined in PT AI Viewer UI";
    public static final String JSON_SETTINGS = "Scan settings in JSON format";
    public static final String JSON_POLICY =
            "Project SAST policy in JSON format." +
                    "<br>" +
                    "If this parameter is empty then SAST policy will be downloaded from PT AI EE server." +
                    "<br>" +
                    "If you need to scan project without policy use [] value";

    public static final String FAIL_IF_FAILED = "Mark build step as failed if AST policy assessment failed";
    public static final String FAIL_IF_UNSTABLE = "Mark build step as failed if AST policy assessment success but there were some minor warnings reported";
    public static final String NODE_NAME = "AST agent node name";
    public static final String VERBOSE = "Show verbose log output";
    public static final String INCLUDES =
            "Files to scan for vulnerabilities. The string is a comma separated " +
                    "list of includes for an Ant fileset eg. '**/*.jar' " +
                    "(see <a href=\"http://ant.apache.org/manual/dirtasks.html#patterns\">Patterns</a> " +
                    "in the Ant manual). The base directory for this fileset is the workspace";
    public static final String REMOVE_PREFIX = "First part of the file path that should not be created on the remote server";
    public static final String EXCLUDES =
            "Exclude files from the Transfer set. The string is a comma separated " +
                    "list of excludes for an Ant fileset eg. '**/*.log, **/*.tmp, .git/' " +
                    "(see <a href=\"http://ant.apache.org/manual/dirtasks.html#patterns\">Patterns</a> " +
                    "in the Ant manual)";
    public static final String PATTERN_SEPARATOR = "The regular expression that is used to separate the Source files and Exclude files patterns";
    public static final String USE_DEFAULT_EXCLUDES =
            "Select this option to disable the default exclude patterns (" +
                    StringHelper.joinListGrammatically(Arrays.asList(FileCollector.defaultExcludes())) +
                    ")";
    public static final String FLATTEN = "Only transfer files, ignore folder structure";
}
