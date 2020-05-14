package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.commands.LegacyUiAst;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.commands.SlimJsonAst;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.commands.SlimServerCheck;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.commands.SlimUiAst;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.commands.admin.UserAdd;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.commands.admin.UserDelete;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.commands.admin.UserList;
import org.fusesource.jansi.AnsiConsole;
import picocli.CommandLine;
import picocli.CommandLine.Command;

@Command (name = "java -jar ptai-cli-plugin.jar", synopsisSubcommandLabel = "COMMAND",
        mixinStandardHelpOptions = true, version = "ptai-cli-plugin v.0.1",
        subcommands = {
                SlimUiAst.class, SlimJsonAst.class, SlimServerCheck.class,
                LegacyUiAst.class,
                UserAdd.class, UserList.class, UserDelete.class})
public class Plugin implements Runnable {
    @CommandLine.Spec
    CommandLine.Model.CommandSpec spec;
    public void run() {
        throw new CommandLine.ParameterException(spec.commandLine(), "Missing required subcommand");
    }

    public static final String CLIENT_ID = "ptai-cli-plugin";
    public static final String CLIENT_SECRET = "ir5qWH61Pvr2FG54aC3YSeq0TGCoudod";

    public static void main(String... args) {
        AnsiConsole.systemInstall(); // enable colors on Windows
        int exitCode = new CommandLine(new Plugin()).execute(args);
        AnsiConsole.systemUninstall(); // cleanup when done
        System.exit(exitCode);
    }
}
