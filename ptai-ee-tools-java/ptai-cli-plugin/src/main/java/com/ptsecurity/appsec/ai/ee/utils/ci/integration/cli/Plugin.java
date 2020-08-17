package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.commands.LegacyUiAst;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.commands.SlimJsonAst;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.commands.SlimServerCheck;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.commands.SlimUiAst;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.commands.admin.ServiceConfigure;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.commands.admin.UserCreate;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.commands.admin.UserDelete;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.commands.admin.UserList;
import org.fusesource.jansi.AnsiConsole;
import picocli.CommandLine;
import picocli.CommandLine.Command;

import java.util.Comparator;

@Command (name = "java -jar ptai-cli-plugin.jar", synopsisSubcommandLabel = "COMMAND",
        mixinStandardHelpOptions = true, version = "ptai-cli-plugin v.0.1",
        subcommands = {
                SlimUiAst.class, SlimJsonAst.class, SlimServerCheck.class,
                LegacyUiAst.class,
                UserCreate.class, UserList.class, UserDelete.class,
                ServiceConfigure.class })
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
        CommandLine commandLine = new CommandLine(new Plugin());
        // Default synopsys usage printed using createShortOptionArityAndNameComparator
        // That means that even if we've sorted options using order attribute, in the synopsis
        // those will be ordered differently. Let's fix that
        commandLine.setHelpFactory(new CommandLine.IHelpFactory() {
            @Override
            public CommandLine.Help create(CommandLine.Model.CommandSpec commandSpec, CommandLine.Help.ColorScheme colorScheme) {
                return new CommandLine.Help(commandSpec, colorScheme) {
                    private boolean empty(Object[] array) { return array == null || array.length == 0; }

                    @Override
                    public String synopsis(int synopsisHeadingLength) {
                        if (!empty(commandSpec.usageMessage().customSynopsis())) { return customSynopsis(); }
                        return commandSpec.usageMessage().abbreviateSynopsis() ? abbreviatedSynopsis()
                                : detailedSynopsis(synopsisHeadingLength, /* createShortOptionArityAndNameComparator()*/ new SortByOrder<CommandLine.Model.OptionSpec>(), true);
                    }
                };
            }
        });
        int exitCode = commandLine.execute(args);
        // that ignores order, so we need to redefine that
        AnsiConsole.systemUninstall(); // cleanup when done
        System.exit(exitCode);
    }

    static class SortByOrder<T extends CommandLine.Model.IOrdered> implements Comparator<T> {
        public int compare(T o1, T o2) {
            return Integer.signum(o1.order() - o2.order());
        }
    }
}
