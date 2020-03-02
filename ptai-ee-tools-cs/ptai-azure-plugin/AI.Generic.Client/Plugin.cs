using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace AI.Generic.Client {
    public class Plugin {
        protected bool useRemotePtaiService;
        protected String url = "";
        protected String login = "";
        protected String password = "";
        protected String ca = "";
        protected String agent = "";
        protected String includes;
        protected String excludes;
        protected String removePrefix;
        protected bool usePredefinedExcludes;
        protected bool flatten;

        protected String project;
        protected String jsonSettings;
        protected String jsonPolicy;
        protected String sourceFolder;
        protected String tempFolder;
        protected String stagingFolder;


        protected const String separator = @"[, ]+";
        public Plugin(
            String useRemotePtaiService, 
            String url, String login, String password, String ca,
            String agent, String includes, String excludes, 
            String removePrefix, String usePredefinedExcludes, String flatten,
            String project, String jsonSettings, String jsonPolicy,
            String sourceFolder, String tempFolder, String stagingFolder) {
            this.useRemotePtaiService = "true".Equals(useRemotePtaiService, StringComparison.OrdinalIgnoreCase);
            this.url = url;
            this.login = login;
            this.password = password;
            this.ca = ca;
            this.agent = agent;
            this.includes = includes;
            this.excludes = excludes;
            this.removePrefix = removePrefix;
            this.usePredefinedExcludes = "true".Equals(usePredefinedExcludes, StringComparison.OrdinalIgnoreCase);
            this.flatten = "true".Equals(flatten, StringComparison.OrdinalIgnoreCase);
            this.project = project;
            this.jsonSettings = jsonSettings;
            this.jsonPolicy = jsonPolicy;
            this.sourceFolder = sourceFolder;
            this.tempFolder = tempFolder;
            this.stagingFolder = stagingFolder;
        }
        public int scan() {
            Console.WriteLine("Console.WriteLine");
            Console.Out.WriteLine("Console.Out.WriteLine");

            return useRemotePtaiService
                ? remoteScan()
                : localScan();
        }
        public int localScan() {
            int res = 1000;
            // Find aic.exe
            String aic = null;
            for (Char drive = 'C'; drive <= 'Z'; drive++) {
                if (!File.Exists(drive + @":\Program Files (x86)\Positive Technologies\Application Inspector Agent\aic.exe")) continue;
                aic = drive + @":\Program Files (x86)\Positive Technologies\Application Inspector Agent\aic.exe";
                break;
            }
            if (null == aic) {
                Console.Error.WriteLine("Couldn't find aic.exe, exiting");
                return res;
            }
            // Aic.exe scans all the sources in the folder so the only way to restrict is to copy files to temporary folder and scan there
            String tempSources = Path.Combine(tempFolder, Guid.NewGuid().ToString());
            Directory.CreateDirectory(tempSources);
            FileUtils.copy(sourceFolder, tempSources,
                Regex.Split(includes ?? "", separator),
                Regex.Split(excludes ?? "", separator),
                usePredefinedExcludes, removePrefix ?? "", flatten);
            // Setup CLI for aic.exe
            String aicParams = "";
            if (!String.IsNullOrEmpty(jsonSettings)) {
                File.WriteAllText(tempFolder + Path.DirectorySeparatorChar + "settings.aiproj", jsonSettings);
                aicParams += $" --project-settings-file \"{tempFolder + Path.DirectorySeparatorChar + "settings.aiproj"}\"";
            }
            if (!String.IsNullOrEmpty(jsonPolicy)) {
                File.WriteAllText(tempFolder + Path.DirectorySeparatorChar + "policy.json", jsonPolicy);
                aicParams += $" --policies-path \"{tempFolder + Path.DirectorySeparatorChar + "policy.json"}\"";
            }
            if (!String.IsNullOrEmpty(project))
                aicParams += $" --project-name \"{project}\"";
            aicParams += $" --scan-target \"{tempSources}\" --reports \"JSON | HTML\"";
            aicParams += $" --reports-folder \"{stagingFolder + Path.DirectorySeparatorChar + ".ptai"}\" --sync";
            res = new ExeWrapper(aic, aicParams).Execute();
            Directory.Delete(tempSources, true);
            return res;
        }
        public int remoteScan() {
            int res = 1000;
            String zipFile = Path.Combine(tempFolder, Guid.NewGuid().ToString());
            Directory.CreateDirectory(Path.GetDirectoryName(zipFile));
            FileUtils.zip(
                sourceFolder, zipFile,
                Regex.Split(includes ?? "", separator),
                Regex.Split(excludes ?? "", separator),
                usePredefinedExcludes, removePrefix ?? "", flatten);
            Client client = new Client(this.url);
            client.init(login, password, ca);
            res = client.scan(project, zipFile, agent, stagingFolder);
            File.Delete(zipFile);
            return res;
        }
    }
}
