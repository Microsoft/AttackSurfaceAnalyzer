// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using CommandLine;
using Microsoft.CST.AttackSurfaceAnalyzer.Objects;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Microsoft.CST.AttackSurfaceAnalyzer.Types;

namespace Microsoft.CST.AttackSurfaceAnalyzer
{
    [Verb("collect", HelpText = "Collect operating system metrics")]
    public class CollectCommandOptions : CollectorOptions
    {
        [Option("match-run-id", Required = false, HelpText = "Match the collectors used on another run id")]
        public string? MatchedCollectorId { get; set; }

        public static CollectCommandOptions FromCollectorOptions(CollectorOptions opts)
        {
            if (opts == null) throw new ArgumentNullException(nameof(opts));
            return new CollectCommandOptions()
            {
                CrawlArchives = opts.CrawlArchives,
                DatabaseFilename = opts.DatabaseFilename,
                Debug = opts.Debug,
                DownloadCloud = opts.DownloadCloud,
                EnableAllCollectors = opts.EnableAllCollectors,
                EnableCertificateCollector = opts.EnableCertificateCollector,
                EnableComObjectCollector = opts.EnableComObjectCollector,
                EnableDriverCollector = opts.EnableDriverCollector,
                EnableEventLogCollector = opts.EnableEventLogCollector,
                EnableFileSystemCollector = opts.EnableFileSystemCollector,
                EnableFirewallCollector = opts.EnableFirewallCollector,
                EnableKeyCollector = opts.EnableKeyCollector,
                EnableNetworkPortCollector = opts.EnableNetworkPortCollector,
                EnableProcessCollector = opts.EnableProcessCollector,
                EnableRegistryCollector = opts.EnableRegistryCollector,
                EnableServiceCollector = opts.EnableServiceCollector,
                EnableTpmCollector = opts.EnableTpmCollector,
                EnableUserCollector = opts.EnableUserCollector,
                EnableWifiCollector = opts.EnableWifiCollector,
                GatherHashes = opts.GatherHashes,
                GatherVerboseLogs = opts.GatherVerboseLogs,
                GatherWifiPasswords = opts.GatherWifiPasswords,
                Overwrite = opts.Overwrite,
                Quiet = opts.Quiet,
                RunId = opts.RunId,
                SelectedDirectories = opts.SelectedDirectories,
                SelectedHives = opts.SelectedHives,
                SingleThread = opts.SingleThread,
                Verbose = opts.Verbose
            };
        }
    }

    public class CollectorOptions : CommandOptions
    {
        [Option("crawl-archives", Required = false, HelpText = "Attempts to crawl every archive file encountered when using File Collector.  May dramatically increase run time of the scan.")]
        public bool CrawlArchives { get; set; }

        [Option(HelpText = "Download files from thin Cloud Folders (like OneDrive) to check them.")]
        public bool DownloadCloud { get; set; }

        [Option('a', "all", Required = false, HelpText = "Enable all collectors")]
        public bool EnableAllCollectors { get; set; }

        [Option('c', "certificates", Required = false, HelpText = "Enable the certificate store collector")]
        public bool EnableCertificateCollector { get; set; }

        [Option('C', "com", Required = false, HelpText = "Enable the COM object collector")]
        public bool EnableComObjectCollector { get; set; }

        [Option('d', "driver", Required = false, HelpText = "Enable the driver collector")]
        public bool EnableDriverCollector { get; set; }

        [Option('l', "logs", Required = false, HelpText = "Enable the Log collector")]
        public bool EnableEventLogCollector { get; set; }

        [Option('f', "file-system", Required = false, HelpText = "Enable the file system collector")]
        public bool EnableFileSystemCollector { get; set; }

        [Option('F', "firewall", Required = false, HelpText = "Enable the firewall collector")]
        public bool EnableFirewallCollector { get; set; }

        [Option('k', "keys", Required = false, HelpText = "Gather information about the cryptographic keys on the system.")]
        public bool EnableKeyCollector { get; set; }

        [Option('p', "network-port", Required = false, HelpText = "Enable the network port collector")]
        public bool EnableNetworkPortCollector { get; set; }

        [Option('P', "process", Required = false, HelpText = "Enable the process information collector")]
        public bool EnableProcessCollector { get; set; }

        [Option('r', "registry", Required = false, HelpText = "Enable the registry collector")]
        public bool EnableRegistryCollector { get; set; }

        [Option('s', "service", Required = false, HelpText = "Enable the service collector")]
        public bool EnableServiceCollector { get; set; }

        [Option('t', "tpm", Required = false, HelpText = "Gather information about the TPM")]
        public bool EnableTpmCollector { get; set; }

        [Option('u', "user", Required = false, HelpText = "Enable the user and group account collector")]
        public bool EnableUserCollector { get; set; }

        [Option('w', "wifi", Required = false, HelpText = "Enable the saved Wifi information collector")]
        public bool EnableWifiCollector { get; set; }

        [Option('h', "gather-hashes", Required = false, HelpText = "Hashes every file when using the File Collector.  May dramatically increase run time of the scan.")]
        public bool GatherHashes { get; set; }

        [Option(HelpText = "Gather all levels in the Log collector. (Default: Only gather Error and Warning when possible.)")]
        public bool GatherVerboseLogs { get; set; }

        [Option(HelpText = "Gather passwords when gathering wifi networks.")]
        public bool GatherWifiPasswords { get; set; }

        [Option(HelpText = "If the specified runid already exists delete all data from that run before proceeding.")]
        public bool Overwrite { get; set; }

        [Option(HelpText = "Identifies which run this is.")]
        public string? RunId { get; set; }

        [Option("directories", Required = false, HelpText = "comma separated list of paths to scan with FileSystemCollector", Separator = ',')]
        public IEnumerable<string> SelectedDirectories { get; set; } = new List<string>();

        [Option("skip-directories", Required = false, HelpText = "comma separated list of paths to skip with FileSystemCollector", Separator = ',')]
        public IEnumerable<string> SkipDirectories { get; set; } = new List<string>();

        [Option("hives", Required = false, HelpText = "comma separated list of hives and subkeys to search.", Separator = ',')]
        public IEnumerable<string> SelectedHives { get; set; } = new List<string>();

        [Option(HelpText = "Force singlethreaded collectors.")]
        public bool SingleThread { get; set; }
    }

    public class CommandOptions
    {
        [Option(Required = false, HelpText = "Name of output database (default: asa.sqlite)", Default = "asa.sqlite")]
        public string DatabaseFilename { get; set; } = "asa.sqlite";

        [Option(HelpText = "Show debug logging statements.")]
        public bool Debug { get; set; }

        [Option(HelpText = "Lower memory usage in database. (May reduce performance.)")]
        public bool LowMemoryUsage { get; set; }

        [Option(Default = false, HelpText = "Decrease logging to Errors")]
        public bool Quiet { get; set; }

        [Option(HelpText = "Number of Database Shards to use.")]
        public int Shards { get; set; } = 7;

        [Option(Default = false, HelpText = "Increase logging verbosity")]
        public bool Verbose { get; set; }
    }

    public class CompareCommandOptions : CommandOptions
    {
        public CompareCommandOptions(string? FirstRunId, string SecondRunId)
        {
            this.FirstRunId = FirstRunId;
            this.SecondRunId = SecondRunId;
        }

        [Option(HelpText = "Custom analysis rules file.")]
        public RuleFile? AnalysesFile { get; set; }

        [Option(HelpText = "When analyzing Monitor Objects apply rules that would apply to the base type.")]
        public bool ApplySubObjectRulesToMonitor { get; set; }

        [Option(HelpText = "Set Disable Analysis.")]
        public bool DisableAnalysis { get; set; }

        [Option(HelpText = "First run (pre-install) identifier")]
        public string? FirstRunId { get; set; }

        [Option(HelpText = "Save to internal database for review in GUI")]
        public bool SaveToDatabase { get; set; }

        [Option(HelpText = "Second run (post-install) identifier")]
        public string SecondRunId { get; set; }

        [Option(HelpText = "Run Scripts")]
        public bool RunScripts { get; set; }

        [Option(HelpText = "Force Analysis to be Single-Threaded")]
        public bool SingleThreadAnalysis { get; set; }
    }

    [Verb("config", HelpText = "Configure and query the database")]
    public class ConfigCommandOptions : CommandOptions
    {
        [Option("delete-run", Required = false, HelpText = "Delete a specific run from the database")]
        public string? DeleteRunId { get; set; }

        [Option("list-runs", Required = false, HelpText = "List runs in the database")]
        public bool ListRuns { get; set; }

        [Option("reset-database", Required = false, HelpText = "Delete the output database")]
        public bool ResetDatabase { get; set; }

        [Option("trim-to-latest", HelpText = "Delete all runs except the latest.")]
        public bool TrimToLatest { get; set; }
    }

    [Verb("export-collect", HelpText = "Compare ASA executions and output a .json report")]
    public class ExportCollectCommandOptions : ExportOptions
    {
        [Option(HelpText = "Export single run. (Specify runid with SecondRunId.)")]
        public bool ExportSingleRun { get; set; }

        [Option(HelpText = "First run (pre-install) identifier")]
        public string? FirstRunId { get; set; }

        [Option(HelpText = "Second run (post-install) identifier")]
        public string SecondRunId { get; set; } = string.Empty;
        
        [Option(HelpText = "Checks if the results of this analysis are already saved in the database. If they are will export the cached data instead of performing new analysis.")]
        public bool ReadFromSavedComparisons { get; set; }
    }

    [Verb("export-monitor", HelpText = "Output a .json report for a monitor run")]
    public class ExportMonitorCommandOptions : ExportOptions
    {
        [Option(HelpText = "Apply rules for FileTypes contained in Monitor objects to those objects. (For example, FILE rules against FILE_MONITOR objects internal File object)")]
        public bool ApplySubObjectRulesToMonitor { get; set; }

        [Option(HelpText = "Monitor run identifier")]
        public string? RunId { get; set; }
    }

    [Verb("export-guided", HelpText = "Output a .json for a guided run")]
    public class ExportGuidedCommandOptions : ExportMonitorCommandOptions
    {
    }

    public class ExportOptions : CommandOptions
    {
        [Option("filename", HelpText = "Custom analysis rules file.")]
        public string? AnalysesFile { get; set; }

        [Option(HelpText = "Set to Disable Analysis.")]
        public bool DisableAnalysis { get; set; }

        [Option(HelpText = "Output Each Result Type in a Separate File")]
        public bool ExplodedOutput { get; set; }

        [Option(HelpText = "Directory to output to")]
        public string? OutputPath { get; set; }

        [Option(HelpText = "Save to internal database for review in GUI")]
        public bool SaveToDatabase { get; set; }

        [Option(HelpText = "Enable running Scripts in rules")]
        public bool RunScripts { get; set; }

        [Option(HelpText = "Output Sarif")]
        public bool OutputSarif { get; set; }

        // Don't output results if they do not have an explicit rule applied
        [Option(HelpText = "Ignore results with no explicit rule match")]
        public bool DisableImplicitFindings { get; set; }

        [Option(HelpText = "Force Analysis to be Single-Threaded")]
        public bool SingleThreadAnalysis { get; set; }

        [Option(HelpText = "Specify the ResultLevels to report", Separator = ',')]
        public IEnumerable<ANALYSIS_RESULT_TYPE> ResultLevels { get; set; } = new List<ANALYSIS_RESULT_TYPE>();
    }

    [Verb("gui", HelpText = "Launch the GUI in a browser.")]
    public class GuiCommandOptions : CommandOptions
    {
        [Option(HelpText = "Disable launching a browser after gui starts.")]
        public bool NoLaunch { get; set; }

        [Option(HelpText = "Port to listen on.", Default = 5000)]
        public int Port { get; set; } = 5000;
    }

    [Verb("guide", HelpText = "Gather and Analyze metrics using a combination of Collectors and Monitors.")]
    public class GuidedModeCommandOptions : CollectorOptions
    {
        // These are from ExportCollectCommandOptions
        [Option(HelpText = "Custom analysis rules file.")]
        public string? AnalysesFile { get; set; }

        [Option(HelpText = "Apply Rules to SubCollect objects of Monitor objects.")]
        public bool ApplySubObjectRulesToMonitor { get; set; }

        [Option(HelpText = "Set Disable Analysis.")]
        public bool DisableAnalysis { get; set; }

        // These are from MonitorCommandOptions
        [Option("duration", Required = false, HelpText = "Duration, in minutes, to run for before automatically terminating.")]
        public int Duration { get; set; }

        [Option('m', "file-system-monitor", Required = false, HelpText = "Enable the file system monitor. Unless -d is specified will monitor the entire file system.")]
        public bool EnableFileSystemMonitor { get; set; }

        [Option(HelpText = "Put each result type in its own document.")]
        public bool ExplodedOutput { get; set; }

        [Option(HelpText = "Don't gather extended information when monitoring files.")]
        public bool FileNamesOnly { get; set; }

        [Option(HelpText = "Comma-separated list of directories to monitor.", Separator = ',')]
        public IEnumerable<string> MonitoredDirectories { get; set; } = new List<string>();

        [Option(HelpText = "Directory to output to.")]
        public string? OutputPath { get; set; }

        [Option(HelpText = "Save to internal database for review in GUI")]
        public bool SaveToDatabase { get; set; }

        [Option(HelpText = "Run Scripts")]
        public bool RunScripts { get; set; }

        [Option(HelpText = "Export Sarif")]
        public bool ExportSarif { get; set; }

        [Option(HelpText = "Force Analysis to be Single-Threaded")]
        public bool SingleThreadAnalysis { get; set; }
    }

    [Verb("monitor", HelpText = "Continue running and monitor activity")]
    public class MonitorCommandOptions : CommandOptions
    {
        [Option('D', "duration", Required = false, HelpText = "Duration, in minutes, to run for before automatically terminating.")]
        public int Duration { get; set; }

        [Option('F', "file-system-monitor", Required = false, HelpText = "Enable the file system monitor. Unless -d is specified will monitor the entire file system.")]
        public bool EnableFileSystemMonitor { get; set; }

        [Option('a', "File names only", Required = false, HelpText = "Don't gather extended information. Overrides any argument to include additional data.")]
        public bool FileNamesOnly { get; set; }

        [Option('h', "gather-hashes", Required = false, HelpText = "Gather a hash of each file that is modified or created.")]
        public bool GatherHashes { get; set; }

        [Option('d', "directories", Required = false, HelpText = "Comma-separated list of directories to monitor.", Separator = ',')]
        public IEnumerable<string> MonitoredDirectories { get; set; } = new List<string>();

        //[Option('r', "registry", Required = false, HelpText = "Monitor the registry for changes. (Windows Only)")]
        //public bool EnableRegistryMonitor { get; set; }
        [Option(Default = false, HelpText = "If the specified runid already exists delete all data from that run before proceeding.")]
        public bool Overwrite { get; set; }

        [Option(HelpText = "Identifies which run this is. Monitor output can be combined with collect output, but doesn't need to be compared.", Default = "Timestamp")]
        public string? RunId { get; set; }

        [Option(HelpText =
            "Specify which NotifyFilters to use for file monitoring, comma separated if provided via cli.", Separator = ',')]
        public IEnumerable<NotifyFilters> Filters { get; set; } = Enumerable.Empty<NotifyFilters>();
    }

    [Verb("verify", HelpText = "Verify your analysis rules")]
    public class VerifyOptions : CommandOptions
    {
        [Option("filename", Required = false, HelpText = "Path to your rule file (leave blank to test the embedded rules)")]
        public string? AnalysisFile { get; set; }

        [Option(HelpText = "Run Scripts in Rules")]
        public bool RunScripts { get; set; }
    }
}