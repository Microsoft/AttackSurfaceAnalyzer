﻿// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using NLog;
using NLog.Config;
using NLog.Targets;

namespace AttackSurfaceAnalyzer.Utils
{
    public class Logger
    {

        public static ILogger Instance { get; private set; }

        static Logger()
        {
            Instance = LogManager.GetCurrentClassLogger();
        }

        public static void Setup()
        {
            Setup(false, false);
        }

        public static void Setup(bool debug, bool verbose)
        {
            // Step 1. Create configuration object 
            var config = new LoggingConfiguration();

            // Step 2. Create targets
            var consoleTarget = new ColoredConsoleTarget("console")
            {
                Layout = @"${date:format=HH\:mm\:ss} ${level} ${message} ${exception}"
            };
            config.AddTarget(consoleTarget);

            var fileTarget = new FileTarget("debug")
            {
                FileName = "asa.debug.log",
                Layout = "${longdate} ${level} ${message}  ${exception}"
            };
            config.AddTarget(fileTarget);

            if (debug)
            {
                config.AddRuleForOneLevel(LogLevel.Debug, fileTarget); 
                config.AddRuleForOneLevel(LogLevel.Warn, consoleTarget);
                config.AddRuleForOneLevel(LogLevel.Error, consoleTarget);
                config.AddRuleForOneLevel(LogLevel.Fatal, consoleTarget);
            }

            if (verbose)
            {
                config.AddRuleForAllLevels(consoleTarget);
            }
            else
            {
                config.AddRuleForOneLevel(LogLevel.Info, consoleTarget);
                config.AddRuleForOneLevel(LogLevel.Warn, consoleTarget);
                config.AddRuleForOneLevel(LogLevel.Error, consoleTarget);
                config.AddRuleForOneLevel(LogLevel.Fatal, consoleTarget);
            }

            // Step 4. Activate the configuration
            LogManager.Configuration = config;
        }

    }
}