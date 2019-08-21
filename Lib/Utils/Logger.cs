﻿// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using Serilog;
using Serilog.Events;

namespace AttackSurfaceAnalyzer.Utils
{
    public class Logger
    {

        public static void Setup()
        {
            Setup(false, false);
        }

        public static void Setup(bool debug, bool verbose)
        {
            if (verbose)
            {
                Log.Logger = new LoggerConfiguration()
                    .MinimumLevel.Verbose()
                    .WriteTo.File("asa.log.txt")
                    .WriteTo.Console()
                    .CreateLogger();
            }
            else if (debug)
            {
                Log.Logger = new LoggerConfiguration()
                    .MinimumLevel.Debug()
                    .WriteTo.File("asa.log.txt")
                    .WriteTo.Console()
                    .CreateLogger();
            }
            else
            {
                Log.Logger = new LoggerConfiguration()
                        .MinimumLevel.Debug()
                        .WriteTo.File("asa.log.txt")
                        .WriteTo.Console(restrictedToMinimumLevel: LogEventLevel.Information)
                        .CreateLogger();
            }
        }

        public static void DebugException(Exception e)
        {
            Log.Debug("{0} {1} {2}", e.GetType().ToString(), e.Message, e.StackTrace);
        }
    }
}