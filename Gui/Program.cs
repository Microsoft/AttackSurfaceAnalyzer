﻿// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using ElectronNET.API;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Hosting;

namespace AttackSurfaceAnalyzer.Gui
{
    public class Program
    {
        public static void Main(string[] args)
        {
            CreateWebHostBuilder(args).Build().Run();
        }

        public static IWebHostBuilder CreateWebHostBuilder(string[] args) =>
            WebHost.CreateDefaultBuilder(args)
                .UseApplicationInsights()
                .UseElectron(args)
                .UseStartup<Startup>();
    }
}