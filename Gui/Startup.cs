﻿// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Threading.Tasks;
using AttackSurfaceAnalyzer.Utils;
using ElectronNET.API;
using ElectronNET.API.Entities;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace AttackSurfaceAnalyzer.Gui
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.Configure<CookiePolicyOptions>(options =>
            {
                // This lambda determines whether user consent for non-essential cookies is needed for a given request.
                options.CheckConsentNeeded = context => true;
                options.MinimumSameSitePolicy = SameSiteMode.None;
            });

            services.AddMvc().SetCompatibilityVersion(CompatibilityVersion.Version_2_1);
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            DatabaseManager.SqliteFilename = "asa.sqlite";
            DatabaseManager.Setup();
            Logger.Setup();
            Telemetry.Setup(Gui: true);

            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
                app.UseHsts();
            }

            app.UseHttpsRedirection();
            app.UseStaticFiles();
            app.UseCookiePolicy();

            app.UseMvc(routes =>
            {
                routes.MapRoute(
                    name: "default",
                    template: "{controller=Home}/{action=Index}/{id?}");
            });

            WebPreferences wp = new WebPreferences();
            wp.NodeIntegration = false;
            wp.ContextIsolation = true;

            BrowserWindowOptions browserWindowOptions = new BrowserWindowOptions
            {
#if DEBUG
                AutoHideMenuBar = false,
#else
                AutoHideMenuBar = true,
#endif
                Width = 1200,
                Height = 1000,
                Resizable = true,
                Center = true,
                Title = string.Format("Attack Surface Analyzer {0}", Helpers.GetVersionString()),
                WebPreferences = wp
            };

            Task.Run(async () =>
            {
                await Electron.WindowManager.CreateWindowAsync(browserWindowOptions);
            });
        }
    }
}