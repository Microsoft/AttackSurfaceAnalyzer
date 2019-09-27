﻿using Microsoft.ApplicationInsights;
using Microsoft.ApplicationInsights.DataContracts;
using Microsoft.ApplicationInsights.Extensibility;
using Microsoft.Data.Sqlite;
using System;
using System.Collections.Generic;

namespace AttackSurfaceAnalyzer.Utils
{
    public class Telemetry
    {
        private static readonly string UPDATE_TELEMETRY = "replace into persisted_settings values ('telemetry_opt_out',@TelemetryOptOut)"; //lgtm [cs/literal-as-local]
        private static readonly string CHECK_TELEMETRY = "select value from persisted_settings where setting='telemetry_opt_out'";

        private static readonly string INSTRUMENTATION_KEY = "719e5a56-dae8-425f-be07-877db7ae4d3b";

        public static TelemetryClient Client;
        public static bool OptOut { get; private set; }

        public static void TestMode()
        {
            Client = new TelemetryClient();
            TelemetryConfiguration.Active.DisableTelemetry = true;
        }

        public static void Setup(bool Gui)
        {
            if (Client == null)
            {
                var config = TelemetryConfiguration.CreateDefault();
                using (var cmd = new SqliteCommand(CHECK_TELEMETRY, DatabaseManager.Connection, DatabaseManager.Transaction))
                {
                    using (var reader = cmd.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            OptOut = bool.Parse(reader["value"].ToString());
                        }
                    }
                }
                config.InstrumentationKey = INSTRUMENTATION_KEY;
                config.DisableTelemetry = OptOut;
                Client = new TelemetryClient(config);
                Client.Context.Component.Version = Helpers.GetVersionString();
                // Force some values to static values to prevent gathering unneeded data
                Client.Context.Cloud.RoleInstance =  "Asa";
                Client.Context.Cloud.RoleName = "Asa";
                Client.Context.Location.Ip = "1.1.1.1";
            }
        }

        public static void Flush()
        {
            Client.Flush();
        }

        public static void SetOptOut(bool optOut)
        {
            OptOut = optOut;
            var config = TelemetryConfiguration.CreateDefault();
            config.InstrumentationKey = INSTRUMENTATION_KEY;
            config.DisableTelemetry = OptOut;
            Client = new TelemetryClient(config);
            Client.Context.Component.Version = Helpers.GetVersionString();
            // Force some values to static values to prevent gathering unneeded data
            Client.Context.Cloud.RoleInstance = "Asa";
            Client.Context.Cloud.RoleName = "Asa";
            Client.Context.Location.Ip = "1.1.1.1";
            using (var cmd = new SqliteCommand(UPDATE_TELEMETRY, DatabaseManager.Connection, DatabaseManager.Transaction))
            {
                cmd.Parameters.AddWithValue("@TelemetryOptOut", OptOut.ToString());
                cmd.ExecuteNonQuery();
                DatabaseManager.Commit();
            }
        }

        public static void TrackEvent(string name, Dictionary<string, string> evt)
        {
            evt.Add("Version", Helpers.GetVersionString());
            evt.Add("OS", Helpers.GetOsName());
            evt.Add("OS_Version", Helpers.GetOsVersion());
            evt.Add("Method", new System.Diagnostics.StackFrame(1).GetMethod().Name);
            Client.TrackEvent(name, evt);
        }

        public static void TrackTrace(SeverityLevel severityLevel, Exception e)
        {
            var evt = new Dictionary<string, string>();
            evt.Add("Version", Helpers.GetVersionString());
            evt.Add("OS", Helpers.GetOsName());
            evt.Add("OS_Version", Helpers.GetOsVersion());
            evt.Add("Method", new System.Diagnostics.StackFrame(1).GetMethod().Name);
            evt.Add("Stack", e.StackTrace);
            Client.TrackTrace("Exception", severityLevel, evt);
        }
    }
}
