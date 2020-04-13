﻿// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using AttackSurfaceAnalyzer.Objects;
using AttackSurfaceAnalyzer.Types;
using AttackSurfaceAnalyzer.Utils;
using Serilog;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;

namespace AttackSurfaceAnalyzer.Collectors
{
    /// <summary>
    /// Collects data about the local ports open.
    /// </summary>
    public class OpenPortCollector : BaseCollector
    {

        private readonly HashSet<string> processedObjects;

        public OpenPortCollector(string runId)
        {
            RunId = runId;
            processedObjects = new HashSet<string>();
        }

        public override bool CanRunOnPlatform()
        {
            try
            {
                var osRelease = File.ReadAllText("/proc/sys/kernel/osrelease") ?? "";
                osRelease = osRelease.ToUpperInvariant();
                if (osRelease.Contains("MICROSOFT") || osRelease.Contains("WSL"))
                {
                    Log.Error("OpenPortCollector cannot run on WSL until https://github.com/Microsoft/WSL/issues/2249 is fixed.");
                    return false;
                }
            }
            catch (Exception)
            {
                /* OK to ignore, expecting this on non-Linux platforms. */
            };

            return RuntimeInformation.IsOSPlatform(OSPlatform.Windows) || RuntimeInformation.IsOSPlatform(OSPlatform.Linux) || RuntimeInformation.IsOSPlatform(OSPlatform.OSX);
        }

        public override void ExecuteInternal()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                ExecuteWindows();
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                ExecuteLinux();
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                ExecuteOsX();
            }
        }

        /// <summary>
        /// Executes the OpenPortCollector on Windows. Uses the .NET Core
        /// APIs to gather active TCP and UDP listeners and writes them 
        /// to the database.
        /// </summary>
        public void ExecuteWindows()
        {
            var properties = IPGlobalProperties.GetIPGlobalProperties();

            foreach (var endpoint in properties.GetActiveTcpListeners())
            {
                var obj = new OpenPortObject(endpoint.Port, TRANSPORT.TCP)
                {
                    Family = endpoint.AddressFamily,
                    Address = endpoint.Address.ToString(),
                };
                foreach (ProcessPort p in Win32ProcessPorts.ProcessPortMap.FindAll(x => x.PortNumber == endpoint.Port))
                {
                    obj.ProcessName = p.ProcessName;
                }

                DatabaseManager.Write(obj, RunId);
            }

            foreach (var endpoint in properties.GetActiveUdpListeners())
            {
                var obj = new OpenPortObject(endpoint.Port, TRANSPORT.UDP)
                {
                    Family = endpoint.AddressFamily,
                    Address = endpoint.Address.ToString()
                };
                foreach (ProcessPort p in Win32ProcessPorts.ProcessPortMap.FindAll(x => x.PortNumber == endpoint.Port))
                {
                    obj.ProcessName = p.ProcessName;
                }

                DatabaseManager.Write(obj, RunId);
            }
        }

        /// <summary>
        /// Executes the OpenPortCollector on Linux. Calls out to the `ss`
        /// command and parses the output, sending the output to the database.
        /// </summary>
        private void ExecuteLinux()
        {
            try
            {
                var result = ExternalCommandRunner.RunExternalCommand("ss", "-ln");

                foreach (var _line in result.Split('\n'))
                {
                    var line = _line;
                    line = line.ToUpperInvariant();
                    if (!line.Contains("LISTEN"))
                    {
                        continue;
                    }
                    var parts = Regex.Split(line, @"\s+");
                    if (parts.Length < 5)
                    {
                        continue;       // Not long enough, must be an error
                    }

                    var addressMatches = Regex.Match(parts[4], @"^(.*):(\d+)$");
                    if (addressMatches.Success)
                    {
                        var address = addressMatches.Groups[1].ToString();
                        var port = addressMatches.Groups[2].ToString();
                        if (int.TryParse(port, out int portInt))
                        {
                            var obj = new OpenPortObject(portInt, parts[0].ToUpperInvariant().Equals("TCP") ? TRANSPORT.TCP : TRANSPORT.UDP)
                            {
                                Family = address.Contains('.')?AddressFamily.InterNetwork:address.Contains(':')?AddressFamily.InterNetworkV6:AddressFamily.Unknown,//@TODO: Determine IPV4 vs IPv6 via looking at the address
                                Address = address
                            };
                            DatabaseManager.Write(obj, RunId);
                        }

                    }
                }
            }
            catch (Exception e)
            {
                Log.Warning(Strings.Get("Err_Iproute2"));
                Log.Debug(e, "");
            }

        }

        /// <summary>
        /// Executes the OpenPortCollector on OS X. Calls out to the `lsof`
        /// command and parses the output, sending the output to the database.
        /// The 'ss' command used on Linux isn't available on OS X.
        /// </summary>
        private void ExecuteOsX()
        {
            try
            {
                string result = ExternalCommandRunner.RunExternalCommand("lsof", "-Pn -i4 -i6");

                foreach (var _line in result.Split('\n'))
                {
                    var line = _line.ToUpperInvariant();
                    if (!line.Contains("LISTEN"))
                    {
                        continue; // Skip any lines which aren't open listeners
                    }
                    var parts = Regex.Split(line, @"\s+");
                    if (parts.Length <= 9)
                    {
                        continue; // Not long enough
                    }

                    var addressMatches = Regex.Match(parts[8], @"^(.*):(\d+)$");
                    if (addressMatches.Success)
                    {
                        var address = addressMatches.Groups[1].ToString();
                        var port = addressMatches.Groups[2].ToString();
                        if (int.TryParse(port, out int portInt))
                        {
                            var obj = new OpenPortObject(portInt, parts[7].ToUpperInvariant().Equals("TCP")?TRANSPORT.TCP: parts[7].ToUpperInvariant().Equals("TCP")?TRANSPORT.UDP:TRANSPORT.UNKNOWN)
                            {
                                // Assuming family means IPv6 vs IPv4
                                Address = address,
                                ProcessName = parts[0]
                            };

                            switch (parts[4])
                            {
                                case "IPv4":
                                    obj.Family = AddressFamily.InterNetwork;
                                    break;
                                case "IPv6":
                                    obj.Family = AddressFamily.InterNetworkV6;
                                    break;
                                default:
                                    obj.Family = AddressFamily.Unknown;
                                    break;
                            }

                            DatabaseManager.Write(obj, RunId);
                        }
                    }
                }
            }
            catch (Exception e)
            {
                Log.Error(e, Strings.Get("Err_Lsof"));
            }
        }
    }
}
