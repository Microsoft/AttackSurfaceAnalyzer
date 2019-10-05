﻿// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using AttackSurfaceAnalyzer.Objects;
using Microsoft.Win32;
using Serilog;
using System;
using System.Collections.Generic;
using System.Security.AccessControl;
using System.Security.Principal;

namespace AttackSurfaceAnalyzer.Utils
{
    public static class RegistryWalker
    {
        public static IEnumerable<RegistryObject> WalkHive(RegistryHive Hive, string startingKey = null)
        {
            Stack<RegistryKey> keys = new Stack<RegistryKey>();

            RegistryKey x86_View = RegistryKey.OpenBaseKey(Hive, RegistryView.Registry32);
            if (startingKey != null)
            {
                x86_View = x86_View.OpenSubKey(startingKey);
            }

            keys.Push(x86_View);

            RegistryKey x64_View = RegistryKey.OpenBaseKey(Hive, RegistryView.Registry64);
            if (startingKey != null)
            {
                x64_View = x64_View.OpenSubKey(startingKey);
            }

            keys.Push(x64_View);

            while (keys.Count > 0)
            {
                RegistryKey currentKey = keys.Pop();

                if (currentKey == null)
                {
                    continue;
                }
                if (Filter.IsFiltered(AsaHelpers.GetPlatformString(), "Scan", "Registry", "Key", currentKey.Name))
                {
                    continue;
                }

                // First push all the new subkeys onto our stack.
                foreach (string key in currentKey.GetSubKeyNames())
                {
                    try
                    {
                        var next = currentKey.OpenSubKey(name: key, writable: false);
                        keys.Push(next);
                    }
                    // These are expected as we are running as administrator, not System.
                    catch (System.Security.SecurityException e)
                    {
                        Log.Verbose(e, "Permission Denied: {0}", currentKey.Name);
                    }
                    // There seem to be some keys which are listed as existing by the APIs but don't actually exist.
                    // Unclear if these are just super transient keys or what the other cause might be.
                    // Since this isn't user actionable, also just supress these to the verbose stream.
                    catch (System.IO.IOException e)
                    {
                        Log.Verbose(e, "Error Reading: {0}", currentKey.Name);
                    }
                    catch (Exception e)
                    {
                        Log.Information(e, "Unexpected error when parsing {0}:", currentKey.Name);
                        AsaTelemetry.TrackTrace(Microsoft.ApplicationInsights.DataContracts.SeverityLevel.Error, e);
                    }
                }

                var regObj = RegistryKeyToRegistryObject(currentKey);

                if (regObj != null)
                {
                    yield return regObj;
                }
            }

            x86_View.Dispose();
            x64_View.Dispose();
        }

        public static RegistryObject RegistryKeyToRegistryObject(RegistryKey registryKey)
        {
            RegistryObject regObj = null;
            try
            {
                regObj = new RegistryObject()
                {
                    Key = registryKey.Name,
                };

                regObj.AddSubKeys(new List<string>(registryKey.GetSubKeyNames()));

                foreach (RegistryAccessRule rule in registryKey.GetAccessControl().GetAccessRules(true, true, typeof(System.Security.Principal.SecurityIdentifier)))
                {
                    string name = rule.IdentityReference.Value;

                    try
                    {
                        name = rule.IdentityReference.Translate(typeof(NTAccount)).Value;
                    }
                    catch (IdentityNotMappedException)
                    {
                        // This is fine. Some SIDs don't map to NT Accounts.
                    }

                    regObj.Permissions.Add(name, rule.RegistryRights.ToString());
                }

                foreach (string valueName in registryKey.GetValueNames())
                {
                    try
                    {
                        if (registryKey.GetValue(valueName) == null)
                        {

                        }
                        regObj.Values.Add(valueName, (registryKey.GetValue(valueName) == null) ? "" : (registryKey.GetValue(valueName).ToString()));
                    }
                    catch (Exception ex)
                    {
                        Log.Debug(ex, "Found an exception processing registry values.");
                    }
                }
            }
            catch (System.ArgumentException e)
            {
                Logger.VerboseException(e);
            }
            catch (Exception e)
            {
                Log.Debug(e, "Couldn't process reg key {0}", registryKey.Name);
            }

            return regObj;
        }
    }
}