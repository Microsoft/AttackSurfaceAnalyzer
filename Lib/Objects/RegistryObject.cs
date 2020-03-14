﻿// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using AttackSurfaceAnalyzer.Types;
using Microsoft.Win32;
using Serilog;
using System;
using System.Collections.Generic;
using System.Globalization;

namespace AttackSurfaceAnalyzer.Objects
{
    public class RegistryObject : CollectObject
    {
        public string Key { get; set; }
        public Dictionary<string, string>? Values { get; set; }
        public List<string>? Subkeys { get; set; }
        public string? PermissionsString { get; set; }
        public Dictionary<string, List<string>> Permissions { get; set; } = new Dictionary<string, List<string>>();

        public int ValueCount
        {
            get { return Values?.Count ?? 0; }
        }
        public int SubkeyCount
        {
            get { return Subkeys?.Count ?? 0; }
        }

        public RegistryObject(string Key)
        {
            ResultType = RESULT_TYPE.REGISTRY;
            this.Key = Key;
        }

        public void AddSubKeys(string[] subkeysIn)
        {
            if (Subkeys == null)
            {
                Subkeys = new List<string>();
            }
            Subkeys.AddRange(subkeysIn);
        }

        public static List<string> GetSubkeys(RegistryKey key)
        {
            if (key is null)
            {
                return new List<string>();
            }
            return new List<string>(key.GetSubKeyNames());
        }

        public static Dictionary<string, string> GetValues(RegistryKey key)
        {
            if (key is null)
            {
                throw new ArgumentNullException(nameof(key));
            }
            Dictionary<string, string> values = new Dictionary<string, string>();
            // Write values under key and commit
            foreach (var value in key.GetValueNames())
            {
                RegistryValueKind rvk = key.GetValueKind(value);
                string str = "";

                switch (rvk)
                {
                    case RegistryValueKind.MultiString:
                        str = string.Join(Environment.NewLine, (string[])key.GetValue(value));
                        break;
                    case RegistryValueKind.Binary:
                        str = Convert.ToBase64String((byte[])key.GetValue(value));
                        break;
                    case RegistryValueKind.DWord:
                        str = ((int)key.GetValue(value)).ToString(CultureInfo.InvariantCulture);
                        break;
                    case RegistryValueKind.ExpandString:
                    case RegistryValueKind.String:
                        str = (string)key.GetValue(value);
                        break;
                    case RegistryValueKind.QWord:
                        str = ((long)key.GetValue(value)).ToString(CultureInfo.InvariantCulture);
                        break;
                    default:
                        str = key.GetValue(value).ToString() ?? string.Empty;
                        break;
                }
                values.Add(value, str);
            }
            return values;
        }

        public override string Identity
        {
            get
            {
                return Key;
            }
        }
    }
}