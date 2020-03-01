﻿// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using AttackSurfaceAnalyzer.Types;
using System.Collections.Generic;

namespace AttackSurfaceAnalyzer.Objects
{

    public class UserAccountObject : CollectObject
    {
        public string AccountType { get; set; }
        public string Caption { get; set; }
        public string Description { get; set; }
        public string Disabled { get; set; }
        public string Domain { get; set; }
        public string FullName { get; set; }
        public string InstallDate { get; set; }
        public string LocalAccount { get; set; }
        public string Lockout { get; set; }
        public string PasswordChangeable { get; set; }
        public string PasswordExpires { get; set; }
        public string PasswordRequired { get; set; }
        public string SID { get; set; }
        public string UID { get; set; }
        public string GID { get; set; }
        public string Inactive { get; set; }
        public string HomeDirectory { get; set; }
        public string Shell { get; set; }
        public string PasswordStorageAlgorithm { get; set; }
        public bool Privileged { get; set; }
        public string Name { get; set; }
        public bool Hidden { get; set; }
        public List<string> Groups { get; set; }
        public Dictionary<string, string> Properties { get; set; }

        public UserAccountObject()
        {
            ResultType = RESULT_TYPE.USER;
            Groups = new List<string>();
            Properties = new Dictionary<string, string>();
        }

        public override string Identity
        {
            get
            {
                return (Domain == null) ? Name : $"{Domain}\\{Name}";
            }
        }
    }
}