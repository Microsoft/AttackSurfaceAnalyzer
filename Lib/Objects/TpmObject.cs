﻿// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using System;
using System.Collections.Generic;
using Tpm2Lib;

namespace AttackSurfaceAnalyzer.Objects
{
    public class TpmObject : CollectObject
    {
        public List<AsaNvIndex> NV { get; set; } = new List<AsaNvIndex>();
        public Dictionary<(TpmAlgId, uint), byte[]> PCRs { get; set; } = new Dictionary<(TpmAlgId, uint), byte[]>();
        public List<CryptographicKeyObject> PersistentKeys { get; set; } = new List<CryptographicKeyObject>();
        public List<CryptographicKeyObject> RandomKeys { get; set; } = new List<CryptographicKeyObject>();
        public List<AlgProperty> Algorithms { get; set; } = new List<AlgProperty>();
        public List<TpmCc> Commands { get; set; } = new List<TpmCc>();
        public string? Manufacturer { get; set; }
        public DateTime TpmSpecDate { get; set; }
        public string? Version { get; set; }
        public string Location { get; }


        public TpmObject(string Location)
        {
            ResultType = Types.RESULT_TYPE.TPM;
            this.Location = Location;
        }

        public override string Identity
        {
            get
            {
                return Location;
            }
        }
    }
}