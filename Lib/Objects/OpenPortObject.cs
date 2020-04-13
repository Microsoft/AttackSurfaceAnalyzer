﻿// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using AttackSurfaceAnalyzer.Types;

namespace AttackSurfaceAnalyzer.Objects
{
    public class OpenPortObject : CollectObject
    {
        public string? Address { get; set; }
        /// <summary>
        /// InterNetwork is IPv4
        /// InterNetworkV6 is IPv6
        /// https://docs.microsoft.com/en-us/dotnet/api/system.net.sockets.addressfamily?view=netcore-3.1
        /// </summary>
        public ADDRESS_FAMILY Family { get; set; }
        /// <summary>
        /// TCP or UDP
        /// </summary>
        public TRANSPORT Type { get; set; }
        /// <summary>
        /// The port number
        /// </summary>
        public int Port { get; set; }
        public string? ProcessName { get; set; }

        public OpenPortObject(int Port, TRANSPORT Type) : this(Port, Type, ADDRESS_FAMILY.Unspecified) { }

        public OpenPortObject(int Port, TRANSPORT Type, ADDRESS_FAMILY Family)
        {
            ResultType = RESULT_TYPE.PORT;
            this.Port = Port;
            this.Type = Type;
            this.Family = Family;
        }

        /// <summary>
        /// $"{Address}:{Family}:{Type}:{Port}:{ProcessName}"
        /// </summary>
        public override string Identity
        {
            get
            {
                return $"{Address}:{Family}:{Type}:{Port}:{ProcessName}";
            }
        }
    }
}