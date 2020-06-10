﻿// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using Newtonsoft.Json;
using PeNet.Header.Authenticode;
using System;
using System.Security.Cryptography.X509Certificates;

namespace AttackSurfaceAnalyzer.Objects
{
    public class Signature
    {
        #region Public Constructors

        public Signature(AuthenticodeInfo authenticodeInfo)
        {
            if (authenticodeInfo != null)
            {
                IsAuthenticodeValid = authenticodeInfo.IsAuthenticodeValid;
                if (authenticodeInfo.SignedHash is byte[] hash)
                {
                    SignedHash = Convert.ToBase64String(hash);
                }
                SignerSerialNumber = authenticodeInfo.SignerSerialNumber;
                if (authenticodeInfo.SigningCertificate is X509Certificate2 cert)
                {
                    SigningCertificate = new SerializableCertificate(cert);
                }
            }
            else
            {
                IsAuthenticodeValid = false;
            }
        }

        /// <summary>
        /// This constructor is for deserialization.
        /// </summary>
        /// <param name="IsAuthenticodeValid"></param>
        [JsonConstructor]
        public Signature(bool IsAuthenticodeValid)
        {
            this.IsAuthenticodeValid = IsAuthenticodeValid;
        }

        #endregion Public Constructors

        #region Public Properties

        public bool IsAuthenticodeValid { get; set; }

        public bool IsTimeValid
        {
            get
            {
                if (SigningCertificate != null)
                {
                    return DateTime.Now > SigningCertificate.NotBefore && DateTime.Now < SigningCertificate.NotAfter;
                }
                return false;
            }
        }

        public string? SignedHash { get; set; }
        public string? SignerSerialNumber { get; set; }
        public SerializableCertificate? SigningCertificate { get; set; }

        #endregion Public Properties
    }
}