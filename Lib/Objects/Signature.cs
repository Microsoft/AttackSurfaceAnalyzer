﻿using PeNet.Authenticode;
using System;

namespace AttackSurfaceAnalyzer.Objects
{
    public class Signature
    {
        public Signature(AuthenticodeInfo authenticodeInfo)
        {
            if (authenticodeInfo != null)
            {
                IsAuthenticodeValid = authenticodeInfo.IsAuthenticodeValid;
                SignedHash = Convert.ToBase64String(authenticodeInfo.SignedHash);
                SignerSerialNumber = authenticodeInfo.SignerSerialNumber;
                SigningCertificate = new SerializableCertificate(authenticodeInfo.SigningCertificate);
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
        public Signature(bool IsAuthenticodeValid)
        {
            this.IsAuthenticodeValid = IsAuthenticodeValid;
        }

        public bool IsAuthenticodeValid { get; set; }
        public string? SignedHash { get; set; }
        public string? SignerSerialNumber { get; set; }
        public SerializableCertificate? SigningCertificate { get; set; }

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
    }
}
