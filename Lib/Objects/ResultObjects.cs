﻿// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using AttackSurfaceAnalyzer.Objects;
using System.Collections.Generic;
using System.IO;

namespace AttackSurfaceAnalyzer.Objects
{

    public class FileMonitorEvent
    {
        public CHANGE_TYPE ChangeType;
        public string Path;
        public string OldPath;
        public string Name;
        public string OldName;
    }

    public class CompareResult
    {
        public string BaseRowKey;
        public string CompareRowKey;
        public string BaseRunId;
        public string CompareRunId;
        public CHANGE_TYPE ChangeType;
        public RESULT_TYPE ResultType;
        public object Base;
        public object Compare;
        public ANALYSIS_RESULT_TYPE Analysis;
        public List<Rule> Rules = new List<Rule>();
    }

    public class OutputFileMonitorResult
    {
        public string RowKey;
        public string Timestamp;
        public string OldPath;
        public string Path;
        public string OldName;
        public string Name;
        public CHANGE_TYPE ChangeType;
    }

    public class OutputCompareResult : CompareResult
    {
        public string SerializedBase;
        public string SerializedCompare;
    }

    public class FileSystemResult : CompareResult
    {
        public FileSystemResult()
        {
            ResultType = RESULT_TYPE.FILE;
        }
    }

    public class FileSystemMonitorResult
    {
        public FileSystemEventArgs evt;
        public NotifyFilters filter;
    }

    public class OpenPortResult: CompareResult
    {
        public OpenPortResult()
        {
            ResultType = RESULT_TYPE.PORT;
        }
    }

    public class RegistryResult: CompareResult
    {
        public RegistryResult()
        {
            ResultType = RESULT_TYPE.REGISTRY;
        }
    }

    public class ServiceResult : CompareResult
    {
        public ServiceResult()
        {
            ResultType = RESULT_TYPE.SERVICES;
        }
    }

    public class UserAccountResult : CompareResult
    {
        public UserAccountResult()
        {
            ResultType = RESULT_TYPE.USER;
        }
    }

    public class CertificateResult: CompareResult
    {
        public CertificateResult()
        {
            ResultType = RESULT_TYPE.CERTIFICATE;
        }
    }
}
