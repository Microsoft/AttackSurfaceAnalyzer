﻿// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using AttackSurfaceAnalyzer.Types;

namespace AttackSurfaceAnalyzer.Objects
{
    public class OutputFileMonitorResult
    {
        #region Public Constructors

        public OutputFileMonitorResult(string PathIn)
        {
            Path = PathIn;
        }

        #endregion Public Constructors

        #region Public Properties

        public CHANGE_TYPE ChangeType { get; set; }
        public string? Name { get; set; }
        public string? OldName { get; set; }
        public string? OldPath { get; set; }
        public string Path { get; set; }
        public string? RowKey { get; set; }
        public string? Timestamp { get; set; }

        #endregion Public Properties
    }
}