﻿// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using AttackSurfaceAnalyzer.Objects;
using AttackSurfaceAnalyzer.Types;
using AttackSurfaceAnalyzer.Utils;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using System.Threading;

namespace AttackSurfaceAnalyzer.Collectors
{
    /// <summary>
    /// Actively monitors the filesystem for changes.
    /// </summary>
    public class FileSystemMonitor : BaseMonitor, IDisposable
    {
        private List<FileSystemWatcher> watchers = new List<FileSystemWatcher>();

        private ConcurrentDictionary<string, FileSystemEventArgs> filesAccessed = new ConcurrentDictionary<string, FileSystemEventArgs>();

        public static readonly NotifyFilters defaultFilters = NotifyFilters.Attributes
                | NotifyFilters.CreationTime
                | NotifyFilters.DirectoryName
                | NotifyFilters.FileName
                | NotifyFilters.LastWrite
                | NotifyFilters.Security
                | NotifyFilters.Size;

        public static readonly NotifyFilters defaultFiltersWithAccessTime = defaultFilters | NotifyFilters.LastAccess;

        private readonly Action<FileMonitorObject> changeHandler;

        public static readonly NotifyFilters[] defaultFiltersList = new NotifyFilters[]
        {
            NotifyFilters.Attributes,
            NotifyFilters.CreationTime,
            NotifyFilters.DirectoryName,
            NotifyFilters.FileName,
            NotifyFilters.LastAccess,
            NotifyFilters.LastWrite,
            NotifyFilters.Security,
            NotifyFilters.Size
        };

        private readonly MonitorCommandOptions options;

        private readonly FileSystemCollector fsc;

        public override void StartRun()
        {
            watchers.ForEach(x => x.EnableRaisingEvents = true);
            RunStatus = RUN_STATUS.RUNNING;

        }

        public override void StopRun()
        {
            watchers.ForEach(x => x.EnableRaisingEvents = false);

            // Write each accessed file once.
            foreach(var e in filesAccessed)
            {
                var ToWrite = new FileMonitorObject(e.Value.FullPath)
                {
                    ResultType = RESULT_TYPE.FILEMONITOR,
                    ChangeType = ChangeTypeStringToChangeType(e.Value.ChangeType.ToString()),
                    Name = e.Value.Name,
                    Timestamp = DateTime.Now.ToString("O", CultureInfo.InvariantCulture),
                    FileSystemObject = fsc.FilePathToFileSystemObject(e.Value.FullPath)
                };
                changeHandler(ToWrite);
            }
            
            RunStatus = RUN_STATUS.COMPLETED;
        }

        public override bool CanRunOnPlatform()
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.Windows) || RuntimeInformation.IsOSPlatform(OSPlatform.OSX);
        }

        public FileSystemMonitor(MonitorCommandOptions opts, Action<FileMonitorObject> changeHandler)
        {
            if (changeHandler == null)
            {
                throw new NullReferenceException(nameof(changeHandler));
            }

            options = opts ?? new MonitorCommandOptions();
            this.changeHandler = changeHandler;

            fsc = new FileSystemCollector(new CollectCommandOptions()
            {
                DownloadCloud = false,
                GatherHashes = options.GatherHashes,
            });

            foreach(var dir in options.MonitoredDirectories?.Split(',') ?? fsc.Roots.ToArray())
            {
                foreach(var filter in defaultFiltersList)
                {
                    var watcher = new FileSystemWatcher();

                    watcher.Path = dir;

                    watcher.NotifyFilter = filter;

                    watcher.IncludeSubdirectories = true;

                    // Changed, Created and Deleted can share a handler, because they throw the same type of event
                    watcher.Changed += GetFunctionForFilterType(filter);
                    watcher.Created += GetFunctionForFilterType(filter);
                    watcher.Deleted += GetFunctionForFilterType(filter);

                    // Renamed needs a different handler because it throws a different kind of event
                    watcher.Renamed += GetRenamedFunctionForFilterType(filter);

                    watchers.Add(watcher);
                }
                
            }
        }

        private RenamedEventHandler? GetRenamedFunctionForFilterType(NotifyFilters filter)
        {
            switch (filter)
            {
                case NotifyFilters.Attributes:
                    return WriteAttributesRename;
                case NotifyFilters.CreationTime:
                    return WriteCreationTimeRename;
                case NotifyFilters.DirectoryName:
                    return WriteDirectoryNameRename;
                case NotifyFilters.FileName:
                    return WriteFileNameRename;
                case NotifyFilters.LastAccess:
                    return WriteLastAccessRename;
                case NotifyFilters.LastWrite:
                    return WriteLastWriteRename;
                case NotifyFilters.Security:
                    return WriteSecurityRename;
                case NotifyFilters.Size:
                    return WriteSizeRename;
                default:
                    return null;
            }
        }

        private FileSystemEventHandler? GetFunctionForFilterType(NotifyFilters filter)
        {
            switch (filter)
            {
                case NotifyFilters.Attributes:
                    return WriteAttributesChange;
                case NotifyFilters.CreationTime:
                    return WriteCreationTimeChange;
                case NotifyFilters.DirectoryName:
                    return WriteDirectoryNameChange;
                case NotifyFilters.FileName:
                    return WriteFileNameChange;
                case NotifyFilters.LastAccess:
                    return WriteLastAccessChange;
                case NotifyFilters.LastWrite:
                    return WriteLastWriteChange;
                case NotifyFilters.Security:
                    return WriteSecurityChange;
                case NotifyFilters.Size:
                    return WriteSizeChange;
                default:
                    return null;
            }
        }

        public bool IsRunning()
        {
            return watchers.Any(x => x.EnableRaisingEvents);
        }

        private void WriteAttributesChange(object source, FileSystemEventArgs e) { WriteChange(e, NotifyFilters.Attributes); }
        private void WriteCreationTimeChange(object source, FileSystemEventArgs e) { WriteChange(e, NotifyFilters.CreationTime); }
        private void WriteDirectoryNameChange(object source, FileSystemEventArgs e) { WriteChange(e, NotifyFilters.DirectoryName); }
        private void WriteFileNameChange(object source, FileSystemEventArgs e) { WriteChange(e, NotifyFilters.FileName); }
        private void WriteLastAccessChange(object source, FileSystemEventArgs e) { WriteChange(e, NotifyFilters.LastAccess); }
        private void WriteLastWriteChange(object source, FileSystemEventArgs e) { WriteChange(e, NotifyFilters.LastWrite); }
        private void WriteSecurityChange(object source, FileSystemEventArgs e) { WriteChange(e, NotifyFilters.Security); }
        private void WriteSizeChange(object source, FileSystemEventArgs e) { WriteChange(e, NotifyFilters.Size); }

        private void WriteAttributesRename(object source, RenamedEventArgs e) { WriteRename(e, NotifyFilters.Attributes); }
        private void WriteCreationTimeRename(object source, RenamedEventArgs e) { WriteRename(e, NotifyFilters.CreationTime); }
        private void WriteDirectoryNameRename(object source, RenamedEventArgs e) { WriteRename(e, NotifyFilters.DirectoryName); }
        private void WriteFileNameRename(object source, RenamedEventArgs e) { WriteRename(e, NotifyFilters.FileName); }
        private void WriteLastAccessRename(object source, RenamedEventArgs e) { WriteRename(e, NotifyFilters.LastAccess); }
        private void WriteLastWriteRename(object source, RenamedEventArgs e) { WriteRename(e, NotifyFilters.LastWrite); }
        private void WriteSecurityRename(object source, RenamedEventArgs e) { WriteRename(e, NotifyFilters.Security); }
        private void WriteSizeRename(object source, RenamedEventArgs e) { WriteRename(e, NotifyFilters.Size); }

        private void WriteChange(FileSystemEventArgs objIn, NotifyFilters filters)
        {
            if (objIn != null)
            {
                if (IsInvalidFile(objIn.FullPath))
                {
                    return;
                }

                // If we are gathering extended details LastAccess times aren't meaningful since we will trigger them
                // Instead we note they are gathered and clean up in StopRun
                if (!options.FileNamesOnly && filters.HasFlag(NotifyFilters.LastAccess))
                {
                    filesAccessed.TryAdd(objIn.FullPath, objIn);
                }
                else
                {
                    // We skip gathering extended information when
                    // The File was Deleted
                    // We are set to gather names only
                    var fso = (objIn.ChangeType == WatcherChangeTypes.Deleted || options.FileNamesOnly) ? null : fsc.FilePathToFileSystemObject(objIn.FullPath);
                    var ToWrite = new FileMonitorObject(objIn.FullPath)
                    {
                        ResultType = RESULT_TYPE.FILEMONITOR,
                        ChangeType = ChangeTypeStringToChangeType(objIn.ChangeType.ToString()),
                        Name = objIn.Name,
                        Timestamp = DateTime.Now.ToString("O", CultureInfo.InvariantCulture),
                        FileSystemObject = fso,
                        NotifyFilters = filters
                    };
                    changeHandler(ToWrite);
                }
            }
        }

        private static CHANGE_TYPE ChangeTypeStringToChangeType(string change_type)
        {
            if (change_type.Equals("Changed"))
            {
                return CHANGE_TYPE.MODIFIED;
            }
            if (change_type.Equals("Created"))
            {
                return CHANGE_TYPE.CREATED;
            }
            if (change_type.Equals("Renamed"))
            {
                return CHANGE_TYPE.RENAMED;
            }
            if (change_type.Equals("Deleted"))
            {
                return CHANGE_TYPE.DELETED;
            }
            return CHANGE_TYPE.INVALID;
        }

        public static CHANGE_TYPE ChangeTypeToChangeType(WatcherChangeTypes changeType)
        {
            switch (changeType)
            {
                case WatcherChangeTypes.Changed:
                    return CHANGE_TYPE.MODIFIED;
                case WatcherChangeTypes.Created:
                    return CHANGE_TYPE.CREATED;
                case WatcherChangeTypes.Deleted:
                    return CHANGE_TYPE.DELETED;
                case WatcherChangeTypes.Renamed:
                    return CHANGE_TYPE.RENAMED;
                default:
                    return CHANGE_TYPE.INVALID;
            }
        }

        public void WriteRename(RenamedEventArgs objIn, NotifyFilters filters)
        {
            if (objIn == null) { return; }

            if (IsInvalidFile(objIn.FullPath))
            {
                return;
            }

            var ToWrite = new FileMonitorObject(objIn.FullPath)
            {
                ResultType = RESULT_TYPE.FILEMONITOR,
                ChangeType = ChangeTypeStringToChangeType(objIn.ChangeType.ToString()),
                OldPath = objIn.OldFullPath,
                Name = objIn.Name,
                OldName = objIn.OldName,
                Timestamp = DateTime.Now.ToString("O", CultureInfo.InvariantCulture),
                FileSystemObject = fsc.FilePathToFileSystemObject(objIn.FullPath),
                NotifyFilters = filters
            };

            changeHandler(ToWrite);
        }
        
        private static bool IsInvalidFile(string Path)
        {
            return Path.StartsWith("/private/var/db/uuidtext");
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
            {
                watchers.ForEach(x => x.Dispose());
            }
        }
    }
}