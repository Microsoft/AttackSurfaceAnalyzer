﻿// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using AttackSurfaceAnalyzer.Types;
using AttackSurfaceAnalyzer.Utils;
using Serilog;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Threading;

namespace AttackSurfaceAnalyzer.Collectors
{
    /// <summary>
    /// Base class for all collectors.
    /// </summary>
    public abstract class BaseCollector : IPlatformRunnable
    {
        public string RunId { get; set; }

        private RUN_STATUS _running = RUN_STATUS.NOT_STARTED;

        private int _numCollected = 0;

        public void Execute()
        {
            if (!CanRunOnPlatform())
            {
                Log.Warning(string.Format(CultureInfo.InvariantCulture, Strings.Get("Err_PlatIncompat"), GetType().ToString()));
                return;
            }
            Start();

            DatabaseManager.BeginTransaction();

            var StopWatch = System.Diagnostics.Stopwatch.StartNew();

            ExecuteInternal();

            StopWatch.Stop();
            TimeSpan t = TimeSpan.FromMilliseconds(StopWatch.ElapsedMilliseconds);
            string answer = string.Format(CultureInfo.InvariantCulture, "{0:D2}h:{1:D2}m:{2:D2}s:{3:D3}ms",
                                    t.Hours,
                                    t.Minutes,
                                    t.Seconds,
                                    t.Milliseconds);
            Log.Debug(Strings.Get("Completed"), this.GetType().Name, answer);

            var prevFlush = DatabaseManager.WriteQueue.Count;
            var totFlush = prevFlush;

            var printInterval = 10;
            var currentInterval = 0;

            StopWatch = System.Diagnostics.Stopwatch.StartNew();

            while (DatabaseManager.HasElements())
            {
                Thread.Sleep(1000);

                if (currentInterval++ % printInterval == 0)
                {
                    var actualDuration = (currentInterval < printInterval) ? currentInterval : printInterval;
                    var sample = DatabaseManager.WriteQueue.Count;
                    var curRate = prevFlush - sample;
                    var totRate = (double)(totFlush - sample) / StopWatch.ElapsedMilliseconds;
                    try
                    {
                        t = TimeSpan.FromMilliseconds(sample / (curRate/(actualDuration * 1000)));
                        answer = string.Format(CultureInfo.InvariantCulture, "{0:D2}h:{1:D2}m:{2:D2}s:{3:D3}ms",
                                                t.Hours,
                                                t.Minutes,
                                                t.Seconds,
                                                t.Milliseconds);
                        Log.Debug("Flushing {0} results. ({1}/{4}s {2:0.00}/s overall {3} ETA)", DatabaseManager.WriteQueue.Count, curRate, totRate * 1000, answer, actualDuration);
                    }
                    catch (Exception e) when (
                        e is OverflowException)
                    {
                        Log.Debug($"Overflowed: {curRate} {totRate} {sample} {sample / totRate} {t} {answer}");
                        Log.Debug("Flushing {0} results. ({1}/s {2:0.00}/s)", DatabaseManager.WriteQueue.Count, curRate, totRate * 1000);
                    }
                    prevFlush = sample;
                }

            }

            StopWatch.Stop();
            t = TimeSpan.FromMilliseconds(StopWatch.ElapsedMilliseconds);
            answer = string.Format(CultureInfo.InvariantCulture, "{0:D2}h:{1:D2}m:{2:D2}s:{3:D3}ms",
                                    t.Hours,
                                    t.Minutes,
                                    t.Seconds,
                                    t.Milliseconds);
            Log.Debug("Completed flushing in {0}", answer);

            DatabaseManager.Commit();
            Stop();
        }
        public abstract bool CanRunOnPlatform();

        public abstract void ExecuteInternal();

        private Stopwatch watch;

        public RUN_STATUS IsRunning()
        {
            return _running;
        }

        public void Start()
        {
            _running = RUN_STATUS.RUNNING;
            watch = System.Diagnostics.Stopwatch.StartNew();

            Log.Information(Strings.Get("Starting"), this.GetType().Name);
        }

        public void Stop()
        {
            _running = RUN_STATUS.COMPLETED;
            watch.Stop();
            TimeSpan t = TimeSpan.FromMilliseconds(watch.ElapsedMilliseconds);
            string answer = string.Format(CultureInfo.InvariantCulture, "{0:D2}h:{1:D2}m:{2:D2}s:{3:D3}ms",
                                    t.Hours,
                                    t.Minutes,
                                    t.Seconds,
                                    t.Milliseconds);
            Log.Information(Strings.Get("Completed"), this.GetType().Name, answer);
            var EndEvent = new Dictionary<string, string>();
            EndEvent.Add("Scanner", this.GetType().Name);
            EndEvent.Add("Duration", watch.ElapsedMilliseconds.ToString(CultureInfo.InvariantCulture));
            EndEvent.Add("NumResults", _numCollected.ToString(CultureInfo.InvariantCulture));
            AsaTelemetry.TrackEvent("EndScanFunction", EndEvent);
        }

        public int NumCollected()
        {
            return _numCollected;
        }
    }
}