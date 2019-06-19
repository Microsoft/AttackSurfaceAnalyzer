﻿using System;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;
using Serilog;
using System.Reflection;
using AttackSurfaceAnalyzer.Objects;
using System.Runtime.InteropServices;
using System.Linq;
using Newtonsoft.Json.Converters;
using PeNet.Structures.MetaDataTables;
using Markdig.Extensions.Tables;

namespace AttackSurfaceAnalyzer.Utils
{
    public class Analyzer
    {
        Dictionary<RESULT_TYPE, List<FieldInfo>> _Fields = new Dictionary<RESULT_TYPE, List<FieldInfo>>();
        Dictionary<RESULT_TYPE, ANALYSIS_RESULT_TYPE> DEFAULT_RESULT_TYPE_MAP = new Dictionary<RESULT_TYPE, ANALYSIS_RESULT_TYPE>();

        JObject config = null;
        List<Rule> _filters = new List<Rule>();
        PLATFORM OsName;

        public Analyzer(PLATFORM platform) : this(platform: platform, useEmbedded:true) { }
        public Analyzer(PLATFORM platform, string filterLocation = "analyses.json", bool useEmbedded = false) {
            if (useEmbedded) { LoadEmbeddedFilters(); }
            else { LoadFilters(filterLocation); }
            if (config != null) { ParseFilters(); }

            OsName = platform;
            PopulateFields();
        }

        protected void ParseFilters()
        {
            _filters = new List<Rule>();
            try
            {
                foreach (var R in (JArray)config["rules"])
                {
                    _filters.Add(R.ToObject<Rule>());
                }
                foreach (var R in (JObject)config["meta"])
                {
                    switch (R.Key)
                    {
                        case "defaultLevels":
                            DEFAULT_RESULT_TYPE_MAP = R.Value.ToObject<Dictionary<RESULT_TYPE, ANALYSIS_RESULT_TYPE>>();
                            break;
                    }
                }
            }
            catch(Exception e)
            {
                Log.Debug("{0} {1} {2}", e.GetType().ToString(), e.Message, e.StackTrace);
            }
        }

        protected void PopulateFields()
        {
            _Fields[RESULT_TYPE.FILE] = new List<FieldInfo>(new FileSystemObject().GetType().GetFields());
            _Fields[RESULT_TYPE.CERTIFICATE] = new List<FieldInfo>(new CertificateObject().GetType().GetFields());
            _Fields[RESULT_TYPE.PORT] = new List<FieldInfo>(new OpenPortObject().GetType().GetFields());
            _Fields[RESULT_TYPE.REGISTRY] = new List<FieldInfo>(new RegistryObject().GetType().GetFields());
            _Fields[RESULT_TYPE.SERVICE] = new List<FieldInfo>(new ServiceObject().GetType().GetFields());
            _Fields[RESULT_TYPE.USER] = new List<FieldInfo>(new UserAccountObject().GetType().GetFields());
        }

        public ANALYSIS_RESULT_TYPE Analyze(CompareResult compareResult)
        {
            if (config == null) { return DEFAULT_RESULT_TYPE_MAP[compareResult.ResultType]; }
            var results = new List<ANALYSIS_RESULT_TYPE>();
            var curFilters = _filters.Where((rule) => (rule.changeTypes.Contains(compareResult.ChangeType) || rule.changeTypes == null)
                                                     && (rule.platforms.Contains(OsName) || rule.platforms == null))
                                .ToList();
            if (curFilters.Count > 0)
            {
                foreach (Rule rule in curFilters)
                {
                    results.Add(Apply(rule, compareResult));
                }

                return results.Max();
            }
            //If there are no filters for a result type
            return DEFAULT_RESULT_TYPE_MAP[compareResult.ResultType];
        }

        protected ANALYSIS_RESULT_TYPE Apply(Rule rule, CompareResult compareResult)
        {
            var fields = _Fields[compareResult.ResultType];

            foreach (Clause clause in rule.clauses)
            {
                FieldInfo field = fields.FirstOrDefault(iField => iField.Name.Equals(clause.field));

                if (field == null)
                {
                    //Custom field logic will go here
                    return DEFAULT_RESULT_TYPE_MAP[compareResult.ResultType];
                }

                var val = default(object);
                var baseVal = default(object);
                try
                {
                    if (compareResult.Compare != null)
                    { 
                        val = GetValueByPropertyName(compareResult.Compare, field.Name);
                    }
                    if (compareResult.Base != null)
                    {
                        baseVal = GetValueByPropertyName(compareResult.Base, field.Name);
                    }
                    var complete = false;

                    switch (clause.op)
                    {
                        case OPERATION.EQ:
                            foreach (string datum in clause.data)
                            {
                                if (datum.Equals(val))
                                {
                                    complete = true;
                                }
                            }
                            if (complete) { break; }
                            return DEFAULT_RESULT_TYPE_MAP[compareResult.ResultType];

                        case OPERATION.NEQ:
                            foreach (string datum in clause.data)
                            {
                                if (!datum.Equals(val))
                                {
                                    complete = true;
                                }
                            }
                            if (complete) { break; }
                            return DEFAULT_RESULT_TYPE_MAP[compareResult.ResultType];

                        case OPERATION.CONTAINS:
                            foreach (string datum in clause.data)
                            {
                                var fld = GetValueByPropertyName(compareResult.Compare, field.Name).ToString();
                                if (fld.Contains(datum))
                                {
                                    complete = true;
                                }
                            }
                            if (complete) { break; }
                            return DEFAULT_RESULT_TYPE_MAP[compareResult.ResultType];

                        case OPERATION.GT:
                            if (Int32.Parse(val.ToString()) > Int32.Parse(clause.data[0]))
                            {
                                break;
                            }
                            return DEFAULT_RESULT_TYPE_MAP[compareResult.ResultType];

                        case OPERATION.LT:
                            if (Int32.Parse(val.ToString()) < Int32.Parse(clause.data[0]))
                            {
                                break;
                            }
                            return DEFAULT_RESULT_TYPE_MAP[compareResult.ResultType];

                        case OPERATION.REGEX:
                            foreach (string datum in clause.data)
                            {
                                var r = new Regex(datum);
                                if (r.IsMatch(val.ToString()))
                                {
                                    complete = true;
                                }
                            }
                            if (complete) { break; }
                            return DEFAULT_RESULT_TYPE_MAP[compareResult.ResultType];
                        case OPERATION.WAS_MODIFIED:
                            if (!val.ToString().Equals(baseVal.ToString()))
                            {
                                break;
                            }
                            return DEFAULT_RESULT_TYPE_MAP[compareResult.ResultType];
                        default:
                            Log.Debug("Unimplemented operation {0}", clause.op);
                            return DEFAULT_RESULT_TYPE_MAP[compareResult.ResultType];
                    }
                }
                catch (Exception e)
                {
                    Log.Debug("{0} {1} {2}", e.GetType().ToString(), e.Message, e.StackTrace);
                    return DEFAULT_RESULT_TYPE_MAP[compareResult.ResultType];
                }
            }
            compareResult.Rules.Add(rule);
            return rule.flag;
        }

        private object GetValueByPropertyName(object obj, string propertyName) => obj.GetType().GetField(propertyName).GetValue(obj);

        public void DumpFilters()
        {
            Log.Verbose("Filter dump:");

            Log.Verbose(JsonConvert.SerializeObject(_filters, new StringEnumConverter()));
        }

        public  void LoadEmbeddedFilters()
        {
            try
            {
                var assembly = System.Reflection.Assembly.GetExecutingAssembly();
                var resourceName = "AttackSurfaceAnalyzer.analyses.json";

                using (Stream stream = assembly.GetManifestResourceStream(resourceName))
                using (StreamReader streamreader = new StreamReader(stream))
                using (JsonTextReader reader = new JsonTextReader(streamreader))
                {
                    config = (JObject)JToken.ReadFrom(reader);
                    Log.Information(Strings.Get("LoadedAnalyses"), "Embedded");
                }
                if (config == null)
                {
                    Log.Debug("No filters today.");
                    return;
                }
                ParseFilters();
                DumpFilters();
            }
            catch (FileNotFoundException)
            {
                config = null;
                Log.Debug("{0} is missing (filter configuration file)", "Embedded");

                return;
            }
            catch (NullReferenceException)
            {
                config = null;
                Log.Debug("{0} is missing (filter configuration file)", "Embedded");

                return;
            }
            catch (JsonReaderException)
            {
                config = null;
                Log.Warning("Error when parsing '{0}' analyses file. This is likely an issue with your JSON formatting.", "Embedded");
            }
            catch (Exception e)
            {
                config = null;
                Log.Warning("Could not load filters {0} {1} {2}", "Embedded", e.GetType().ToString(), e.StackTrace);

                return;
            }
        }

        public void LoadFilters(string filterLoc = "analyses.json")
        {
            try
            {
                using (StreamReader file = System.IO.File.OpenText(filterLoc))
                using (JsonTextReader reader = new JsonTextReader(file))
                {
                    config = (JObject)JToken.ReadFrom(reader);
                    Log.Information(Strings.Get("LoadedAnalyses"), filterLoc);
                }
                if (config == null)
                {
                    Log.Debug("No filters this time.");
                    return;
                }
                ParseFilters();
                DumpFilters();
            }
            catch (System.IO.FileNotFoundException)
            {
                //That's fine, we just don't have any filters to load
                config = null;
                Log.Warning("{0} is missing (filter configuration file)", filterLoc);

                return;
            }
            catch (NullReferenceException)
            {
                config = null;
                Log.Warning("{0} is missing (filter configuration file)", filterLoc);

                return;
            }
            catch (JsonReaderException)
            {
                config = null;
                Log.Warning("Error when parsing '{0}' analyses file. This is likely an issue with your JSON formatting.",filterLoc);
            }
            catch (Exception e)
            {
                config = null;
                Log.Warning("Could not load filters {0} {1} {2}", filterLoc, e.GetType().ToString(), e.StackTrace);
                return;
            }
        }
    }
}


