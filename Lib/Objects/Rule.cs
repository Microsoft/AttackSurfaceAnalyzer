﻿using AttackSurfaceAnalyzer.Types;
using Newtonsoft.Json;
using System.Collections.Generic;
using System.ComponentModel;

namespace AttackSurfaceAnalyzer.Objects
{

    public class Rule
    {
        [DefaultValue(new PLATFORM[] { PLATFORM.LINUX, PLATFORM.MACOS, PLATFORM.WINDOWS })]
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.IgnoreAndPopulate)]
        public List<PLATFORM> Platforms { get; }

        [DefaultValue(new CHANGE_TYPE[] { CHANGE_TYPE.CREATED, CHANGE_TYPE.DELETED, CHANGE_TYPE.MODIFIED })]
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.IgnoreAndPopulate)]
        public List<CHANGE_TYPE> ChangeTypes { get; }

        public string Name { get; set; }
        public string Description { get; set; }
        public ANALYSIS_RESULT_TYPE Flag { get; set; }
        public RESULT_TYPE ResultType { get; set; }
        public List<Clause> Clauses { get; }
    }

    public class Clause
    {
        public string Field { get; set; }
        public OPERATION Operation { get; set; }
        public List<string> Data { get; }
        public List<KeyValuePair<string, string>> DictData { get; }
    }
}
