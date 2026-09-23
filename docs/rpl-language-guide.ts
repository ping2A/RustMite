export type RplGuideGroup = {
  id: string;
  title: string;
  description: string;
};

export type RplGuideCallout = {
  variant: "tip" | "note" | "important";
  title?: string;
  body: string;
};

export type RplGuideTable = {
  headers: string[];
  rows: string[][];
};

export type RplGuideExample = {
  title?: string;
  query: string;
  note?: string;
};

export type RplGuideSection = {
  id: string;
  group: string;
  title: string;
  lead?: string;
  command?: string;
  paragraphs?: string[];
  callouts?: RplGuideCallout[];
  list?: string[];
  table?: RplGuideTable;
  examples?: RplGuideExample[];
};

export const RPL_GUIDE_GROUPS: RplGuideGroup[] = [
  {
    id: "start",
    title: "Getting started",
    description: "How RPL queries are structured and how time windows work.",
  },
  {
    id: "syntax",
    title: "Search syntax",
    description: "Filters, wildcards, and boolean logic before the first pipe.",
  },
  {
    id: "pipes",
    title: "Pipe commands",
    description: "Transform result rows — aggregate, enrich, chart, and shape output.",
  },
  {
    id: "reference",
    title: "Field reference",
    description: "Common RustMite event fields and analyst habits that save time.",
  },
];

export const RPL_CHEATSHEET: RplGuideExample[] = [
  { title: "High severity", query: 'severity="critical" OR severity="high" | head 50' },
  {
    title: "Top processes",
    query: "process_name=* | stats count by process_name | sort -count | head 20",
  },
  { title: "memfd exec", query: "exe_memfd=1 | head 100" },
  { title: "SSH keys", query: 'kind="authorized_key" | head 50' },
  { title: "Timeline", query: "| timechart span=1h count by kind limit=8" },
];

export const RPL_GUIDE_SECTIONS: RplGuideSection[] = [
  {
    id: "overview",
    group: "start",
    title: "What is RPL?",
    lead: "RPL (RustMite Pipe Language) is RustMite’s search and detection query language — pipe-oriented, readable, and compiled to ClickHouse SQL.",
    paragraphs: [
      "Think of a query in three beats: optionally bound time, filter events with a search clause, then pipe the rows through commands that summarize, enrich, or reshape them.",
      "The same syntax powers the operator console RPL Hunt workspace. If you can hunt there, you can express the same logic in detection rules later.",
    ],
    callouts: [
      {
        variant: "tip",
        title: "Start here",
        body: "Copy an example from the Hunt Results chips, run it, then return here when you want the grammar behind the pipes.",
      },
    ],
    examples: [
      {
        title: "Filter and sample",
        query: 'last 24h severity="high" | head 20',
        note: "Wall-clock window + severity filter, capped at 20 rows",
      },
      {
        title: "Aggregate processes",
        query: "process_name=* | stats count by process_name | sort -count | head 50",
      },
      {
        title: "Chart volume over time",
        query: "| timechart span=1h count by kind limit=8",
      },
    ],
  },
  {
    id: "shape",
    group: "start",
    title: "Anatomy of a query",
    lead: "Every RPL query follows the same skeleton. Memorize this and the rest is just vocabulary.",
    table: {
      headers: ["Segment", "Required?", "What it does"],
      rows: [
        ["Time modifier", "Optional", "Bounds wall-clock time (`last 24h`, `now-7d`)"],
        ["Search clause", "Yes (can be `*`)", "Boolean filters on event fields"],
        ["`| command`", "Optional, repeatable", "Transform rows: stats, sort, chart…"],
      ],
    },
    callouts: [
      {
        variant: "important",
        title: "Always cap exploratory queries",
        body: "End open-ended hunts with `| head N`. Without a limit, broad searches can scan huge partitions.",
      },
    ],
    examples: [
      {
        title: "Full pipeline",
        query:
          'last 7d host_name=* process_name=* | stats count by process_name | sort -count | head 25',
      },
    ],
  },
  {
    id: "time",
    group: "start",
    title: "Time modifiers",
    lead: "Control which slice of the event stream you see — or set From / To on the Hunt command bar.",
    paragraphs: [
      "Prefix the search bar with `last …` or `now-…`, or set **From / To** on the Results tab. Explicit `time_from` / `time_to` on the API request win over inline `last` when both are set.",
      "When you omit a time prefix, the server uses the values you pass (or no wall-clock bound if both are empty).",
    ],
    table: {
      headers: ["Syntax", "Meaning"],
      rows: [
        ["`last 15m`", "Last 15 minutes"],
        ["`last 24h`", "Last 24 hours"],
        ["`last 7d`", "Last 7 days"],
        ["`now-7d`", "Equivalent to last 7 days"],
        ["`@timestamp last 1h`", "Optional prefix (accepted, ignored)"],
      ],
    },
    list: ["Units: `m` / `min`, `h` / `hr`, `d` / `day`, `w` / `week`"],
    callouts: [
      {
        variant: "note",
        body: "Incident response: pin From/To to the suspected window, then widen with `last 7d` once you know the shape of activity.",
      },
    ],
  },
  {
    id: "search",
    group: "syntax",
    title: "Search expressions",
    lead: "The search clause is plain boolean logic over fields — implicit AND between terms, with explicit AND / OR / NOT when you need grouping.",
    paragraphs: [
      "Compare fields with `=`, `!=`, `>`, `<`, `>=`, `<=`. A bang before the field (`!severity=\"info\"`) is shorthand for not-equal.",
      "Quote values for strings with spaces or special characters. Bare tokens work when unambiguous.",
    ],
    table: {
      headers: ["You write", "It matches"],
      rows: [
        ['platform="linux"', "Exact platform"],
        ['process_name="ssh*"', "Process name prefix (glob)"],
        ["message=*rootkit*", "Substring in message"],
        ["path=*", "Field is present (non-empty)"],
        ['severity IN ("critical", "high")', "Value in list"],
        ['kind NOT IN ("recon")', "Value not in list"],
        ["*memfd*", "Wildcard token (searches message)"],
      ],
    },
    list: [
      'Group with parentheses: `(severity="critical" OR severity="high") exe_memfd=1`',
      "Comments: `// line` and `/* block */`",
    ],
    callouts: [
      {
        variant: "tip",
        body: "Prefer structured fields (`process_name`, `kind`, `host_id`, `exe_memfd`) over `message=*…*` — faster, clearer, and easier to pivot on.",
      },
    ],
  },
  {
    id: "where",
    group: "pipes",
    title: "where",
    command: "where",
    lead: "Filter rows after earlier pipe stages — same expression syntax as the initial search clause.",
    examples: [
      {
        query: "process_name=* | stats count by process_name | where count>10 | head 50",
        note: "Often used mid-pipeline after stats",
      },
    ],
  },
  {
    id: "stats",
    group: "pipes",
    title: "stats",
    command: "stats",
    lead: "Roll events up into summaries — counts, distinct values, and numeric aggregates grouped by any field.",
    table: {
      headers: ["Function", "What you get"],
      rows: [
        ["count", "Number of rows in each group"],
        ["dc / distinct_count", "Distinct values of a field"],
        ["values", "Unique values as an array"],
        ["list", "All values as an array (may repeat)"],
        ["sum, avg, min, max", "Numeric aggregate on a field"],
      ],
    },
    paragraphs: ["`by` accepts comma- or space-separated fields. Trailing commas are fine."],
    examples: [
      { title: "Events per kind", query: "| stats count by kind" },
      { title: "Hosts per severity", query: "| stats dc host_id by severity" },
      {
        title: "Top process names",
        query: "process_name=* | stats count by process_name | sort -count | head 20",
      },
    ],
  },
  {
    id: "head",
    group: "pipes",
    title: "head",
    command: "head",
    lead: "Hard limit on rows returned. Your safety rail on every hunt.",
    examples: [{ query: "| head 100", note: "Keep N most recent rows after prior commands" }],
  },
  {
    id: "sort",
    group: "pipes",
    title: "sort",
    command: "sort",
    lead: "Order rows by a field. Prefix with `-` for descending.",
    examples: [
      { query: "| sort timestamp", note: "Oldest first" },
      { query: "| sort -timestamp", note: "Newest first" },
    ],
  },
  {
    id: "fields",
    group: "pipes",
    title: "fields",
    command: "fields",
    lead: "Project only the columns you care about — great before export or when trimming wide rows.",
    examples: [
      {
        query: "| fields timestamp, host_name, kind, process_name, severity, message",
      },
      {
        query: "| rename process_name AS proc | fields proc severity message",
        note: "Combine with rename for readable column names",
      },
    ],
  },
  {
    id: "rename",
    group: "pipes",
    title: "rename",
    command: "rename",
    lead: "Rename a column. `AS` is optional — whitespace alone works.",
    examples: [{ query: "| rename process_name AS proc" }],
  },
  {
    id: "eval",
    group: "pipes",
    title: "eval",
    command: "eval",
    lead: "Add or overwrite a column with a literal, field reference, `if()`, or simple arithmetic.",
    examples: [
      { query: '| eval risk=if(severity="high",1,0)' },
      { query: '| eval label="reviewed"' },
    ],
  },
  {
    id: "dedup",
    group: "pipes",
    title: "dedup",
    command: "dedup",
    lead: "Keep the first row for each distinct value — deduplicate noisy repeated events.",
    examples: [{ query: "| dedup host_id" }],
  },
  {
    id: "rex",
    group: "pipes",
    title: "rex",
    command: "rex",
    lead: "Extract text with a regex capture group into a new column. Default source field is `message`.",
    examples: [
      {
        query: "| rex ip=(\\d+\\.\\d+\\.\\d+\\.\\d+) field=message",
        note: "Capture group 1 becomes column `ip`",
      },
    ],
  },
  {
    id: "timechart",
    group: "pipes",
    title: "timechart",
    command: "timechart",
    lead: "Bucket event counts or numeric metrics over time for the Hunt timeline. Split series with `by`, cap with `limit`.",
    table: {
      headers: ["Option", "Default", "Role"],
      rows: [
        ["span", "—", "Bucket width: 15m, 1h, 1d…"],
        ["count", "—", "Event count per bucket"],
        ["avg / min / max / sum field", "—", "Numeric metric"],
        ["by", "—", "Field to split series"],
        ["limit", "10", "Top N series; 0 = show all"],
        ["useother", "true", "Roll minor series into Other"],
      ],
    },
    examples: [
      { query: "| timechart span=1h count by kind limit=8" },
      { query: "| timechart span=1h count by severity" },
      { query: "| timechart span=1d count by collector limit=5 useother=false" },
    ],
  },
  {
    id: "fields-ref",
    group: "reference",
    title: "Common fields",
    lead: "Events follow the RustMite ClickHouse schema (`rustmite.events`). The Hunt fields sidebar and `GET /v1/hunt/rpl/fields` list every searchable column.",
    table: {
      headers: ["Field", "Analyst use"],
      rows: [
        ["host_id / host_name", "Scope almost every hunt to a host"],
        ["platform", "Usually `linux`"],
        ["kind", "Observation kind: process, authorized_key, …"],
        ["collector", "Which probe collector emitted the row"],
        ["check_id", "Finding / check identity when present"],
        ["severity", "critical / high / medium / low / info"],
        ["process_name / process_id", "Process inventory & decloak"],
        ["exe_memfd", "1 when executable is memfd-backed"],
        ["user", "Process or account user"],
        ["path", "File / binary path"],
        ["src_ip, dest_ip", "Network endpoints"],
        ["file_hash", "Content hash IoC"],
        ["scan_id", "Pivot to a specific scan"],
        ["message", "Raw text — wildcard-friendly"],
        ["timestamp", "Event time (UTC)"],
        ["ext", "JSON bag for collector-specific keys"],
      ],
    },
    callouts: [
      {
        variant: "tip",
        title: "ext JSON",
        body: "Collector-specific keys land in `ext` when not promoted to a top-level field. Prefer promoted columns when they exist.",
      },
    ],
  },
  {
    id: "tips",
    group: "reference",
    title: "Habits that help",
    lead: "Small conventions that keep hunts fast and results trustworthy.",
    list: [
      "Start with host_id= or severity= when investigating a finding.",
      "Put | head N on every query while exploring.",
      "stats before head when summarizing — stats shrinks rows first.",
      "Use timechart for volume questions; stats for top-N tables.",
      "Click a field in the sidebar to insert it into the query bar.",
      "Save useful pipelines with the Saved queries list (localStorage).",
    ],
  },
];

export function sectionsForGroup(groupId: string): RplGuideSection[] {
  return RPL_GUIDE_SECTIONS.filter((s) => s.group === groupId);
}
