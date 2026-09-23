/* IronSift run results page: findings table + triage (same structure as workbench). */
(function () {
  "use strict";

  var M = {
    datasetTags: "Dataset tags",
    inspectHint: "Open Ingestion inspect in a new tab (filtered to this host)",
    colMachine: "Machine",
    colSeverity: "Severity",
    colScore: "Score",
    colRisk: "Risk",
    colDetectors: "Detectors",
    colReasons: "Reasons",
    oneReason: "1 reason",
    nReasons: "%n reasons",
    reasonsHint: "Show or hide detection reasons and per-reason triage for this host.",
    none: "No findings for this run.",
    save: "Save triage",
    saving: "Saving…",
    saved: "Saved.",
    saveErr: "Could not save triage.",
    autoSaveHint: "Verdict changes save automatically.",
    pendingReasonsShort: "Review",
    pendingReasonsTitle:
      "This host has at least one grouped detection reason whose triage verdict is still Unset — open Reasons and pick False positive or Malicious.",
    reasonAria: "Per-reason verdict",
    unset: "Unset",
    fp: "False positive",
    mal: "Malicious",
    detIronsiftProcess: "IronSift · process",
    detAnomark: "AnoMark",
    detSigma: "Sigma (stable)",
    detIronsiftFile: "IronSift · file",
    detOther: "Other",
  };

  function esc(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function escapeAttr(s) {
    return esc(s).replace(/"/g, "&quot;");
  }

  function normVerdict(v) {
    return String(v || "unset")
      .toLowerCase()
      .replace(/-/g, "_");
  }

  function classifyLegacyReason(text) {
    var s = String(text || "");
    if (s.startsWith("Sigma match:")) return "sigma-zero";
    if (s.startsWith("AnoMark suspect:") || s.startsWith("AnoMark suspicious command ratio")) return "anomark-rs";
    if (s.startsWith("RISK DETECTED:") || s.startsWith("Process row:") || s.startsWith("Rare process:")) return "ironsift-process";
    if (
      s.startsWith("Rare file access:") ||
      s.startsWith("MTIME ANOMALY") ||
      s.startsWith("METADATA ANOMALY") ||
      s.startsWith("FLEET OUTLIER") ||
      s.startsWith("(+") ||
      s.indexOf("more rare files matched") !== -1
    )
      return "ironsift-file";
    return "other";
  }

  var GROUP_ORDER_DET = ["ironsift-process", "anomark-rs", "sigma-zero", "ironsift-file", "other"];

  function reasonExcludedFromPerReasonTriage(reason) {
    return String(reason || "").trimStart().startsWith("Process row:");
  }

  function extractIronsiftProcessPrimaryName(reason) {
    var s = String(reason || "").trimStart();
    if (s.startsWith("RISK DETECTED:")) {
      var after = s.slice("RISK DETECTED:".length).trimStart();
      var parts = after.split(/\s+/);
      for (var i = 0; i < parts.length; i++) {
        var tok = parts[i];
        if (tok.indexOf("name=") === 0) {
          var v = tok.slice("name=".length).replace(/,$/, "").trim();
          if (v) return v.toLowerCase();
        }
      }
      return null;
    }
    if (s.startsWith("Rare process:")) {
      var rest = s.slice("Rare process:".length).trim();
      var first = (rest.split(/[\s(]+/)[0] || "").trim();
      return first ? first.toLowerCase() : null;
    }
    if (s.startsWith("Process row:")) {
      var parts2 = s.split(/\s+/);
      for (var j = 0; j < parts2.length; j++) {
        var tok2 = parts2[j];
        if (tok2.indexOf("name=") === 0) {
          var v2 = tok2.slice("name=".length).replace(/,$/, "").trim();
          if (v2) return v2.toLowerCase();
        }
      }
    }
    return null;
  }

  function triageGroupKey(detector, reason) {
    if (detector === "ironsift-process") {
      var n = extractIronsiftProcessPrimaryName(reason);
      if (n) return "ironsift-process::g::" + n;
    }
    return String(detector) + "::" + String(reason);
  }

  /** Mirrors `finding_detector_reason_pairs` in platform.rs (UI / triage order). */
  function findingDetectorReasonPairs(f) {
    var out = [];
    var buckets = Array.isArray(f.reasons_by_detector) ? f.reasons_by_detector : [];
    if (buckets.length) {
      var byDet = {};
      buckets.forEach(function (b) {
        if (!b || !b.detector) return;
        var list = Array.isArray(b.reasons) ? b.reasons : [];
        if (!list.length) return;
        var det = String(b.detector);
        if (!byDet[det]) byDet[det] = [];
        list.forEach(function (r) {
          byDet[det].push(r);
        });
      });
      GROUP_ORDER_DET.forEach(function (det) {
        var list = byDet[det];
        if (!list) return;
        list.forEach(function (reason) {
          out.push([det, reason]);
        });
        delete byDet[det];
      });
      Object.keys(byDet)
        .sort()
        .forEach(function (det) {
          byDet[det].forEach(function (reason) {
            out.push([det, reason]);
          });
        });
    } else {
      var reasons = f.reasons || [];
      reasons.forEach(function (reason) {
        out.push([classifyLegacyReason(reason), reason]);
      });
    }
    return out;
  }

  function actionableTriageGroupSlots(f) {
    var seen = {};
    var out = [];
    var pairs = findingDetectorReasonPairs(f);
    for (var i = 0; i < pairs.length; i++) {
      var det = pairs[i][0];
      var reason = pairs[i][1];
      if (reasonExcludedFromPerReasonTriage(reason)) continue;
      var gk = triageGroupKey(det, reason);
      var key = det + "\0" + gk;
      if (!seen[key]) {
        seen[key] = true;
        out.push([det, gk]);
      }
    }
    return out;
  }

  function verdictForReasonOnMachine(triage, machineId, detector, reason) {
    var mlist = (triage && triage.machines) || [];
    for (var i = 0; i < mlist.length; i++) {
      if (!mlist[i] || mlist[i].machine_id !== machineId) continue;
      var rd = mlist[i].reason_decisions || [];
      for (var j = 0; j < rd.length; j++) {
        if (!rd[j]) continue;
        if (String(rd[j].detector || "") === String(detector || "") && String(rd[j].reason || "") === String(reason || "")) {
          return normVerdict(rd[j].verdict);
        }
      }
      return "unset";
    }
    return "unset";
  }

  function aggregateVerdictsForGroup(vers) {
    if (!vers || !vers.length) return "unset";
    for (var i = 0; i < vers.length; i++) {
      if (normVerdict(vers[i]) === "malicious") return "malicious";
    }
    for (var j = 0; j < vers.length; j++) {
      if (normVerdict(vers[j]) === "unset") return "unset";
    }
    return "false_positive";
  }

  /** True if any actionable triage group on this host still aggregates to Unset (matches run list / platform). */
  function machineHasPendingReasonTriage(f, userTriage) {
    var slots = actionableTriageGroupSlots(f);
    if (!slots.length) return false;
    var mid = String((f && f.machine_id) || "");
    var pairs = findingDetectorReasonPairs(f);
    for (var si = 0; si < slots.length; si++) {
      var det = slots[si][0];
      var gk = slots[si][1];
      var reasons = [];
      for (var pi = 0; pi < pairs.length; pi++) {
        var d = pairs[pi][0];
        var r = pairs[pi][1];
        if (reasonExcludedFromPerReasonTriage(r)) continue;
        if (d === det && triageGroupKey(d, r) === gk) reasons.push(r);
      }
      var vers = reasons.map(function (r) {
        return verdictForReasonOnMachine(userTriage, mid, det, r);
      });
      if (aggregateVerdictsForGroup(vers) === "unset") return true;
    }
    return false;
  }

  function finiteF64(x) {
    var n = Number(x);
    return n === n && n !== Infinity && n !== -Infinity ? n : 0;
  }

  /** Same thresholds as `severity_from_score` in platform.rs */
  function severityFromScore(score) {
    var s = finiteF64(score);
    if (s >= 0.9) return "CRITICAL";
    if (s >= 0.7) return "HIGH";
    if (s >= 0.4) return "MEDIUM";
    return "LOW";
  }

  /**
   * Effective score/severity after per-reason triage (matches `effective_score_and_severity` in platform.rs).
   * @returns {{ score: number, severity: string }}
   */
  function effectiveScoreAndSeverity(f, triage) {
    var raw = finiteF64(f && f.score != null ? f.score : 0);
    var slots = actionableTriageGroupSlots(f);
    if (!slots.length) {
      return { score: raw, severity: String((f && f.severity) || "LOW").toUpperCase() };
    }
    var mid = (f && f.machine_id) || "";
    var nMal = 0;
    var nFp = 0;
    var pairs = findingDetectorReasonPairs(f);
    for (var si = 0; si < slots.length; si++) {
      var det = slots[si][0];
      var gk = slots[si][1];
      var reasons = [];
      for (var pi = 0; pi < pairs.length; pi++) {
        var d = pairs[pi][0];
        var r = pairs[pi][1];
        if (reasonExcludedFromPerReasonTriage(r)) continue;
        if (d === det && triageGroupKey(d, r) === gk) reasons.push(r);
      }
      var vers = reasons.map(function (r) {
        return verdictForReasonOnMachine(triage, mid, det, r);
      });
      var agg = aggregateVerdictsForGroup(vers);
      if (agg === "malicious") nMal++;
      else if (agg === "false_positive") nFp++;
    }
    var nAct = slots.length;
    var newScore = nMal > 0 ? raw : nFp === nAct ? 0 : raw;
    return { score: newScore, severity: severityFromScore(newScore) };
  }

  function collectFindingReasonGroups(f) {
    var out = [];
    var directBuckets = Array.isArray(f.reasons_by_detector) ? f.reasons_by_detector : [];
    var groupOrder = ["ironsift-process", "anomark-rs", "sigma-zero", "ironsift-file", "other"];
    if (directBuckets.length) {
      var byDet = {};
      directBuckets.forEach(function (b) {
        if (b && b.detector) {
          var list = Array.isArray(b.reasons) ? b.reasons.slice() : [];
          if (list.length) byDet[b.detector] = list;
        }
      });
      groupOrder.forEach(function (det) {
        var r = byDet[det];
        if (r && r.length) {
          r.forEach(function (reason) {
            out.push({ detector: det, reason: reason });
          });
          delete byDet[det];
        }
      });
      Object.keys(byDet).forEach(function (det) {
        byDet[det].forEach(function (reason) {
          out.push({ detector: det, reason: reason });
        });
      });
    } else {
      var reasons = f.reasons || [];
      reasons.forEach(function (reason) {
        out.push({ detector: classifyLegacyReason(reason), reason: reason });
      });
    }
    return out;
  }

  function buildTriageVerdictLookup(userTriage, machineId) {
    var m = (userTriage && userTriage.machines) || [];
    var entry = null;
    for (var i = 0; i < m.length; i++) {
      if (m[i] && m[i].machine_id === machineId) {
        entry = m[i];
        break;
      }
    }
    var map = {};
    if (entry && Array.isArray(entry.reason_decisions)) {
      entry.reason_decisions.forEach(function (row) {
        if (!row) return;
        var k = String(row.detector || "") + "\0" + String(row.reason || "");
        map[k] = row.verdict != null ? String(row.verdict) : "unset";
      });
    }
    return function (detector, reason) {
      var k = String(detector || "") + "\0" + String(reason || "");
      return map[k] != null ? map[k] : "unset";
    };
  }

  function detectorDisplayName(detector) {
    switch (detector) {
      case "ironsift-process":
        return M.detIronsiftProcess;
      case "anomark-rs":
        return M.detAnomark;
      case "sigma-zero":
        return M.detSigma;
      case "ironsift-file":
        return M.detIronsiftFile;
      default:
        return M.detOther;
    }
  }

  function formatReasonHtml(reason) {
    var raw = String(reason == null ? "" : reason);
    if (/^\(\+\d+\s+more\b/.test(raw)) {
      return '<span class="findings-reasons-truncated">' + esc(raw) + "</span>";
    }
    var labelMatch = raw.match(/^([A-Z][A-Z0-9 a-z._-]{0,80}?):\s*(.*)$/);
    if (labelMatch) {
      var label = labelMatch[1];
      var payload = labelMatch[2];
      var labelEsc = '<span class="findings-reasons-label">' + esc(label + ":") + "</span>";
      if (/(?:^|\s)[a-zA-Z_][a-zA-Z0-9_]*=/.test(payload)) {
        var tokens = payload.match(/\S+=(?:"[^"]*"|\S+)|\S+/g) || [];
        var inner = tokens
          .map(function (tok) {
            var m = tok.match(/^([a-zA-Z_][a-zA-Z0-9_]*)=(.*)$/);
            if (m) {
              return '<span class="kv-key">' + esc(m[1]) + "=</span><span class=\"kv-val\">" + esc(m[2]) + "</span>";
            }
            return '<span class="kv-val">' + esc(tok) + "</span>";
          })
          .join(" ");
        return labelEsc + '<span class="findings-reasons-payload-kv">' + inner + "</span>";
      }
      return labelEsc + '<span class="findings-reasons-payload">' + esc(payload) + "</span>";
    }
    return '<span class="findings-reasons-payload">' + esc(raw) + "</span>";
  }

  function isExcludedFromReasonTriage(reason) {
    return String(reason || "").trim().startsWith("Process row:");
  }

  function renderReasonVerdictSelect(machineId, detector, reasonText, current) {
    var enc = encodeURIComponent(reasonText);
    var cur = normVerdict(current);
    var un = cur === "unset";
    var fp = cur === "false_positive";
    var ma = cur === "malicious";
    return (
      '<select class="triage-reason-verdict" aria-label="' +
      esc(M.reasonAria) +
      '" data-machine="' +
      escapeAttr(machineId) +
      '" data-detector="' +
      escapeAttr(detector) +
      '" data-reason="' +
      enc +
      '">' +
      '<option value="unset"' +
      (un ? " selected" : "") +
      ">" +
      esc(M.unset) +
      "</option>" +
      '<option value="false_positive"' +
      (fp ? " selected" : "") +
      ">" +
      esc(M.fp) +
      "</option>" +
      '<option value="malicious"' +
      (ma ? " selected" : "") +
      ">" +
      esc(M.mal) +
      "</option></select>"
    );
  }

  function renderReasonGroupTriage(machineId, detector, reasons, verdictLookup) {
    var safeDet = String(detector || "other").replace(/[^a-z0-9_-]/gi, "_");
    var pillCls = "findings-reasons-group-pill findings-reasons-group-pill--" + safeDet;
    var items = reasons
      .map(function (r) {
        var excluded = isExcludedFromReasonTriage(r);
        var v = verdictLookup(detector, r);
        var sel = excluded ? "" : renderReasonVerdictSelect(machineId, detector, r, v);
        var liCls = excluded
          ? "findings-reason-triage-li findings-reason-triage-li--no-decision"
          : "findings-reason-triage-li";
        return '<li class="' + liCls + '"><div class="findings-reason-li-main">' + formatReasonHtml(r) + "</div>" + sel + "</li>";
      })
      .join("");
    return (
      '<div class="findings-reasons-group">' +
      '<div class="findings-reasons-group-head">' +
      '<span class="' +
      pillCls +
      '">' +
      esc(detectorDisplayName(detector)) +
      '</span><span class="findings-reasons-group-count">' +
      reasons.length +
      "</span></div>" +
      '<ul class="findings-reasons-group-list findings-reasons-group-list--triage">' +
      items +
      "</ul></div>"
    );
  }

  function findingsReasonsCell(f, userTriage, runId) {
    var pairs = collectFindingReasonGroups(f);
    if (!pairs.length) return '<span class="muted">—</span>';
    var byDet = {};
    pairs.forEach(function (p) {
      if (!byDet[p.detector]) byDet[p.detector] = [];
      byDet[p.detector].push(p.reason);
    });
    var groupOrder = ["ironsift-process", "anomark-rs", "sigma-zero", "ironsift-file", "other"];
    var groups = [];
    groupOrder.forEach(function (det) {
      if (byDet[det]) {
        groups.push([det, byDet[det]]);
        delete byDet[det];
      }
    });
    Object.keys(byDet).forEach(function (det) {
      groups.push([det, byDet[det]]);
    });
    var total = groups.reduce(function (acc, g) {
      return acc + g[1].length;
    }, 0);
    if (!total) return '<span class="muted">—</span>';
    var machineId = f.machine_id || "";
    var verdictLookup = buildTriageVerdictLookup(userTriage, machineId);
    var sum = total === 1 ? M.oneReason : M.nReasons.replace("%n", String(total));
    var groupsHtml = groups
      .map(function (gr) {
        return renderReasonGroupTriage(machineId, gr[0], gr[1], verdictLookup);
      })
      .join("");
    var ridAttr = escapeAttr(String(runId || "").trim());
    var midAttr = escapeAttr(machineId);
    return (
      '<details class="findings-reasons-box" data-fr-run="' +
      ridAttr +
      '" data-fr-machine="' +
      midAttr +
      '"><summary class="findings-reasons-sum" title="' +
      esc(M.reasonsHint) +
      '">' +
      esc(sum) +
      '</summary><div class="findings-reasons-groups">' +
      groupsHtml +
      "</div></details>"
    );
  }

  function findingsDatasetTagsHtml(tags) {
    if (!tags || !tags.length) return "";
    var pills = tags
      .map(function (tag) {
        return '<span class="pill">' + esc(tag) + "</span>";
      })
      .join("");
    return '<div class="findings-dataset-tags">' + pills + "</div>";
  }

  function parseFindingMachineInspect(machineId, runDatasetIds) {
    var mid = String(machineId || "").trim();
    var ids = Array.isArray(runDatasetIds) ? runDatasetIds : [];
    var slash = mid.indexOf("/");
    if (slash > 0) {
      var prefix = mid.slice(0, slash);
      var rest = mid.slice(slash + 1);
      if (ids.indexOf(prefix) !== -1) return { datasetId: prefix, machineFilter: rest };
    }
    if (ids.length === 1) return { datasetId: ids[0], machineFilter: mid };
    return { datasetId: null, machineFilter: "" };
  }

  function findingsInspectUrl(datasetId, machineFilter) {
    var u = new URLSearchParams();
    u.set("tab", "ingestion");
    if (datasetId) u.set("inspect", datasetId);
    var mf = machineFilter != null ? String(machineFilter).trim() : "";
    if (mf) u.set("machine", mf);
    return "/?" + u.toString();
  }

  function findingsMachineCellHtml(f, runDatasetIds, userTriage) {
    var tri = userTriage || {};
    var mid = String(f.machine_id || "");
    var insp = parseFindingMachineInspect(mid, runDatasetIds);
    var code = '<code class="findings-machine">' + esc(mid) + "</code>";
    var core = code;
    if (insp.datasetId) {
      var href = findingsInspectUrl(insp.datasetId, insp.machineFilter);
      var hint = esc(M.inspectHint);
      core =
        '<a href="' +
        esc(href) +
        '" target="_blank" rel="noopener noreferrer" class="findings-machine-link" title="' +
        hint +
        '">' +
        code +
        "</a>";
    }
    var pending = machineHasPendingReasonTriage(f, tri);
    var badge = pending
      ? '<span class="findings-machine-pending" title="' +
        esc(M.pendingReasonsTitle) +
        '" aria-label="' +
        esc(M.pendingReasonsTitle) +
        '">' +
        esc(M.pendingReasonsShort) +
        "</span>"
      : "";
    return '<div class="findings-machine-cell">' + core + badge + "</div>" + findingsDatasetTagsHtml(f.dataset_tags);
  }

  function findingsDetectorsCell(f) {
    var d = f.detectors || [];
    if (!d.length) return '<span class="muted">—</span>';
    return (
      '<div style="display:flex;flex-wrap:wrap;gap:4px;align-items:center;">' +
      d
        .map(function (x) {
          return '<span class="pill" style="font-size:11px;margin:0">' + esc(x) + "</span>";
        })
        .join("") +
      "</div>"
    );
  }

  function severityClass(sev) {
    var s = String(sev || "").toUpperCase();
    if (s === "CLEAN" || s === "NONE") return "sev-low";
    if (s === "CRITICAL") return "sev-critical";
    if (s === "HIGH") return "sev-high";
    if (s === "MEDIUM") return "sev-medium";
    return "sev-low";
  }

  function severityColor(v) {
    var n = Number(v);
    if (n >= 0.9) return "#b91c1c";
    if (n >= 0.7) return "#dc2626";
    if (n >= 0.4) return "#f59e0b";
    return "#16a34a";
  }

  function cloneTriageMachineRows(userTriage) {
    var out = {};
    var rows = (userTriage && userTriage.machines) || [];
    for (var i = 0; i < rows.length; i++) {
      var row = rows[i];
      if (!row || !row.machine_id) continue;
      out[row.machine_id] = {
        machine_id: row.machine_id,
        reason_decisions: (row.reason_decisions || []).map(function (r) {
          return {
            detector: r.detector != null ? String(r.detector) : "other",
            reason: r.reason != null ? String(r.reason) : "",
            verdict: r.verdict != null ? String(r.verdict) : "unset",
          };
        }),
        final_verdict: row.final_verdict != null ? String(row.final_verdict) : "unset",
      };
    }
    return out;
  }

  function collectTriagePayloadFromDom(root, userTriage, findings) {
    var byMid = cloneTriageMachineRows(userTriage);
    (findings || []).forEach(function (f) {
      var mid = f.machine_id || "";
      if (!mid) return;
      if (!byMid[mid]) byMid[mid] = { machine_id: mid, reason_decisions: [], final_verdict: "unset" };
    });
    var domByMid = {};
    (root || document).querySelectorAll(".triage-reason-verdict").forEach(function (sel) {
      var mid = sel.getAttribute("data-machine");
      var det = sel.getAttribute("data-detector");
      var reason = "";
      try {
        reason = decodeURIComponent(sel.getAttribute("data-reason") || "");
      } catch (_) {
        return;
      }
      if (!mid) return;
      if (!domByMid[mid]) domByMid[mid] = [];
      domByMid[mid].push({
        detector: det || "other",
        reason: reason,
        verdict: sel.value || "unset",
      });
    });
    Object.keys(domByMid).forEach(function (mid) {
      if (!byMid[mid]) byMid[mid] = { machine_id: mid, reason_decisions: [], final_verdict: "unset" };
      byMid[mid].reason_decisions = domByMid[mid];
    });
    var list = Object.keys(byMid)
      .map(function (k) {
        return byMid[k];
      })
      .sort(function (a, b) {
        return String(a.machine_id).localeCompare(String(b.machine_id));
      });
    return { user_triage: { machines: list } };
  }

  function syncTriageReasonVerdictTheme(sel) {
    if (!sel || !sel.classList || !sel.classList.contains("triage-reason-verdict")) return;
    var v = normVerdict(sel.value);
    if (v === "false_positive") sel.setAttribute("data-verdict", "false_positive");
    else if (v === "malicious") sel.setAttribute("data-verdict", "malicious");
    else sel.setAttribute("data-verdict", "unset");
  }

  function wireTriageReasonVerdictTheming(root) {
    (root || document).querySelectorAll(".triage-reason-verdict").forEach(function (sel) {
      syncTriageReasonVerdictTheme(sel);
      if (sel.dataset.ironsiftTriageThemeBound) return;
      sel.dataset.ironsiftTriageThemeBound = "1";
      sel.addEventListener("change", function () {
        syncTriageReasonVerdictTheme(sel);
      });
    });
  }

  window.RunFindingsUi = {
    M: M,
    esc: esc,
    findingsReasonsCell: findingsReasonsCell,
    findingsMachineCellHtml: findingsMachineCellHtml,
    findingsDetectorsCell: findingsDetectorsCell,
    severityClass: severityClass,
    severityColor: severityColor,
    collectTriagePayloadFromDom: collectTriagePayloadFromDom,
    wireTriageReasonVerdictTheming: wireTriageReasonVerdictTheming,
    effectiveScoreAndSeverity: effectiveScoreAndSeverity,
    machineHasPendingReasonTriage: machineHasPendingReasonTriage,
  };
})();
