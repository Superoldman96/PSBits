/// <reference path="jsprovider.d.ts" />
"use strict";

// ============================================================================
//  CallerCalleeGraph.js — TTD Call Graph → GEXF for Gephi Lite
// ============================================================================
//
//  LOAD:   .scriptload C:\path\to\CallerCalleeGraph.js
//
//  EXPORT GEXF (file):
//      !exportGEXF "myapp!*" "C:\\temp\\callgraph.gexf"
//      !exportAllGEXF "C:\\temp\\callgraph.gexf"
//      !exportAllGEXF "C:\\temp\\callgraph.gexf" 200      ← top-200 edges
//
//  HUMAN-READABLE (console):
//      !callerCallee "myapp!*"
//      !callerCalleeAll 50
//
//  DX / LINQ:
//      dx @$scriptContents.analyzePattern("myapp!*").Where(p => p.count > 5)
//
// ============================================================================

function initializeScript() {
    return [
        new host.apiVersionSupport(1, 7),
        new host.functionAlias(analyzePattern,    "callerCallee"),
        new host.functionAlias(analyzeAllModules, "callerCalleeAll"),
        new host.functionAlias(exportGEXF,        "exportGEXF"),
        new host.functionAlias(exportAllGEXF,     "exportAllGEXF")
    ];
}

// ═══════════════════════════════════════════════════════════════════════════
//  MODULE TABLE — sorted by base for O(log n) containment lookup
// ═══════════════════════════════════════════════════════════════════════════

var _modTable      = null;
var _symCache      = {};
var _ctl           = null;
var _hasGMCS       = null;
var _rStats        = null;

function buildModuleTable() {
    _modTable = [];
    for (var mod of host.currentProcess.Modules) {
        var base     = mod.BaseAddress;
        var size     = mod.Size;
        var fullName = mod.Name.toString();
        var sep      = Math.max(fullName.lastIndexOf("\\"), fullName.lastIndexOf("/"));
        if (sep >= 0) fullName = fullName.substring(sep + 1);
        var dot = fullName.lastIndexOf(".");
        if (dot >= 0) fullName = fullName.substring(0, dot);
        _modTable.push({ base: base, end: host.Int64(base).add(size), name: fullName });
    }
    _modTable.sort(function (a, b) {
        return host.Int64(a.base).compareTo(b.base) < 0 ? -1 :
               host.Int64(a.base).compareTo(b.base) > 0 ?  1 : 0;
    });
}

function findModule(addr) {
    if (!_modTable) return null;
    var lo = 0, hi = _modTable.length - 1, t = host.Int64(addr);
    while (lo <= hi) {
        var mid = (lo + hi) >>> 1, m = _modTable[mid];
        if      (t.compareTo(m.base) < 0) hi = mid - 1;
        else if (t.compareTo(m.end) >= 0) lo = mid + 1;
        else return { name: m.name, offset: t.subtract(m.base) };
    }
    return null;
}

// ═══════════════════════════════════════════════════════════════════════════
//  TIERED SYMBOL RESOLUTION
// ═══════════════════════════════════════════════════════════════════════════

function initResolver() {
    _symCache = {};
    _ctl      = host.namespace.Debugger.Utility.Control;
    _hasGMCS  = (typeof host.getModuleContainingSymbol === "function");
    _rStats   = { t1: 0, t2: 0, t3: 0, t4: 0 };
    buildModuleTable();
}

// Tier 1 — native data-model API (private PDBs)
function tier1(addr) {
    if (!_hasGMCS) return null;
    try {
        var sym = host.getModuleContainingSymbol(addr);
        if (sym) { var s = sym.toString(); if (s && s.indexOf("!") > 0) return s; }
    } catch (e) {}
    return null;
}

// Tier 2 — .printf "%y" (public + private PDBs, single clean line)
function tier2(addr) {
    try {
        var lines = _ctl.ExecuteCommand('.printf "%y", 0x' + addr.toString(16));
        for (var line of lines) {
            var s = line.toString().trim();
            if (!s || s.indexOf("!") < 0) continue;
            var p = s.indexOf("+0x"); if (p > 0) s = s.substring(0, p);
            return s;
        }
    } catch (e) {}
    return null;
}

// Tier 3 — module-range binary search (no symbols needed → module+0xRVA)
function tier3(addr) {
    var m = findModule(addr);
    return m ? m.name + "+0x" + m.offset.toString(16) : null;
}

function resolveSymbol(addr) {
    if (addr === undefined || addr === null) return "<unknown>";
    var hex = addr.toString(16);
    if (_symCache[hex] !== undefined) return _symCache[hex];

    var r;
    r = tier1(addr); if (r) { _rStats.t1++; _symCache[hex] = r; return r; }
    r = tier2(addr); if (r) { _rStats.t2++; _symCache[hex] = r; return r; }
    r = tier3(addr); if (r) { _rStats.t3++; _symCache[hex] = r; return r; }

    _rStats.t4++;
    r = "0x" + hex;
    _symCache[hex] = r;
    return r;
}

// ═══════════════════════════════════════════════════════════════════════════
//  DATA COLLECTION — batch-unique: collect → resolve → map
// ═══════════════════════════════════════════════════════════════════════════

function gatherPairs(pattern, pairMap, stats) {
    var calls;
    try { calls = host.currentSession.TTD.Calls(pattern); }
    catch (e) {
        host.diagnostics.debugLog("  [!] TTD.Calls('" + pattern + "') failed: "
                                  + e.message + "\n");
        return;
    }

    // Pass 1 — collect raw tuples + unique return addresses
    var raw = [], uniq = {};
    for (var call of calls) {
        var callee = "";
        try { callee = call.Function; } catch (e) {}
        if (!callee || callee.length === 0) {
            try { callee = resolveSymbol(call.FunctionAddress); }
            catch (e2) { callee = "<unknown_callee>"; }
        }
        var ret = null;
        try { ret = call.ReturnAddress; } catch (e) {}
        raw.push({ callee: callee, ret: ret });
        if (ret !== null && ret !== undefined)
            uniq[ret.toString(16)] = ret;
        if (raw.length % 5000 === 0)
            host.diagnostics.debugLog("    … " + raw.length + " calls collected\n");
    }

    // Pass 2 — batch-resolve unique return addresses (each resolved once)
    var keys = Object.keys(uniq);
    host.diagnostics.debugLog("    → " + raw.length + " calls, "
                              + keys.length + " unique return addrs\n");
    for (var i = 0; i < keys.length; i++) {
        resolveSymbol(uniq[keys[i]]);
        if ((i + 1) % 500 === 0)
            host.diagnostics.debugLog("    … " + (i + 1) + "/"
                                      + keys.length + " resolved\n");
    }

    // Pass 3 — accumulate caller→callee (all cache hits, O(1))
    for (var j = 0; j < raw.length; j++) {
        var rc     = raw[j];
        var caller = "<unknown_caller>";
        if (rc.ret !== null && rc.ret !== undefined)
            caller = resolveSymbol(rc.ret);
        var key = caller + " -> " + rc.callee;
        pairMap[key] = (pairMap[key] || 0) + 1;
    }
    stats.totalCalls += raw.length;
}

function allModulePatterns() {
    var names = [];
    for (var mod of host.currentProcess.Modules) {
        var n   = mod.Name.toString();
        var sep = Math.max(n.lastIndexOf("\\"), n.lastIndexOf("/"));
        if (sep >= 0) n = n.substring(sep + 1);
        var dot = n.lastIndexOf("."); if (dot >= 0) n = n.substring(0, dot);
        names.push(n + "!*");
    }
    return names;
}

// ═══════════════════════════════════════════════════════════════════════════
//  GEXF BUILDER
// ═══════════════════════════════════════════════════════════════════════════

function xmlEsc(s) {
    if (!s) return "";
    return s.replace(/&/g, "&amp;").replace(/</g, "&lt;")
            .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function modOf(label) {
    var i = label.indexOf("!");
    if (i > 0) return label.substring(0, i);
    if (label.indexOf("+0x") > 0) return label.split("+")[0];
    return "unknown";
}

function isoToday() {
    try   { return new Date().toISOString().substring(0, 10); }
    catch (e) { return "2026-01-01"; }
}

/**
 * Build a GEXF 1.2 XML string from the pair map.
 * @param {object} pairMap   key="caller -> callee", value=count
 * @param {number} topN      keep only top-N edges by weight (0 = all)
 * @returns {string}         complete GEXF XML
 */
function buildGEXF(pairMap, topN) {

    // ── Build edge list (optionally pruned to top-N) ──
    var edges = [];
    for (var key in pairMap) {
        if (!pairMap.hasOwnProperty(key)) continue;
        var parts = key.split(" -> ");
        edges.push({ caller: parts[0], callee: parts[1], w: pairMap[key] });
    }
    if (topN > 0 && topN < edges.length) {
        edges.sort(function (a, b) { return b.w - a.w; });
        edges = edges.slice(0, topN);
    }

    // ── Derive node set from surviving edges ──
    var nodes = {};  // label → { id, inC, outC }
    var nid   = 0;
    for (var i = 0; i < edges.length; i++) {
        var e = edges[i];
        if (!(e.caller in nodes)) nodes[e.caller] = { id: nid++, inC: 0, outC: 0 };
        if (!(e.callee in nodes)) nodes[e.callee] = { id: nid++, inC: 0, outC: 0 };
        nodes[e.caller].outC += e.w;
        nodes[e.callee].inC  += e.w;
    }

    // ── Emit GEXF 1.2 XML ──
    var x = [];
    x.push('<?xml version="1.0" encoding="UTF-8"?>');
    x.push('<gexf xmlns="http://gexf.net/1.2" version="1.2">');
    x.push('  <meta lastmodifieddate="' + isoToday() + '">');
    x.push('    <creator>CallerCalleeGraph.js (WinDbg TTD)</creator>');
    x.push('    <description>Caller-Callee call graph from TTD trace</description>');
    x.push('  </meta>');
    x.push('  <graph defaultedgetype="directed" mode="static">');

    // — node attributes —
    x.push('    <attributes class="node">');
    x.push('      <attribute id="0" title="module"   type="string"/>');
    x.push('      <attribute id="1" title="inCalls"  type="integer"/>');
    x.push('      <attribute id="2" title="outCalls" type="integer"/>');
    x.push('    </attributes>');

    // — edge attributes —
    x.push('    <attributes class="edge">');
    x.push('      <attribute id="0" title="callCount" type="integer"/>');
    x.push('    </attributes>');

    // — nodes —
    x.push('    <nodes>');
    for (var label in nodes) {
        if (!nodes.hasOwnProperty(label)) continue;
        var n = nodes[label];
        x.push('      <node id="' + n.id + '" label="' + xmlEsc(label) + '">');
        x.push('        <attvalues>');
        x.push('          <attvalue for="0" value="' + xmlEsc(modOf(label)) + '"/>');
        x.push('          <attvalue for="1" value="' + n.inC + '"/>');
        x.push('          <attvalue for="2" value="' + n.outC + '"/>');
        x.push('        </attvalues>');
        x.push('      </node>');
    }
    x.push('    </nodes>');

    // — edges: one per unique caller→callee pair —
    x.push('    <edges>');
    for (var j = 0; j < edges.length; j++) {
        var ed = edges[j];
        x.push('      <edge id="' + j
               + '" source="' + nodes[ed.caller].id
               + '" target="' + nodes[ed.callee].id
               + '" weight="' + ed.w + '.0">');
        x.push('        <attvalues>');
        x.push('          <attvalue for="0" value="' + ed.w + '"/>');
        x.push('        </attvalues>');
        x.push('      </edge>');
    }
    x.push('    </edges>');

    x.push('  </graph>');
    x.push('</gexf>');
    return x.join("\n");
}

// ═══════════════════════════════════════════════════════════════════════════
//  FILE WRITING — Debugger.Utility.FileSystem with .logopen fallback
// ═══════════════════════════════════════════════════════════════════════════

function writeFile(filePath, content) {
    // ── Primary: FileSystem API (clean, no noise) ──
    try {
        var fs = host.namespace.Debugger.Utility.FileSystem;
        var file;

        try { file = fs.CreateFile(filePath, "CreateAlways"); }
        catch (e) {
            try { if (fs.FileExists(filePath)) fs.DeleteFile(filePath); } catch (e2) {}
            file = fs.CreateFile(filePath);
        }

        var writer;
        try      { writer = fs.CreateTextWriter(file, "Utf8");  }
        catch (e) {
            try      { writer = fs.CreateTextWriter(file, "Ascii"); }
            catch (e2) { writer = fs.CreateTextWriter(file);        }
        }

        try {
            var lines = content.split("\n");
            for (var i = 0; i < lines.length; i++)
                writer.WriteLine(lines[i]);
        } finally { file.Close(); }

        return;

    } catch (outerEx) {
        host.diagnostics.debugLog(
            "    [!] FileSystem API failed (" + outerEx.message
            + "), falling back to .logopen\n");
    }

    // ── Fallback: .logopen / .logclose (adds 2 noise lines) ──
    _ctl.ExecuteCommand('.logopen "' + filePath + '"');
    host.diagnostics.debugLog(content);
    _ctl.ExecuteCommand('.logclose');
    host.diagnostics.debugLog(
        "    [!] Remove the first and last line from " + filePath + "\n"
        + "        PowerShell one-liner:\n"
        + '        $l=gc "' + filePath + '";$l[1..($l.Length-2)]|sc "' + filePath + '"\n');
}

// ═══════════════════════════════════════════════════════════════════════════
//  DISPLAY HELPERS
// ═══════════════════════════════════════════════════════════════════════════

function padR(s, n) { while (s.length < n) s += " "; return s; }

function logStats() {
    host.diagnostics.debugLog(
        "    Resolution: T1(API)=" + _rStats.t1
        + "  T2(printf)=" + _rStats.t2
        + "  T3(module)=" + _rStats.t3
        + "  T4(hex)=" + _rStats.t4 + "\n");
}

function logStatsBox() {
    host.diagnostics.debugLog("║  T1 getModuleContainingSymbol : " + padR("" + _rStats.t1, 25) + "║\n");
    host.diagnostics.debugLog("║  T2 .printf \"%y\"              : " + padR("" + _rStats.t2, 25) + "║\n");
    host.diagnostics.debugLog("║  T3 module range lookup       : " + padR("" + _rStats.t3, 25) + "║\n");
    host.diagnostics.debugLog("║  T4 raw hex fallback          : " + padR("" + _rStats.t4, 25) + "║\n");
}

// ═══════════════════════════════════════════════════════════════════════════
//  PUBLIC API — GEXF EXPORT
// ═══════════════════════════════════════════════════════════════════════════

function exportGEXF(pattern, filePath) {
    if (!pattern) {
        host.diagnostics.debugLog(
            'Usage: !exportGEXF "module!*" "C:\\\\temp\\\\graph.gexf"\n');
        return;
    }
    if (!filePath) filePath = "C:\\temp\\callgraph.gexf";

    initResolver();
    var pairMap = {}, stats = { totalCalls: 0 };

    host.diagnostics.debugLog("[*] Querying: " + pattern + "\n");
    gatherPairs(pattern, pairMap, stats);

    var ec = Object.keys(pairMap).length;
    host.diagnostics.debugLog("[*] " + stats.totalCalls + " calls → " + ec + " unique edges\n");
    logStats();

    var gexf = buildGEXF(pairMap, 0);
    host.diagnostics.debugLog("[*] Writing GEXF to: " + filePath + "\n");
    writeFile(filePath, gexf);
    host.diagnostics.debugLog("[✓] Done → open at https://gephi.org/gephi-lite/\n");
}

function exportAllGEXF(filePath, topN) {
    if (!filePath) filePath = "C:\\temp\\callgraph.gexf";

    initResolver();
    var pairMap = {}, stats = { totalCalls: 0 };
    var pats = allModulePatterns();

    host.diagnostics.debugLog("[*] " + pats.length + " modules. Querying…\n");
    for (var i = 0; i < pats.length; i++) {
        host.diagnostics.debugLog("[" + (i + 1) + "/" + pats.length + "] " + pats[i] + "\n");
        gatherPairs(pats[i], pairMap, stats);
    }

    var ec = Object.keys(pairMap).length;
    host.diagnostics.debugLog("[*] " + stats.totalCalls + " calls → " + ec + " unique edges\n");
    logStats();

    var gexf = buildGEXF(pairMap, topN || 0);
    host.diagnostics.debugLog("[*] Writing GEXF to: " + filePath + "\n");
    writeFile(filePath, gexf);
    host.diagnostics.debugLog("[✓] Done → open at https://gephi.org/gephi-lite/\n");
}

// ═══════════════════════════════════════════════════════════════════════════
//  PUBLIC API — HUMAN-READABLE (console output)
// ═══════════════════════════════════════════════════════════════════════════

function analyzePattern(pattern) {
    if (!pattern || pattern.length === 0) {
        host.diagnostics.debugLog('Usage: !callerCallee "module!pattern"\n');
        return;
    }
    initResolver();
    var pairMap = {}, stats = { totalCalls: 0 };
    host.diagnostics.debugLog("[*] Querying: " + pattern + "\n");
    gatherPairs(pattern, pairMap, stats);
    return printResults(pairMap, stats, 0);
}

function analyzeAllModules(topN) {
    initResolver();
    var pairMap = {}, stats = { totalCalls: 0 };
    var pats = allModulePatterns();
    host.diagnostics.debugLog("[*] " + pats.length + " modules. Querying…\n");
    for (var i = 0; i < pats.length; i++) {
        host.diagnostics.debugLog("[" + (i + 1) + "/" + pats.length + "] " + pats[i] + "\n");
        gatherPairs(pats[i], pairMap, stats);
    }
    return printResults(pairMap, stats, topN || 0);
}

function printResults(pairMap, stats, topN) {
    var pairs = [];
    for (var k in pairMap)
        if (pairMap.hasOwnProperty(k))
            pairs.push({ pair: k, count: pairMap[k] });
    pairs.sort(function (a, b) { return b.count - a.count; });

    var total = pairs.length;
    if (topN > 0 && topN < pairs.length) pairs = pairs.slice(0, topN);

    host.diagnostics.debugLog("\n╔══════════════════════════════════════════════════════════╗\n");
    host.diagnostics.debugLog("║  Total calls  : " + padR("" + stats.totalCalls, 39) + "║\n");
    host.diagnostics.debugLog("║  Unique pairs : " + padR("" + total, 39) + "║\n");
    if (topN > 0)
        host.diagnostics.debugLog("║  Showing top  : " + padR("" + pairs.length, 39) + "║\n");
    host.diagnostics.debugLog("╠══════════════════════════════════════════════════════════╣\n");
    logStatsBox();
    host.diagnostics.debugLog("╚══════════════════════════════════════════════════════════╝\n\n");

    host.diagnostics.debugLog(padR("Count", 10) + "Caller  →  Callee\n");
    host.diagnostics.debugLog(padR("─────", 10) + "──────────────────────────────────────\n");
    for (var i = 0; i < pairs.length; i++)
        host.diagnostics.debugLog(padR("" + pairs[i].count, 10) + pairs[i].pair + "\n");
    host.diagnostics.debugLog("\n");
    return pairs;
}
