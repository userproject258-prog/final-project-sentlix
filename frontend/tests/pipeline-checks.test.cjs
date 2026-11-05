const assert = require("node:assert/strict");
const fs = require("node:fs");
const Module = require("node:module");
const path = require("node:path");
const test = require("node:test");
const React = require("react");
const { renderToStaticMarkup } = require("react-dom/server");
const typescript = require("typescript");

const filename = path.resolve(__dirname, "../src/components/PipelineChecks.tsx");
const componentModule = new Module(filename, module);
componentModule.filename = filename;
componentModule.paths = Module._nodeModulePaths(path.dirname(filename));
componentModule._compile(typescript.transpileModule(fs.readFileSync(filename, "utf8"), {
  compilerOptions: { module: typescript.ModuleKind.CommonJS, jsx: typescript.JsxEmit.ReactJSX, esModuleInterop: true },
}).outputText, filename);
const { PipelineChecks, filterPipelineRuns } = componentModule.exports;

const runs = [
  { id: "RUN-123", time: "2026-11-05T12:00:00", branch: "main", commit_sha: "abcdef", developer: "analyst@example.test", status: "INCOMPLETE", sast_status: "WARNING", secret_status: "NOT RUN", dependency_status: "FAILED", container_status: "NOT RUN", details: { sast: { engine: "Bandit", loc_scanned: 42, high_issues: 0, medium_issues: 2, low_issues: 1 }, secrets: { engine: "gitleaks", reason: "Scanner is not installed" }, dependencies: { engine: "pip-audit", vulnerabilities: [{ package: "example", version: "1.0", id: "CVE-2025-0001", fix_versions: ["1.1"] }] } } },
  { id: "RUN-456", time: "2026-11-04T12:00:00Z", branch: "feature/test", commit_sha: "123456", developer: "ci", status: "PASSED", sast_status: "PASSED", secret_status: "PASSED", dependency_status: "PASSED", container_status: "PASSED", details: null },
];

function render(overrides = {}) {
  return renderToStaticMarkup(React.createElement(PipelineChecks, { runs, loading: false, loadError: false, manualStatus: {status: "idle", run_id: null, error: null}, manualStatusError: false, onRetry() {}, async onRun() {}, ...overrides }));
}

test("pipeline cards show actual scan details and missing information accurately", () => {
  const html = render();
  for (const value of ["RUN-123", "INCOMPLETE", "NOT RUN", "Scanner is not installed", "42 lines scanned", "CVE-2025-0001", "Fix versions: 1.1", "Detailed scanner results are unavailable", "not a built image", "Download run JSON"]) assert.ok(html.includes(value), value);
});

test("search and status filters combine across run metadata and check statuses", () => {
  assert.deepEqual(filterPipelineRuns(runs, " NOT RUN ", "INCOMPLETE").map((run) => run.id), ["RUN-123"]);
  assert.deepEqual(filterPipelineRuns(runs, "feature/test", "All").map((run) => run.id), ["RUN-456"]);
  assert.deepEqual(filterPipelineRuns(runs, "abcdef", "PASSED"), []);
});

test("loading, missing data, errors, and background progress are distinct", () => {
  assert.match(render({ runs: [], loading: true }), /Loading pipeline runs/);
  assert.match(render({ runs: [] }), /No pipeline runs recorded/);
  const error = render({ runs: [], loadError: true });
  assert.match(error, /Could not refresh pipeline runs/);
  assert.doesNotMatch(error, /No pipeline runs recorded/);
  const running = render({ manualStatus: { status: "running", run_id: null, error: null } });
  assert.match(running, /Running installed scanners/);
  assert.match(running, /disabled=""[^>]*>.*Running checks/);
  assert.match(render({ manualStatus: { status: "failed", run_id: null, error: "Checks failed" } }), /Checks failed/);
  assert.match(render({ manualStatusError: true }), /Could not check whether a manual scan is running/);
});
