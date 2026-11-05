const assert = require("node:assert/strict");
const fs = require("node:fs");
const Module = require("node:module");
const path = require("node:path");
const test = require("node:test");
const React = require("react");
const { renderToStaticMarkup } = require("react-dom/server");
const typescript = require("typescript");

const filename = path.resolve(__dirname, "../src/components/AuditObservations.tsx");
const componentModule = new Module(filename, module);
componentModule.filename = filename;
componentModule.paths = Module._nodeModulePaths(path.dirname(filename));
componentModule._compile(typescript.transpileModule(fs.readFileSync(filename, "utf8"), {
  compilerOptions: { module: typescript.ModuleKind.CommonJS, jsx: typescript.JsxEmit.ReactJSX, esModuleInterop: true },
}).outputText, filename);
const { AuditObservations, filterAuditFindings } = componentModule.exports;

const findings = [
  { id: "1", run_id: "run-one", time: "2026-11-05T12:00:00", target: "https://example.test", title: "Missing CSP", severity: "HIGH", evidence: "CSP header absent", recommendation: "Configure CSP", status: "Open" },
  { id: "2", run_id: "run-two", time: "2026-11-05T13:00:00Z", target: "https://other.test", title: "TLS expiry", severity: "MEDIUM", evidence: "Certificate expired", recommendation: "Renew certificate", status: "Resolved" },
];

function render(overrides = {}) {
  return renderToStaticMarkup(React.createElement(AuditObservations, {
    findings, loading: false, loadError: false, onRetry() {}, async onResolve() { return 1; }, ...overrides,
  }));
}

test("observation cards show evidence, recommendation, status, and the scope of resolution", () => {
  const html = render();
  for (const value of ["Missing CSP", "https://example.test", "HIGH", "Open", "CSP header absent", "Configure CSP", "Resolved", "same title and target across all runs", "run-one"]) {
    assert.ok(html.includes(value), value);
  }
  assert.equal((html.match(/Mark resolved for this target/g) || []).length, 1);
});

test("search and filters work together across targets, evidence, recommendations and runs", () => {
  assert.deepEqual(filterAuditFindings(findings, " CERTIFICATE ", "All", "All").map((item) => item.id), ["2"]);
  assert.deepEqual(filterAuditFindings(findings, "RUN-ONE", "Open", "HIGH").map((item) => item.id), ["1"]);
  assert.deepEqual(filterAuditFindings(findings, "", "Resolved", "HIGH"), []);
  assert.deepEqual(filterAuditFindings(findings, "example.test", "All", "All").map((item) => item.id), ["1"]);
});

test("loading, empty and failed states are distinct", () => {
  assert.match(render({ findings: [], loading: true }), /Loading observations/);
  assert.match(render({ findings: [] }), /No observations recorded yet/);
  const error = render({ findings: [], loadError: true });
  assert.match(error, /Could not refresh observations/);
  assert.doesNotMatch(error, /No observations recorded yet/);
  assert.match(render({ loadError: true }), /The list may be out of date/);
});
