const assert = require("node:assert/strict");
const fs = require("node:fs");
const Module = require("node:module");
const path = require("node:path");
const test = require("node:test");
const React = require("react");
const { renderToStaticMarkup } = require("react-dom/server");
const typescript = require("typescript");

// Compile the actual TSX component with the project's TypeScript compiler so
// these tests exercise the same renderer used by every audit stage.
const filename = path.resolve(__dirname, "../src/components/MarkdownReport.tsx");
const componentModule = new Module(filename, module);
componentModule.filename = filename;
componentModule.paths = Module._nodeModulePaths(path.dirname(filename));
const compiled = typescript.transpileModule(fs.readFileSync(filename, "utf8"), {
  compilerOptions: { module: typescript.ModuleKind.CommonJS, jsx: typescript.JsxEmit.ReactJSX, esModuleInterop: true },
});
componentModule._compile(compiled.outputText, filename);
const { default: MarkdownReport, normalizeMarkdownText } = componentModule.exports;

function render(content) {
  return renderToStaticMarkup(React.createElement(MarkdownReport, { content, compact: true }));
}

function textContent(html) {
  return html.replace(/<[^>]*>/g, "").replaceAll("&amp;", "&").replaceAll("&#x27;", "'").replaceAll("&gt;", ">").replaceAll("&lt;", "<");
}

function cells(html, tag) {
  return [...html.matchAll(new RegExp(`<${tag}\\b[^>]*>([\\s\\S]*?)<\\/${tag}>`, "g"))].map((match) => textContent(match[1]));
}

test("DNS stage displays its title and five matching columns", () => {
  const content = "## DNS Configuration & Infrastructure Matrix\n\n| Record Type | Subdomain / Name | Resolved Target / Data | TTL | Status |\n|---|---|---|---|---|\n| A (IPv4) | `leads.edu.pk` | `172.67.167.109` | 300s | Active |";
  const html = render(content);
  assert.match(html, /<h3\b[^>]*>.*DNS Configuration &amp; Infrastructure Matrix.*<\/h3>/);
  assert.deepEqual(cells(html, "th"), ["Record Type", "Subdomain / Name", "Resolved Target / Data", "TTL", "Status"]);
  assert.deepEqual(cells(html, "td"), ["A (IPv4)", "leads.edu.pk", "172.67.167.109", "300s", "Active"]);
  assert.doesNotMatch(textContent(html), /---|##|\*\*/);
  assert.match(html, /bg-emerald-500\/10/); // Existing status badge styling.
  assert.match(html, /bg-primary\/10/); // Existing code highlighting.
});

const stageTables = [
  ["Network reconnaissance", ["Intelligence Attribute", "Resolved Value", "Operational & Security Context"]],
  ["Perimeter ports", ["Port", "Protocol & Service", "Risk Level", "Status", "Exposure Analysis & Recommendation"]],
  ["Security headers", ["Security Header", "Policy / Value", "Category", "Severity", "Status", "Risk Assessment & Remediation"]],
  ["TLS certificates", ["Certificate Property", "Value", "Verification Status", "Trust Chain Context"]],
  ["Cookies", ["Cookie Name", "Security Attribute", "Status", "Recommendation"]],
  ["Endpoint discovery", ["Endpoint", "HTTP Status", "Risk", "Details"]],
  ["Authentication", ["Test", "Result", "Severity", "Evidence"]],
  ["Injection assessment", ["Parameter", "Payload", "Status", "Evidence"]],
  ["Rate limiting", ["Test Type", "Response", "Status", "Finding"]],
  ["Executive summary", ["Security Governance Metric", "Evaluated Result", "Benchmark Baseline", "Executive Evaluation"]],
];

for (const [title, headers] of stageTables) {
  test(`${title} headings stay aligned with their results`, () => {
    const values = headers.map((_, index) => `value ${index + 1}`);
    const content = `## ${title}\n\n| ${headers.join(" | ")} |\n|${headers.map(() => "---").join("|")}|\n| ${values.join(" | ")} |`;
    const html = render(content);
    assert.deepEqual(cells(html, "th"), headers);
    assert.deepEqual(cells(html, "td"), values);
    assert.doesNotMatch(textContent(html), /---|##/);
  });
}

test("multiple sections, escaped line breaks and pipes inside values retain their structure", () => {
  const content = "## First section\\n\\n| Name | Value | Status |\\n|---|---|---|\\n| Rule | `a|b` | Passed |\\n\\n## Second section\\n\\n| Name | Details |\\n|---|---|\\n| Policy | left \\| right |";
  const normalized = normalizeMarkdownText(content);
  assert.match(normalized, /First section\n\n\| Name/);
  const html = render(content);
  assert.deepEqual(cells(html, "th"), ["Name", "Value", "Status", "Name", "Details"]);
  assert.deepEqual(cells(html, "td"), ["Rule", "a|b", "Passed", "Policy", "left | right"]);
  assert.equal((html.match(/<table\b/g) || []).length, 2);
});

test("table headings from all ten report generators render above their corresponding columns", () => {
  const toolsDir = path.resolve(__dirname, "../../backend/app/devsecops/crew_tools/tools");
  const toolNames = [
    "cookie_security_analyzer.py", "cve_owasp_intelligence_analyzer.py",
    "deep_endpoint_directory_discovery_tool.py", "dns_ip_recon_tool.py",
    "executive_security_report_generator.py", "http_security_headers_inspector.py",
    "metadata_information_disclosure_extractor.py", "rate_limiting_dos_resilience_tester.py",
    "shodan_port_service_lookup.py", "ssl_tls_certificate_inspector.py",
  ];
  let checked = 0;
  for (const name of toolNames) {
    const source = fs.readFileSync(path.join(toolsDir, name), "utf8");
    const headers = [...source.matchAll(/(?:lines|sections)\.append\("(\|[^"\n]*\|)"\)\s*(?:lines|sections)\.append\("(\|[-|:\s]+\|)"\)/g)];
    assert.ok(headers.length > 0, `No table headings found in ${name}`);
    for (const [, header, separator] of headers) {
      const expected = header.split("|").slice(1, -1).map((cell) => cell.trim());
      const values = expected.map((_, index) => `result ${index + 1}`);
      const html = render(`## Stage results\n\n${header}\n${separator}\n| ${values.join(" | ")} |`);
      assert.deepEqual(cells(html, "th"), expected, name);
      assert.deepEqual(cells(html, "td"), values, name);
      checked++;
    }
  }
  assert.ok(checked >= 50);
});
