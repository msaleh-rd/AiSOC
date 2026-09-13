# Probes every web route over both localhost (::1) and 127.0.0.1
$routes = @(
  "/", "/costs",
  "/admin/tenants", "/admin/waitlist",
  "/alerts", "/analytics/team", "/audit", "/cases", "/compliance",
  "/compliance/soc2", "/connectors", "/copilot", "/coverage-advisor",
  "/dashboard", "/dashboards/soc-insights",
  "/detection", "/detection/catalog", "/detection/coverage", "/detection/new",
  "/detection/proposals", "/detection/tuning",
  "/easm", "/explore", "/fim", "/graph", "/honeytokens", "/hunt",
  "/identity/permissions", "/investigate", "/marketplace", "/mssp",
  "/noise-tuning", "/onboarding", "/playbooks", "/purple-team", "/queue",
  "/reports/digest", "/settings", "/settings/business-context", "/settings/rbac",
  "/shifts", "/sla", "/threat-intel",
  "/about", "/blog", "/contact", "/customers", "/mesh", "/press",
  "/privacy", "/sovereign", "/terms", "/waitlist",
  "/responder", "/responder/approvals", "/responder/case", "/responder/login",
  "/responder/oncall", "/responder/settings", "/responder/triage",
  "/tools", "/tools/coverage", "/tools/nl2sigma", "/tools/noise", "/tools/translate",
  "/benchmark", "/login", "/why-open-source",
  # dynamic routes with real IDs
  "/cases/d66639e0-9761-4140-a3bb-59edbd3643c4"
)

$fails = @()
foreach ($host_ in @("127.0.0.1", "localhost")) {
  foreach ($r in $routes) {
    try {
      $resp = Invoke-WebRequest -Uri "http://${host_}:3000$r" -UseBasicParsing -MaximumRedirection 5 -TimeoutSec 30
      if ($resp.StatusCode -ne 200) { $fails += "${host_} $r -> $($resp.StatusCode)" }
    } catch {
      $code = $_.Exception.Response.StatusCode.value__
      $fails += "${host_} $r -> $(if ($code) { $code } else { $_.Exception.Message })"
    }
  }
  Write-Host "Done: $host_"
}

if ($fails.Count -eq 0) {
  Write-Host "ALL $($routes.Count * 2) probes returned 200 OK"
} else {
  Write-Host "FAILURES ($($fails.Count)):"
  $fails | ForEach-Object { Write-Host "  $_" }
}
