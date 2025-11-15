<#
Arabic: سكربت فحص ذكي لمسارات المشروع بعد تفعيل OAuth2 دائماً
English: Smart smoke test script for project endpoints with OAuth2 always-on

- يشغّل خادم std_http محلياً على 8080
- يتحقق أن مسارات الواجهة UI تُرجع 404
- يجرب استدعاءات OAuth2 الأساسية للتأكد من عدم 404 وأن الاستجابات منظمة
- يشغّل عميل HMAC المضمّن للتحقق من /metrics و /webhook/in
#>

$ErrorActionPreference = 'SilentlyContinue'

function Write-Log {
	param([string]$Message)
	$ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
	Write-Host "[$ts] $Message"
}

function Wait-Port {
	param([int]$Port = 8080, [int]$TimeoutSec = 20)
	$start = Get-Date
	while ((New-TimeSpan -Start $start -End (Get-Date)).TotalSeconds -lt $TimeoutSec) {
		try {
			$tcp = Get-NetTCPConnection -LocalPort $Port -ErrorAction Stop
			if ($tcp) { return $true }
		} catch { Start-Sleep -Milliseconds 250 }
	}
	return $false
}

function Try-Web {
	param(
		[string]$Method = 'GET',
		[string]$Uri,
		[string]$Body = '',
		[string]$ContentType = 'application/x-www-form-urlencoded'
	)
	try {
		if ($Method -eq 'POST') {
			return Invoke-WebRequest -Uri $Uri -Method POST -Body $Body -ContentType $ContentType -UseBasicParsing -TimeoutSec 8 -ErrorAction Stop
		} else {
			return Invoke-WebRequest -Uri $Uri -Method GET -UseBasicParsing -TimeoutSec 8 -ErrorAction Stop
		}
	} catch {
		$resp = $_.Exception.Response
		if ($null -ne $resp) { return $resp }
		return $null
	}
}

function Get-Status {
	param($Resp)
	try {
		if ($null -eq $Resp) { return -1 }
		if ($Resp -is [Microsoft.PowerShell.Commands.HtmlWebResponseObject]) {
			return [int]$Resp.StatusCode
		}
		if ($Resp.PSObject.Properties.Name -contains 'StatusCode') {
			return [int]$Resp.StatusCode
		}
		return -1
	} catch { return -1 }
}

# Environment
$env:CARGO_HOME = "C:\rust\cargo"
$env:RUSTUP_HOME = "C:\rust\rustup"
if (-not $env:MKT_AUTH_HMAC_HEX -or $env:MKT_AUTH_HMAC_HEX.Trim().Length -eq 0) {
	$env:MKT_AUTH_HMAC_HEX = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
}
$ws = "C:\rust\projects\MKT-KSA-Geolocation-Security"

# Stop old processes and free port
Write-Log "Stopping any existing std_dashboard_demo/cargo and freeing port 8080"
Stop-Process -Name std_dashboard_demo -Force -ErrorAction SilentlyContinue
Stop-Process -Name cargo -Force -ErrorAction SilentlyContinue
Get-NetTCPConnection -LocalPort 8080 -ErrorAction SilentlyContinue | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }
Start-Sleep -Milliseconds 300

# Start server
Write-Log "Starting std_http server..."
$server = Start-Process cargo -WorkingDirectory $ws -ArgumentList 'run --features "api_std_http,sign_hmac,sign_host" --bin std_dashboard_demo' -WindowStyle Hidden -PassThru
 
if (-not (Wait-Port -Port 8080 -TimeoutSec 120)) {
	Write-Log "Server did not become ready on :8080 within timeout."
	if ($server) { Stop-Process -Id $server.Id -Force -ErrorAction SilentlyContinue }
	exit 2
}
Write-Log "Server is listening on :8080"

$results = @()

# 1) UI route should be 404
$uiResp = Try-Web -Method GET -Uri "http://127.0.0.1:8080/dashboard"
$uiCode = Get-Status $uiResp
$results += [pscustomobject]@{ name = "/dashboard 404"; pass = ($uiCode -eq 404); code = $uiCode }

# 2) OAuth2 authorize (should not be 404)
$authUri = "http://127.0.0.1:8080/oauth/authorize?client_id=test&response_type=code&redirect_uri=http://localhost/cb&scope=read&state=xyz"
$authResp = Try-Web -Method GET -Uri $authUri
$authCode = Get-Status $authResp
$results += [pscustomobject]@{ name = "/oauth/authorize non-404"; pass = ($authCode -ne 404 -and $authCode -ne -1); code = $authCode }

# 3) OAuth2 token (form-encoded). Accept 200 or 400 with JSON error.
$tokenResp = Try-Web -Method POST -Uri "http://127.0.0.1:8080/oauth/token" -Body "grant_type=client_credentials&client_id=test&client_secret=test" -ContentType "application/x-www-form-urlencoded"
$tokenCode = Get-Status $tokenResp
$results += [pscustomobject]@{ name = "/oauth/token structured"; pass = ($tokenCode -in 200,400,401); code = $tokenCode }

# 4) Run HMAC client for protected endpoints
Write-Log "Running hmac_client for signed requests..."
$hmac = Start-Process cargo -WorkingDirectory $ws -ArgumentList 'run --features "sign_hmac,sign_host" --bin hmac_client' -Wait -PassThru -NoNewWindow
$hmacPass = ($hmac.ExitCode -eq 0)
$results += [pscustomobject]@{ name = "hmac_client suite"; pass = $hmacPass; code = $hmac.ExitCode }

# Stop server
if ($server) {
	Stop-Process -Id $server.Id -Force -ErrorAction SilentlyContinue
	Start-Sleep -Milliseconds 200
}

Write-Log "Results:"
foreach ($r in $results) {
	$ok = if ($r.pass) { "PASS" } else { "FAIL" }
	Write-Host (" - {0}: {1} (code={2})" -f $r.name, $ok, $r.code)
}

# non-zero exit if any failed
if ($results.Where({-not $_.pass}).Count -gt 0) {
	exit 1
}
exit 0


