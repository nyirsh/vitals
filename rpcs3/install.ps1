<# :
@echo off
rem vitals @VERSION@ for RPCS3 on Windows: double-click this file. It runs the PowerShell below,
rem which is the rest of this file up to its files (a .bat, so that no execution policy stops it)
setlocal
set "VITALS_SELF=%~f0"
set "VITALS_ARGS=%*"
powershell -NoProfile -ExecutionPolicy Bypass -Command "$t = [IO.File]::ReadAllText($env:VITALS_SELF); $i = $t.IndexOf([char]10 + '__VITALS_' + 'PAYLOAD__'); Invoke-Expression $t.Substring(0, $i)"
if errorlevel 1 pause
exit /b %errorlevel%
#>
# vitals @VERSION@ for RPCS3, on Windows: modern TLS (1.2 and 1.3) and host redirects for the games
# RPCS3 runs, by putting vitals' libssl and libhttp in RPCS3's dev_flash in place of Sony's, which it
# keeps to put back. Everything it installs is inside this file.
#
#   @NAME@                                  the menu (double-click it)
#   @NAME@ install|uninstall|status|certificates [-rpcs3 <folder>]
#
# RPCS3's folder is the one rpcs3.exe is in: this file's own folder when it's there, a running
# RPCS3's, or the one picked when asked. Made by rpcs3/make_installers.py from
# rpcs3/install.ps1: edit that, not a generated copy

$ErrorActionPreference = 'Stop'
$Version = '@VERSION@'
# Sony's CAs as vitals' libssl reads them (ps3/common/sony_cas.h): "file offset length", length 0
# for the whole file. Mozilla's certificates leave these out, as the PS3 app's install does
$SonyCas = @'
@SONY_CAS@
'@
$MozillaUrl = 'https://curl.se/ca/cacert.pem'
$Self = $env:VITALS_SELF
# The .bat's arguments, a quoted one kept whole
$Arguments = @([regex]::Matches([string]$env:VITALS_ARGS, '"[^"]*"|\S+') | ForEach-Object { $_.Value.Trim('"') })

$script:Rpcs3 = $null
$script:Flash = $null
$script:Hdd = $null
$script:Yaml = $null
$script:Payload = $null

function Say([string]$text) { Write-Host $text }
function Fail([string]$text) { Write-Host "Error: $text" -ForegroundColor Red; $false }
function Pause-Menu { if ([Environment]::UserInteractive) { [void](Read-Host "`nPress Enter to go back to the menu") } }

# ---- RPCS3's folders ----

function Test-Rpcs3([string]$dir) {
	$dir -and ((Test-Path -LiteralPath (Join-Path $dir 'rpcs3.exe')) -or (Test-Path -LiteralPath (Join-Path $dir 'dev_flash')) -or
		(Test-Path -LiteralPath (Join-Path $dir 'config.yml')) -or (Test-Path -LiteralPath (Join-Path $dir 'config\config.yml')))
}

function Get-VfsValue([string]$file, [string]$key) {
	foreach ($line in [IO.File]::ReadAllLines($file)) {
		if ($line.StartsWith("${key}:")) {
			$value = $line.Substring($key.Length + 1).Trim()
			if ($value.Length -ge 2 -and ($value[0] -eq '"' -or $value[0] -eq "'") -and $value[-1] -eq $value[0]) {
				$value = $value.Substring(1, $value.Length - 2)
			}
			return $value
		}
	}
	return ''
}

# dev_flash and dev_hdd0 where vfs.yml puts them, else in RPCS3's folder
function Find-Devices {
	$script:Flash = Join-Path $script:Rpcs3 'dev_flash'
	$script:Hdd = Join-Path $script:Rpcs3 'dev_hdd0'
	$script:Yaml = Join-Path $script:Rpcs3 'config.yml'
	if (Test-Path -LiteralPath (Join-Path $script:Rpcs3 'config\config.yml')) { $script:Yaml = Join-Path $script:Rpcs3 'config\config.yml' }
	$vfs = @((Join-Path $script:Rpcs3 'config\vfs.yml'), (Join-Path $script:Rpcs3 'vfs.yml')) |
		Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
	if (-not $vfs) { return }
	$emulator = Get-VfsValue $vfs '$(EmulatorDir)'
	if (-not $emulator) { $emulator = $script:Rpcs3.TrimEnd('\') + '\' }
	$value = Get-VfsValue $vfs '/dev_flash/'
	if ($value) { $script:Flash = $value.Replace('$(EmulatorDir)', $emulator).TrimEnd('/', '\') }
	$value = Get-VfsValue $vfs '/dev_hdd0/'
	if ($value) { $script:Hdd = $value.Replace('$(EmulatorDir)', $emulator).TrimEnd('/', '\') }
}

function Pick-Folder {
	try {
		Add-Type -AssemblyName System.Windows.Forms
		$dialog = New-Object System.Windows.Forms.FolderBrowserDialog
		$dialog.Description = "RPCS3's folder (the one rpcs3.exe is in)"
		if ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { return $dialog.SelectedPath }
	} catch { }
	return $null
}

function Find-Rpcs3([string]$given) {
	if ($given) {
		if (-not (Test-Rpcs3 $given)) { return (Fail "$given isn't RPCS3's folder (no rpcs3.exe or dev_flash in it)") }
		$script:Rpcs3 = $given.TrimEnd('\')
	} else {
		$candidates = @()
		if ($Self) { $candidates += Split-Path -Parent $Self }
		$candidates += Get-Process -Name rpcs3 -ErrorAction SilentlyContinue | ForEach-Object { try { Split-Path -Parent $_.Path } catch { } }
		$candidates += @("$env:USERPROFILE\Desktop\rpcs3", "$env:USERPROFILE\Downloads\rpcs3", 'C:\rpcs3', 'C:\RPCS3', "$env:USERPROFILE\rpcs3")
		$script:Rpcs3 = $candidates | Where-Object { Test-Rpcs3 $_ } | Select-Object -First 1
	}
	while (-not $script:Rpcs3) {
		Say "RPCS3's folder wasn't found. Pick it (the folder rpcs3.exe is in), or type its path."
		$answer = Read-Host 'Press Enter to pick it, type a path, or Q to quit'
		if ($answer -eq 'q' -or $answer -eq 'Q') { return $false }
		$dir = if ($answer) { $answer.Trim('"') } else { Pick-Folder }
		if (Test-Rpcs3 $dir) { $script:Rpcs3 = $dir.TrimEnd('\') } elseif ($dir) { Say "That isn't RPCS3's folder." }
	}
	Find-Devices
	return $true
}

function Test-Running { [bool](Get-Process -Name rpcs3 -ErrorAction SilentlyContinue) }

function Test-NetworkOff {
	(Test-Path -LiteralPath $script:Yaml) -and
		[bool](Select-String -LiteralPath $script:Yaml -Pattern '^\s*Internet enabled:\s*Disconnected' -Quiet)
}

# ---- what this file carries ----

function Open-Payload {
	if ($script:Payload) { return $true }
	try {
		$text = [IO.File]::ReadAllText($Self)
		$marker = [char]10 + '__VITALS_' + 'PAYLOAD__'
		$at = $text.IndexOf($marker)
		$data = [Convert]::FromBase64String(($text.Substring($at + $marker.Length) -replace '\s', ''))
		$dir = Join-Path ([IO.Path]::GetTempPath()) ('vitals-rpcs3-' + [Guid]::NewGuid().ToString('N'))
		[void](New-Item -ItemType Directory -Path $dir)
		$zip = Join-Path $dir 'payload.zip'
		[IO.File]::WriteAllBytes($zip, $data)
		Expand-Archive -LiteralPath $zip -DestinationPath $dir
		Remove-Item -LiteralPath $zip
		$script:Payload = $dir
		return $true
	} catch {
		return (Fail "this file's own files can't be read: download it again ($($_.Exception.Message))")
	}
}

function Close-Payload { if ($script:Payload) { Remove-Item -LiteralPath $script:Payload -Recurse -Force -ErrorAction SilentlyContinue } }

# ---- vitals' files in RPCS3 ----

function VitalsDir { Join-Path $script:Hdd 'vitals' }
function SystemDir { Join-Path (VitalsDir) 'system' }
function FlagsDir { Join-Path (VitalsDir) 'flags' }
function External([string]$name) { Join-Path $script:Flash "sys\external\$name" }

# vitals' builds are fake-signed SELFs (key revision 0x8000), Sony's never are
function Test-VitalsModule([string]$path) {
	if (-not (Test-Path -LiteralPath $path)) { return $false }
	$stream = [IO.File]::OpenRead($path)
	try { $bytes = New-Object byte[] 9; [void]$stream.Read($bytes, 0, 9); return $bytes[8] -eq 0x80 } finally { $stream.Close() }
}

function Get-InstalledVersion {
	$file = Join-Path (SystemDir) 'installed.txt'
	if (-not (Test-Path -LiteralPath $file)) { return '' }
	foreach ($line in [IO.File]::ReadAllLines($file)) { if ($line.StartsWith('version=')) { return $line.Substring(8) } }
	return ''
}

function Get-DebugLevel {
	if (Test-Path -LiteralPath (Join-Path (FlagsDir) 'debug.2')) { return 2 }
	if (Test-Path -LiteralPath (Join-Path (FlagsDir) 'debug.1')) { return 1 }
	return 0
}

function LevelName([int]$level) { switch ($level) { 1 { 'Basic debug' } 2 { 'Full debug' } default { 'Off' } } }
function BuildName([string]$module, [int]$level) { if ($level -eq 0) { "$module.sprx" } else { "$module-debug$level.sprx" } }
function Test-Flag([string]$name) { Test-Path -LiteralPath (Join-Path (FlagsDir) $name) }

function Set-Flag([string]$name, [bool]$on) {
	[void](New-Item -ItemType Directory -Force -Path (FlagsDir))
	$path = Join-Path (FlagsDir) $name
	if ($on) { [IO.File]::WriteAllBytes($path, @()) } elseif (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path }
}

# A copy that's never left half-written
function Put([string]$from, [string]$to) {
	$new = "$to.vitals-new"
	try {
		Copy-Item -LiteralPath $from -Destination $new -Force
		Move-Item -LiteralPath $new -Destination $to -Force
		return $true
	} catch {
		Remove-Item -LiteralPath $new -ErrorAction SilentlyContinue
		return (Fail "can't write $to ($($_.Exception.Message))")
	}
}

# Sony's libssl and libhttp, kept in system\sony before vitals' first take their place
function Keep-Sony {
	$sony = Join-Path (SystemDir) 'sony'
	[void](New-Item -ItemType Directory -Force -Path $sony)
	foreach ($name in 'libssl.sprx', 'libhttp.sprx') {
		$kept = Join-Path $sony $name
		$current = External $name
		if (Test-Path -LiteralPath $kept) { continue }
		if (-not (Test-Path -LiteralPath $current)) { return (Fail "RPCS3 has no ${name}: install the PS3 firmware in RPCS3 first") }
		if (Test-VitalsModule $current) {
			return (Fail "RPCS3's $name is already vitals' and Sony's isn't kept: reinstall the firmware in RPCS3, then vitals")
		}
		Copy-Item -LiteralPath $current -Destination $kept
		Say "Kept Sony's $name"
	}
	return $true
}

# dev_flash as the Options say: vitals' libssl unless TLS is off, vitals' libhttp unless HTTP is off
function Apply-Switches {
	$tls = Join-Path (SystemDir) 'libssl.sprx'
	$http = Join-Path (SystemDir) 'libhttp.sprx'
	if (Test-Flag 'tls.off') { $tls = Join-Path (SystemDir) 'sony\libssl.sprx' }
	if (Test-Flag 'http.off') { $http = Join-Path (SystemDir) 'sony\libhttp.sprx' }
	(Put $tls (External 'libssl.sprx')) -and (Put $http (External 'libhttp.sprx'))
}

function Copy-Builds([int]$level) {
	if (-not (Open-Payload)) { return $false }
	[void](New-Item -ItemType Directory -Force -Path (SystemDir), (FlagsDir))
	if (-not ((Put (Join-Path $script:Payload (BuildName 'libssl' $level)) (Join-Path (SystemDir) 'libssl.sprx')) -and
			(Put (Join-Path $script:Payload (BuildName 'libhttp' $level)) (Join-Path (SystemDir) 'libhttp.sprx')))) { return $false }
	Set-Flag 'debug.1' $false
	Set-Flag 'debug.2' $false
	if ($level -ne 0) { Set-Flag "debug.$level" $true }
	Say "Debug output: $(LevelName $level)"
	return $true
}

# A certificate block's base64, whatever its line breaks
function Get-Body([string]$text) { $text -replace '[^A-Za-z0-9+/=]', '' }

# Sony's CAs, as RPCS3's flash has them: each certificate's base64
function Get-SonyBodies {
	$bodies = New-Object 'System.Collections.Generic.HashSet[string]'
	foreach ($line in ($SonyCas -split "`r?`n")) {
		$parts = $line.Trim() -split '\s+'
		if ($parts.Count -ne 3) { continue }
		$path = Join-Path $script:Flash "data\cert\$($parts[0])"
		if (-not (Test-Path -LiteralPath $path)) { continue }
		$bytes = [IO.File]::ReadAllBytes($path)
		$offset = [int]$parts[1]; $length = [int]$parts[2]
		if ($length -eq 0) { $offset = 0; $length = $bytes.Length }
		if ($offset + $length -gt $bytes.Length) { continue }
		$text = [Text.Encoding]::ASCII.GetString($bytes, $offset, $length)
		foreach ($match in [regex]::Matches($text, '-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----')) {
			[void]$bodies.Add((Get-Body $match.Groups[1].Value))
		}
	}
	return ,$bodies
}

# Mozilla's bundle without the certificates Sony's list has: the PS3 app's store_certs.c, on whole
# certificate blocks matched by their base64
function Write-Mozilla([string]$from, [string]$to) {
	$sony = Get-SonyBodies
	$kept = 0; $left = 0
	$out = New-Object Text.StringBuilder
	$block = $null; $body = ''
	foreach ($line in [IO.File]::ReadAllLines($from)) {
		if ($line.StartsWith('-----BEGIN CERTIFICATE-----')) { $block = New-Object Text.StringBuilder; [void]$block.Append($line + "`n"); $body = ''; continue }
		if ($null -ne $block) {
			[void]$block.Append($line + "`n")
			if ($line.StartsWith('-----END CERTIFICATE-----')) {
				if ($sony.Contains((Get-Body $body))) { $left++ } else { [void]$out.Append($block.ToString()); $kept++ }
				$block = $null
			} else { $body += $line }
			continue
		}
		[void]$out.Append($line + "`n")
	}
	if ($null -ne $block) { [void]$out.Append($block.ToString()) }
	try {
		[IO.File]::WriteAllText("$to.vitals-new", $out.ToString(), (New-Object Text.UTF8Encoding $false))
		Move-Item -LiteralPath "$to.vitals-new" -Destination $to -Force
	} catch { return (Fail "can't write $to") }
	Say "Mozilla's certificates: $kept, and $left Sony's already has left out"
	return $true
}

# ---- what the menu does ----

function Install-Vitals {
	$version = Get-InstalledVersion
	if (Test-Running) { return (Fail 'RPCS3 is running: close it first') }
	if (-not (Test-Path -LiteralPath (External 'libssl.sprx'))) { return (Fail 'RPCS3 has no firmware: install it first (File, Install Firmware)') }
	if (-not (Open-Payload)) { return $false }
	[void](New-Item -ItemType Directory -Force -Path (SystemDir), (FlagsDir), (Join-Path (VitalsDir) 'logs'))
	if (-not (Keep-Sony)) { return $false }
	if (-not (Copy-Builds (Get-DebugLevel))) { return $false }
	$bundle = Join-Path (SystemDir) 'mozilla-certs.pem'
	if (Test-Path -LiteralPath $bundle) { Say "Kept Mozilla's certificates already in $bundle" }
	elseif (-not (Write-Mozilla (Join-Path $script:Payload 'cacert.pem') $bundle)) { return $false }
	$redirects = Join-Path (VitalsDir) 'redirects.txt'
	if (Test-Path -LiteralPath $redirects) { Say "Kept $redirects" }
	else { Copy-Item -LiteralPath (Join-Path $script:Payload 'redirects.txt') -Destination $redirects; Say "Wrote the example $redirects" }
	if (-not (Apply-Switches)) { return $false }
	[IO.File]::WriteAllText((Join-Path (SystemDir) 'installed.txt'), "version=$Version`n")
	Remove-Item -LiteralPath (Join-Path (VitalsDir) 'logs\vitals.log') -ErrorAction SilentlyContinue
	if (-not $version) { Say "vitals $Version installed" }
	elseif ($version -eq $Version) { Say "vitals $Version reinstalled" }
	else { Say "vitals $version replaced with $Version" }
	if (Test-NetworkOff) { Say "Note: RPCS3's network is off (Configuration, Network, Network Status: Connected)" }
	return $true
}

function Uninstall-Vitals {
	if (Test-Running) { return (Fail 'RPCS3 is running: close it first') }
	foreach ($name in 'libssl.sprx', 'libhttp.sprx') {
		$kept = Join-Path (SystemDir) "sony\$name"
		if (Test-Path -LiteralPath $kept) {
			if (-not (Put $kept (External $name))) { return $false }
			Say "Put Sony's $name back"
		} elseif (Test-VitalsModule (External $name)) {
			Say "Sony's $name isn't kept: reinstall the firmware in RPCS3 to get it back"
		}
	}
	foreach ($file in 'system\sony\libssl.sprx', 'system\sony\libhttp.sprx', 'system\libssl.sprx', 'system\libhttp.sprx',
		'system\mozilla-certs.pem', 'system\installed.txt', 'flags\debug.1', 'flags\debug.2', 'logs\vitals.log', 'logs\vitals-app.log') {
		Remove-Item -LiteralPath (Join-Path (VitalsDir) $file) -ErrorAction SilentlyContinue
	}
	# The user's lists and the Options' switches stay, as the app leaves them
	foreach ($dir in 'system\sony', 'system', 'logs', 'flags', '') {
		$path = if ($dir) { Join-Path (VitalsDir) $dir } else { VitalsDir }
		if ((Test-Path -LiteralPath $path) -and -not (Get-ChildItem -LiteralPath $path -Force)) { Remove-Item -LiteralPath $path }
	}
	Say 'vitals uninstalled'
	return $true
}

function Update-Certificates {
	$download = [IO.Path]::GetTempFileName()
	try {
		Say "Downloading Mozilla's certificates from $MozillaUrl..."
		[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
		Invoke-WebRequest -UseBasicParsing -Uri $MozillaUrl -OutFile $download
		$content = (Invoke-WebRequest -UseBasicParsing -Uri "$MozillaUrl.sha256").Content
		if ($content -is [byte[]]) { $content = [Text.Encoding]::ASCII.GetString($content) }
		$expected = ($content.Trim() -split '\s+')[0]
		$actual = (Get-FileHash -LiteralPath $download -Algorithm SHA256).Hash
		$count = (Select-String -LiteralPath $download -Pattern 'BEGIN CERTIFICATE').Count
		if ($actual -ne $expected.Trim().ToUpper() -or $count -lt 100) {
			return (Fail "the download doesn't match curl's checksum: the certificates weren't changed")
		}
		[void](New-Item -ItemType Directory -Force -Path (SystemDir))
		$to = Join-Path (SystemDir) 'mozilla-certs.pem'
		if (Write-Mozilla $download $to) { Say "Written to $to"; return $true }
		return $false
	} catch {
		return (Fail "the download failed: the certificates weren't changed ($($_.Exception.Message))")
	} finally {
		Remove-Item -LiteralPath $download -ErrorAction SilentlyContinue
	}
}

function Get-CertificatesDate {
	$file = Join-Path (SystemDir) 'mozilla-certs.pem'
	if (Test-Path -LiteralPath $file) { (Get-Item -LiteralPath $file).LastWriteTime.ToString('yyyy-MM-dd') } else { '' }
}

function Get-StatusLine {
	$version = Get-InstalledVersion
	if (-not $version) { return 'not installed' }
	if (-not (Test-Flag 'tls.off') -and -not (Test-VitalsModule (External 'libssl.sprx'))) {
		return "$version, but RPCS3's libssl is Sony's again (a firmware reinstall?): Reinstall"
	}
	return "$version installed, debug output $(LevelName (Get-DebugLevel))"
}

function TlsState { if (Test-Flag 'tls.off') { 'Off (Sony TLS)' } else { 'On (vitals TLS)' } }
function HttpState {
	if (Test-Flag 'http.off') { 'Off (Sony HTTP, no redirects)' }
	elseif (Test-Flag 'redirects.off') { 'Redirects off (vitals HTTP)' }
	else { 'On (vitals HTTP and redirects)' }
}

function Show-Status {
	Say "RPCS3: $($script:Rpcs3)"
	Say "dev_flash: $($script:Flash)"
	Say "dev_hdd0: $($script:Hdd)"
	Say "vitals: $(Get-StatusLine)"
	Say "TLS: $(TlsState)"
	Say "HTTP: $(HttpState)"
	$date = Get-CertificatesDate
	if ($date) { Say "Certificates: last update $date" }
	if (Test-NetworkOff) { Say "RPCS3's network is off (Configuration, Network, Network Status: Connected)" }
	return $true
}

function Show-Document([string[]]$names) {
	if (-not (Open-Payload)) { return }
	foreach ($name in $names) { Get-Content -LiteralPath (Join-Path $script:Payload $name) | Out-Host -Paging }
	Pause-Menu
}

# Applies a switch's change right away when vitals is installed
function Switched {
	if (-not (Get-InstalledVersion)) { return }
	if (Test-Running) { Say 'RPCS3 is running: the change applies from its next start' }
	[void](Apply-Switches)
}

function Show-Options {
	while ($true) {
		Say ''
		Say 'Options'
		Say "  1) TLS: $(TlsState)"
		Say "  2) HTTP: $(HttpState)"
		Say "  3) Debug output: $(LevelName (Get-DebugLevel)) (the log goes to $(Join-Path (VitalsDir) 'logs\vitals.log'))"
		Say "     DNS rules aren't in RPCS3: use its own Configuration, Network, IP/Hosts switches"
		Say '  0) Back'
		switch (Read-Host 'Choose') {
			'1' { Set-Flag 'tls.off' (-not (Test-Flag 'tls.off')); Switched }
			'2' {
				if (Test-Flag 'http.off') { Set-Flag 'http.off' $false; Set-Flag 'redirects.off' $false }
				elseif (Test-Flag 'redirects.off') { Set-Flag 'redirects.off' $false; Set-Flag 'http.off' $true }
				else { Set-Flag 'redirects.off' $true }
				Switched
			}
			'3' {
				$level = ((Get-DebugLevel) + 1) % 3
				if (Get-InstalledVersion) {
					if (Test-Running) { [void](Fail 'RPCS3 is running: close it first') }
					elseif (Copy-Builds $level) { [void](Apply-Switches) }
				} else {
					Set-Flag 'debug.1' $false; Set-Flag 'debug.2' $false
					if ($level -ne 0) { Set-Flag "debug.$level" $true }
				}
			}
			default { return }
		}
	}
}

function Show-Menu {
	while ($true) {
		$version = Get-InstalledVersion
		Say ''
		Say "vitals $Version for RPCS3"
		Say "RPCS3: $($script:Rpcs3)"
		Say "vitals: $(Get-StatusLine)"
		$date = Get-CertificatesDate
		if ($date) { Say "Certificates: last update $date" }
		if (Test-NetworkOff) { Say "Note: RPCS3's network is off (Configuration, Network, Network Status: Connected)" }
		if (Test-Running) { Say 'Note: RPCS3 is running: close it before installing or uninstalling' }
		Say ''
		if (-not $version) { Say '  1) Install: lets games connect to modern secure (TLS 1.2 and 1.3) sites' }
		elseif ($version -ne $Version) { Say "  1) Update: replaces vitals $version with $Version" }
		else { Say '  1) Reinstall: fixes a broken installation' }
		if ($version) { Say "  2) Uninstall: puts Sony's libraries back and removes vitals' files" }
		Say '  3) Update certificates: downloads the latest trusted websites certificates'
		Say '  4) Options: turns each part of vitals on or off, and picks the debug output'
		Say '  5) Changelog'
		Say '  6) Credits'
		Say '  0) Exit'
		$choice = Read-Host 'Choose'
		Say ''
		switch ($choice) {
			'1' { [void](Install-Vitals); Pause-Menu }
			'2' { if ($version) { [void](Uninstall-Vitals); Pause-Menu } }
			'3' { [void](Update-Certificates); Pause-Menu }
			'4' { Show-Options }
			'5' { Show-Document @('CHANGELOG.md') }
			'6' { Show-Document @('CREDITS.md', 'THIRD_PARTY_NOTICES.md') }
			'0' { return }
		}
	}
}

function Main([string[]]$arguments) {
	$action = ''; $given = ''
	for ($i = 0; $i -lt $arguments.Count; $i++) {
		switch -regex ($arguments[$i]) {
			'^-{1,2}rpcs3$' { $i++; if ($i -lt $arguments.Count) { $given = $arguments[$i] } }
			'^(install|uninstall|status|certificates)$' { $action = $arguments[$i] }
			default { [void](Fail "unknown argument $($arguments[$i])"); return 2 }
		}
	}
	if (-not (Find-Rpcs3 $given)) { return 1 }
	$ok = switch ($action) {
		'install' { Install-Vitals }
		'uninstall' { Uninstall-Vitals }
		'status' { Show-Status }
		'certificates' { Update-Certificates }
		default { Show-Menu; $true }
	}
	if ($ok) { return 0 } else { return 1 }
}

try {
	$code = Main $Arguments
} finally {
	Close-Payload
}
exit $code
