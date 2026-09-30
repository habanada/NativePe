param(
    [Parameter(Mandatory = $true)]
    [string]$NativePeJson,

    [Parameter(Mandatory = $true)]
    [string]$LibPeConvJson,

    [Parameter(Mandatory = $false)]
    [string]$OutputDir = ""
)

$ErrorActionPreference = "Stop"

$AllowedRoots = @(
    "System32",
    "SysWOW64",
    "bintests-master",
    "pocs-master"
)

function Test-AllowedPath([string]$Path) {
    foreach ($root in $AllowedRoots) {
        if ($Path.Equals($root, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }

        $prefix = $root + "\"
        if ($Path.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }

    return $false
}

function Has-Property($Object, [string]$Name) {
    if ($null -eq $Object) {
        return $false
    }

    return $null -ne $Object.PSObject.Properties[$Name]
}

function Get-Bool($Object, [string]$Name) {
    if (-not (Has-Property $Object $Name)) {
        return $null
    }

    return [bool]$Object.$Name
}

function Get-Int64($Object, [string]$Name) {
    if (-not (Has-Property $Object $Name)) {
        return $null
    }

    return [int64]$Object.$Name
}

function Parse-NativeOutputSize([string]$Message) {
    if ($Message -match 'output=0x([0-9A-Fa-f]+)') {
        return [Convert]::ToUInt64($Matches[1], 16)
    }

    return $null
}

function Contains-Text([string]$Text, [string]$Needle) {
    if ($null -eq $Text) {
        return $false
    }

    return $Text.IndexOf(
        $Needle,
        [System.StringComparison]::OrdinalIgnoreCase) -ge 0
}

if (-not $OutputDir) {
    $OutputDir = Split-Path -Parent $LibPeConvJson
}

New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

$native = Get-Content -LiteralPath $NativePeJson -Raw | ConvertFrom-Json
$lib = Get-Content -LiteralPath $LibPeConvJson -Raw | ConvertFrom-Json

if ($native.schemaVersion -ne 6 -or $lib.schemaVersion -ne 6) {
    throw "Both reports must use corpus schemaVersion 6."
}

$nativeMap = @{}
foreach ($r in $native.results) {
    if (Test-AllowedPath $r.file) {
        $nativeMap[$r.file.ToLowerInvariant()] = $r
    }
}

$libMap = @{}
foreach ($r in $lib.results) {
    if (Test-AllowedPath $r.file) {
        $libMap[$r.file.ToLowerInvariant()] = $r
    }
}

$keys = @($nativeMap.Keys + $libMap.Keys | Sort-Object -Unique)

$rows = foreach ($key in $keys) {
    $n = $nativeMap[$key]
    $l = $libMap[$key]

    if ($null -eq $n) {
        [pscustomobject]@{
            status = "ONLY_LIBPECONV"
            file = $l.file
            details = "file not present in filtered NativePe report"
            nativeOutcome = ""
            libOutcome = $l.outcome
            nativeStage = ""
            libStage = $l.stage
            nativeImports = ""
            libImports = if (Has-Property $l "imports") { $l.imports } else { "" }
            nativeExports = ""
            libExports = if (Has-Property $l "exports") { $l.exports } else { "" }
            nativeTls = ""
            libTls = if (Has-Property $l "tlsCallbacks") { $l.tlsCallbacks } else { "" }
            nativeResources = ""
            libResources = if (Has-Property $l "resources") { $l.resources } else { "" }
        }
        continue
    }

    if ($null -eq $l) {
        [pscustomobject]@{
            status = "ONLY_NATIVEPE"
            file = $n.file
            details = "file not present in filtered libpeconv report"
            nativeOutcome = $n.outcome
            libOutcome = ""
            nativeStage = $n.stage
            libStage = ""
            nativeImports = $n.imports
            libImports = ""
            nativeExports = $n.exports
            libExports = ""
            nativeTls = $n.tlsCallbacks
            libTls = ""
            nativeResources = $n.resources
            libResources = ""
        }
        continue
    }

    $hardDiffs = New-Object System.Collections.Generic.List[string]
    $nativeStricter = New-Object System.Collections.Generic.List[string]
    $libStricter = New-Object System.Collections.Generic.List[string]
    $matches = New-Object System.Collections.Generic.List[string]
    $comparable = $false
    $referenceMatch = $false

    if ($n.architecture -and $l.architecture) {
        $comparable = $true

        $nArch = [string]$n.architecture
        $lArch = [string]$l.architecture
        if ($nArch -eq "PE64") { $nArch = "PE32+" }
        if ($lArch -eq "PE64") { $lArch = "PE32+" }

        if ($nArch -ne $lArch) {
            $hardDiffs.Add("architecture NativePe=$($n.architecture) libpeconv=$($l.architecture)")
        }

        if ($n.imageBase -ne $l.imageBase) {
            $hardDiffs.Add("imageBase NativePe=$($n.imageBase) libpeconv=$($l.imageBase)")
        }

        if ($n.entryPoint -ne $l.entryPoint) {
            $hardDiffs.Add("entryPoint NativePe=$($n.entryPoint) libpeconv=$($l.entryPoint)")
        }

        if ([int64]$n.sections -ne [int64]$l.sections) {
            $hardDiffs.Add("sections NativePe=$($n.sections) libpeconv=$($l.sections)")
        }

        if ((Has-Property $l "directories") -and
            [int64]$n.directories -ne [int64]$l.directories) {
            $hardDiffs.Add("directories NativePe=$($n.directories) libpeconv=$($l.directories)")
        }
    }

    if ($n.outcome -eq "SKIP" -and $l.outcome -eq "SKIP") {
        $referenceMatch = $true
        $matches.Add("both skip non-PE input")
    }

    if ($n.stage -eq "headers" -and $l.stage -eq "headers" -and
        $n.outcome -eq "REJECT" -and $l.outcome -eq "REJECT") {
        $referenceMatch = $true
        $matches.Add("both reject headers")
    }
    elseif ($n.stage -eq "headers" -and $n.outcome -eq "REJECT" -and
            $l.outcome -ne "REJECT") {
        $nativeStricter.Add("NativePe rejects headers while libpeconv continues")
    }
    elseif ($l.stage -eq "headers" -and $l.outcome -eq "REJECT" -and
            $n.outcome -ne "REJECT") {
        $libStricter.Add("libpeconv rejects headers while NativePe continues")
    }

    $nativeImportInvalid =
        Contains-Text $n.message "import directory is present but malformed"

    if ($nativeImportInvalid -and (Has-Property $l "importsPresent")) {
        $comparable = $true
        $libImportPresent = Get-Bool $l "importsPresent"
        $libImportValid = Get-Bool $l "importsValid"
        $libImportParsed = Get-Bool $l "importsParsed"

        if ($libImportPresent -and
            ((-not $libImportValid) -or (-not $libImportParsed))) {
            $referenceMatch = $true
            $matches.Add("both detect malformed imports")
        } else {
            $nativeStricter.Add("NativePe rejects imports; libpeconv accepts/parses them")
        }
    }
    elseif (Has-Property $l "importsPresent") {
        $libImportPresent = Get-Bool $l "importsPresent"
        $libImportParsed = Get-Bool $l "importsParsed"

        if (-not $libImportPresent) {
            if ([int64]$n.imports -ne 0) {
                $hardDiffs.Add("imports NativePe=$($n.imports) libpeconv=0 (absent)")
            }
        }
        elseif ($libImportParsed -and $n.stage -notin @("headers", "sections")) {
            $comparable = $true
            if ([int64]$n.imports -ne [int64]$l.imports) {
                $hardDiffs.Add("imports NativePe=$($n.imports) libpeconv=$($l.imports)")
            } else {
                $matches.Add("import count matches")
            }
        }
    }

    $nativeDelayInvalid =
        Contains-Text $n.message "delay import directory is present but invalid"

    if ($nativeDelayInvalid -and (Has-Property $l "delayImportsPresent")) {
        $comparable = $true
        $present = Get-Bool $l "delayImportsPresent"
        $valid = Get-Bool $l "delayImportsValid"

        if ($present -and (-not $valid)) {
            $referenceMatch = $true
            $matches.Add("both detect malformed delay imports")
        } else {
            $nativeStricter.Add("NativePe rejects delay imports; libpeconv accepts them")
        }
    }

    if ((Has-Property $l "exportsPresent") -and
        -not $nativeImportInvalid -and
        -not $nativeDelayInvalid -and
        $n.stage -notin @("headers", "sections", "imports", "delay-imports")) {

        $present = Get-Bool $l "exportsPresent"
        $parsed = Get-Bool $l "exportsParsed"

        if (-not $present) {
            if ([int64]$n.exports -ne 0) {
                $hardDiffs.Add("exports NativePe=$($n.exports) libpeconv=0 (absent)")
            }
        }
        elseif ($parsed) {
            $comparable = $true
            if ([int64]$n.exports -ne [int64]$l.exports) {
                $hardDiffs.Add("exports NativePe=$($n.exports) libpeconv=$($l.exports)")
            } else {
                $matches.Add("export count matches")
            }
        }
    }

    if ((Has-Property $l "tlsPresent") -and
        -not $nativeImportInvalid -and
        -not $nativeDelayInvalid -and
        $n.stage -notin @("headers", "sections", "imports", "delay-imports")) {

        $present = Get-Bool $l "tlsPresent"
        $parsed = Get-Bool $l "tlsParsed"

        if (-not $present) {
            if ([int64]$n.tlsCallbacks -ne 0) {
                $hardDiffs.Add("TLS callbacks NativePe=$($n.tlsCallbacks) libpeconv=0 (absent)")
            }
        }
        elseif ($parsed) {
            $comparable = $true
            if ([int64]$n.tlsCallbacks -ne [int64]$l.tlsCallbacks) {
                $hardDiffs.Add("TLS callbacks NativePe=$($n.tlsCallbacks) libpeconv=$($l.tlsCallbacks)")
            } else {
                $matches.Add("TLS callback count matches")
            }
        }
    }

    if ((Has-Property $n "tlsCallbackDigest") -and (Has-Property $l "tlsCallbackDigest") -and
        [bool]$n.tlsParsed -and [bool]$l.tlsParsed) {
        $comparable = $true
        if ([int64]$n.tlsCallbacks -ne ([int64]$n.tlsCallbacksValid + [int64]$n.tlsCallbacksInvalid)) {
            $hardDiffs.Add("NativePe TLS callback accounting inconsistent")
        }
        if ([int64]$l.tlsCallbacks -ne ([int64]$l.tlsCallbacksValid + [int64]$l.tlsCallbacksInvalid)) {
            $hardDiffs.Add("libpeconv TLS callback accounting inconsistent")
        }
        foreach ($field in @("tlsCallbacksValid", "tlsCallbacksInvalid")) {
            if ([int64]$n.$field -ne [int64]$l.$field) {
                $hardDiffs.Add("$field NativePe=$($n.$field) libpeconv=$($l.$field)")
            } else {
                $matches.Add("$field matches")
            }
        }
        foreach ($field in @("tlsCallbackDigest", "tlsCallbackFirstValidRva", "tlsCallbackLastValidRva", "tlsIndexRva", "tlsRawData")) {
            if ([string]$n.$field -ne [string]$l.$field) {
                $hardDiffs.Add("$field NativePe=$($n.$field) libpeconv=$($l.$field)")
            } else {
                $matches.Add("$field matches")
            }
        }
        if ([bool]$n.tlsCallbackTruncated -ne [bool]$l.tlsCallbackTruncated) {
            $hardDiffs.Add("tlsCallbackTruncated NativePe=$($n.tlsCallbackTruncated) libpeconv=$($l.tlsCallbackTruncated)")
        } else {
            $matches.Add("tlsCallbackTruncated matches")
        }
        if ([string]$n.tlsCallbackPreview -ne [string]$l.tlsCallbackPreview) {
            $hardDiffs.Add("tlsCallbackPreview NativePe=$($n.tlsCallbackPreview) libpeconv=$($l.tlsCallbackPreview)")
        } else {
            $matches.Add("tlsCallbackPreview matches")
        }
    }

    if ((Has-Property $n "exceptionsPresent") -and (Has-Property $l "exceptionsPresent")) {
        $comparable = $true
        if ([bool]$n.exceptionsPresent -ne [bool]$l.exceptionsPresent) {
            $hardDiffs.Add("exception directory presence NativePe=$($n.exceptionsPresent) libpeconv=$($l.exceptionsPresent)")
        } elseif ([bool]$n.exceptionsPresent) {
            if ([bool]$n.exceptionsParsed -ne [bool]$l.exceptionsParsed) {
                $hardDiffs.Add("exception parse NativePe=$($n.exceptionsParsed) libpeconv=$($l.exceptionsParsed)")
            } elseif ([bool]$n.exceptionsParsed) {
                if ([int64]$n.exceptionsCount -ne [int64]$l.exceptionsCount) {
                    $hardDiffs.Add("exception count NativePe=$($n.exceptionsCount) libpeconv=$($l.exceptionsCount)")
                } elseif ([string]$n.exceptionsDigest -ne [string]$l.exceptionsDigest) {
                    $hardDiffs.Add("exception entries differ")
                } else {
                    $matches.Add("exception directory matches")
                }
            }
        }
    }

    if ((Has-Property $n "loadConfigPresent") -and (Has-Property $l "loadConfigPresent")) {
        $comparable = $true
        if ([bool]$n.loadConfigPresent -ne [bool]$l.loadConfigPresent) {
            $hardDiffs.Add("load config presence NativePe=$($n.loadConfigPresent) libpeconv=$($l.loadConfigPresent)")
        } elseif ([bool]$n.loadConfigPresent) {
            if ([bool]$n.loadConfigParsed -ne [bool]$l.loadConfigParsed) {
                $hardDiffs.Add("load config parse NativePe=$($n.loadConfigParsed) libpeconv=$($l.loadConfigParsed)")
            } elseif ([bool]$n.loadConfigParsed) {
                if ([int64]$n.loadConfigSize -ne [int64]$l.loadConfigSize) {
                    $hardDiffs.Add("load config size NativePe=$($n.loadConfigSize) libpeconv=$($l.loadConfigSize)")
                }
                if ([int64]$n.loadConfigVersion -ne [int64]$l.loadConfigVersion) {
                    $hardDiffs.Add("load config version NativePe=$($n.loadConfigVersion) libpeconv=$($l.loadConfigVersion)")
                }
                if ([string]$n.securityCookieRva -ne [string]$l.securityCookieRva) {
                    $hardDiffs.Add("security cookie RVA NativePe=$($n.securityCookieRva) libpeconv=$($l.securityCookieRva)")
                } else {
                    $matches.Add("security cookie RVA matches")
                }
            }
        }
    }

    $nativeResourceInvalid =
        Contains-Text $n.message "resource directory is present but parsing failed"

    if ($nativeResourceInvalid -and (Has-Property $l "resourcesPresent")) {
        $comparable = $true
        $present = Get-Bool $l "resourcesPresent"
        $parsed = Get-Bool $l "resourcesParsed"

        if ($present -and (-not $parsed)) {
            $referenceMatch = $true
            $matches.Add("both reject resource parsing")
        } else {
            $nativeStricter.Add("NativePe rejects resources; libpeconv parser succeeds")
        }
    }
    elseif ((Has-Property $l "resourcesPresent") -and
            -not $nativeImportInvalid -and
            -not $nativeDelayInvalid -and
            $n.stage -notin @("headers", "sections", "imports", "delay-imports")) {

        $present = Get-Bool $l "resourcesPresent"
        $parsed = Get-Bool $l "resourcesParsed"

        if (-not $present) {
            if ([int64]$n.resources -ne 0) {
                $hardDiffs.Add("resources NativePe=$($n.resources) libpeconv=0 (absent)")
            }
        }
        elseif ($parsed -and $n.stage -ne "resources") {
            $comparable = $true
            if ([int64]$n.resources -ne [int64]$l.resources) {
                $hardDiffs.Add("resources NativePe=$($n.resources) libpeconv=$($l.resources)")
            } else {
                $matches.Add("resource count matches")
            }
        }
    }

    $nativeRelocInvalid =
        Contains-Text $n.message "relocation directory is present but malformed"

    if ($nativeRelocInvalid -and (Has-Property $l "relocsPresent")) {
        $comparable = $true
        $present = Get-Bool $l "relocsPresent"
        $valid = Get-Bool $l "relocsValid"

        if ($present -and (-not $valid)) {
            $referenceMatch = $true
            $matches.Add("both detect malformed relocations")
        } else {
            $nativeStricter.Add("NativePe rejects relocations; libpeconv validates them")
        }
    }
    elseif ((Has-Property $l "relocsPresent") -and
            $n.stage -notin @("headers", "sections")) {

        $present = Get-Bool $l "relocsPresent"
        $valid = Get-Bool $l "relocsValid"
        $libHasRelocs = $present -and $valid

        $comparable = $true
        if ([bool]$n.hasRelocs -ne $libHasRelocs) {
            $hardDiffs.Add("valid relocations NativePe=$($n.hasRelocs) libpeconv=$libHasRelocs")
        } else {
            $matches.Add("relocation validity matches")
        }
        if ($libHasRelocs -and (Has-Property $n "relocFields") -and (Has-Property $l "relocFields")) {
            if ([int64]$n.relocFields -ne [int64]$l.relocFields) {
                $hardDiffs.Add("relocation fields NativePe=$($n.relocFields) libpeconv=$($l.relocFields)")
            } else {
                $matches.Add("relocation field count matches")
            }
        }
    }

    if ((Has-Property $l "isDotNet") -and
        $n.stage -notin @("headers", "sections")) {

        $comparable = $true
        if ([bool]$n.isDotNet -ne [bool]$l.isDotNet) {
            $hardDiffs.Add(".NET detection NativePe=$($n.isDotNet) libpeconv=$($l.isDotNet)")
        } else {
            $matches.Add(".NET detection matches")
        }
    }

    if ($n.roundTripChecked -or $n.stage -eq "roundtrip") {
        $comparable = $true

        if (Contains-Text $n.message "PeVirtualToRaw returned nil") {
            if ((Has-Property $l "unmapOk") -and (-not [bool]$l.unmapOk)) {
                $referenceMatch = $true
                $matches.Add("both reject virtual-to-raw")
            } elseif ($l.outcome -ne "REJECT") {
                $nativeStricter.Add("NativePe rejects virtual-to-raw; libpeconv succeeds")
            }
        }
        elseif (Contains-Text $n.message "raw range missing:") {
            $nativeOutput = Parse-NativeOutputSize $n.message

            if ((Has-Property $l "unmapOk") -and
                [bool]$l.unmapOk -and
                $null -ne $nativeOutput -and
                [uint64]$l.rawOutputSize -eq [uint64]$nativeOutput) {

                $referenceMatch = $true
                $matches.Add("same lossy virtual-to-raw output size: $nativeOutput bytes")
            }
            elseif ((Has-Property $l "unmapOk") -and (-not [bool]$l.unmapOk)) {
                $hardDiffs.Add("NativePe produces raw output; libpeconv rejects virtual-to-raw")
            }
            else {
                $hardDiffs.Add("lossy virtual-to-raw output size differs")
            }
        }
        elseif ([bool]$n.roundTripChecked) {
            if ((Has-Property $l "unmapOk") -and (-not [bool]$l.unmapOk)) {
                $libStricter.Add("NativePe roundtrip succeeds; libpeconv rejects virtual-to-raw")
            }
            elseif ((Has-Property $l "roundTripChecked") -and [bool]$l.roundTripChecked) {
                if ([bool]$n.roundTripEqual -ne [bool]$l.roundTripEqual) {
                    $hardDiffs.Add("roundTripEqual NativePe=$($n.roundTripEqual) libpeconv=$($l.roundTripEqual)")
                } else {
                    $matches.Add("roundtrip equality matches")
                }

                if ([bool]$n.roundTripEqual -and
                    [bool]$l.roundTripEqual -and
                    [int64]$n.firstDiff -ne [int64]$l.firstDiff) {
                    $hardDiffs.Add("firstDiff differs despite equal roundtrip")
                }
            }
        }
    }

    if ($l.outcome -in @("FAIL", "CRASH", "TIMEOUT")) {
        $hardDiffs.Add("libpeconv outcome=$($l.outcome) stage=$($l.stage)")
    }

    if ($hardDiffs.Count -gt 0) {
        $status = "DIFFERENT"
    }
    elseif ($libStricter.Count -gt 0) {
        $status = "LIBPECONV_STRICTER"
    }
    elseif ($nativeStricter.Count -gt 0) {
        $status = "NATIVEPE_STRICTER"
    }
    elseif ($referenceMatch) {
        $status = "MATCH_REFERENCE"
    }
    elseif ($comparable) {
        $status = "MATCH"
    }
    else {
        $status = "NOT_COMPARABLE"
    }

    $details = @()
    $details += $hardDiffs
    $details += $nativeStricter
    $details += $libStricter
    $details += $matches

    [pscustomobject]@{
        status = $status
        file = $n.file
        details = ($details -join "; ")
        nativeOutcome = $n.outcome
        libOutcome = $l.outcome
        nativeStage = $n.stage
        libStage = $l.stage
        nativeImports = $n.imports
        libImports = if (Has-Property $l "imports") { $l.imports } else { "" }
        nativeExports = $n.exports
        libExports = if (Has-Property $l "exports") { $l.exports } else { "" }
        nativeTls = $n.tlsCallbacks
        libTls = if (Has-Property $l "tlsCallbacks") { $l.tlsCallbacks } else { "" }
        nativeResources = $n.resources
        libResources = if (Has-Property $l "resources") { $l.resources } else { "" }
    }
}

$stamp = Get-Date -Format "yyyyMMdd-HHmmss-fff"
$csvPath = Join-Path $OutputDir "NativePe-vs-libpeconv-$stamp.csv"
$logPath = Join-Path $OutputDir "NativePe-vs-libpeconv-$stamp.log"

$rows |
    Sort-Object status, file |
    Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8

$counts = $rows | Group-Object status | Sort-Object Name

$log = New-Object System.Collections.Generic.List[string]
$log.Add("NativePe vs libpeconv differential comparison v6")
$log.Add("NativePe=$NativePeJson")
$log.Add("libpeconv=$LibPeConvJson")
$log.Add("AllowedRoots=$($AllowedRoots -join ',')")
$log.Add("ComparedFiles=$($rows.Count)")
$log.Add("")

foreach ($c in $counts) {
    $log.Add("$($c.Name)=$($c.Count)")
}

foreach ($category in @(
    "DIFFERENT",
    "LIBPECONV_STRICTER",
    "NATIVEPE_STRICTER",
    "ONLY_NATIVEPE",
    "ONLY_LIBPECONV")) {

    $selected = @($rows | Where-Object { $_.status -eq $category })
    if ($selected.Count -eq 0) {
        continue
    }

    $log.Add("")
    $log.Add($category + ":")

    foreach ($r in $selected) {
        $log.Add("$($r.file) :: $($r.details)")
    }
}

$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllLines($logPath, $log, $utf8NoBom)

Write-Host "CSV : $csvPath"
Write-Host "LOG : $logPath"
Write-Host ""

foreach ($c in $counts) {
    Write-Host "$($c.Name)=$($c.Count)"
}

$hard = @(
    $rows |
    Where-Object {
        $_.status -in @(
            "DIFFERENT",
            "LIBPECONV_STRICTER",
            "ONLY_NATIVEPE",
            "ONLY_LIBPECONV")
    }
)

if ($hard.Count -gt 0) {
    exit 1
}

exit 0
