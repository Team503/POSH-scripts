<#
.SYNOPSIS
    Pushes Active Directory export data (Users & Groups) to a JSON REST API with batching, retries, logging, manifesting, throttling, and summary email.

.DESCRIPTION
    Designed to ingest exported AD User and Group CSVs and push each record to a REST API using Bearer token auth. Includes throttling, retry logic, dual progress bars, cleanup, manifest logging, and optional verbose diagnostics.

    Features:
    - Multi-mode secret delivery: Header, Custom Header, Query Param, or Body
    - Dual progress bar output per record + batch (optional)
    - Per-batch .manifest.json and .stats.csv file export
    - Optional verbose retry logs with status codes
    - ActionType logging: RETRY, PROGRESS, THROTTLE, etc.
    - Compression of logs and diagnostics for email or archiving
    - Scheduled task-friendly; non-blocking jobs with throttle control
    - Smart cleanup of daily folders, logs, and zipped failures
    - Optional HTML email summary with metrics, run time, and ZIPs

.PARAMETER SecretDelivery
    Optional. How to deliver the API secret. Valid values:
        - Header       (default)
        - HeaderCustom
        - Query
        - Body

.PARAMETER enableConsoleOutput
    Optional. Enables real-time console logging and progress bars.

.PARAMETER enableVerboseMode
    Optional. Enables deep logging, stack trace, verbose output, and JSON diagnostics.

.PARAMETER ThrottleDelayMs
    Optional. Delay (in ms) between pushes to prevent flooding.

.PARAMETER RetentionDays
    Optional. Number of days to retain daily folders and logs.

.PARAMETER RunDate
    Optional, allows user to override the default use of today's date. Format: yyyy-MM-dd

.EXAMPLE
    .\Push-Files.ps1 -SecretDelivery Body -EnableVerboseMode:$true -enableConsoleOutput:$false

    Pushes records with secret in JSON body and logs everything in detail, useful for troubleshooting or dry runs.

.EXAMPLE
    powershell.exe -File "Push-Files.ps1" -ThrottleDelayMs 250 -OnlyEmailIfFailures:$true

    Runs with 250ms throttling and only sends emails if failures occurred.

.NOTES
    Author       : Alex Cherry
    Script Name  : Push-Files.ps1
    Version      : v2.5.3
    Last Updated : 2025-07-24

.CHANGELOG
    v1.0.0 - Initial release. Supports:
        - User and Group CSV format mapping
        - Secret delivery via header/query/body
        - Retry queue with max retry limit
        - Domain-aware failed CSVs
        - Per-domain ZIP archive of failures
        - HTML email report with metrics
        - Automated cleanup of aged data folders and ZIPs
    v1.1.0 - "Added an only email if failures" switch to reduce alert fatigue
    v2.0.1 - Switched to job-based processing to allow faster processing, also updated email report and improved error logging
    v2.1.0 - Added throttles to the job to prevent triggering flooding
    v2.1.1 - Re-added support for $enableConsoleOutput and $enableVerboseMode
    v2.2.1 - Extended logging, added progress bars, trimmed memory usage
    v2.3.1 - Added manifest.json files to each batch, added ActionTypes of Retry/Progress/Throttle, and catpured available HTTP error codes
    v2.3.2 - Switched to start-threadjob for decreased overhead, tons of mistypes and mismatched param/args fixed
    v2.4.1 - Added detailed HTTP logging when verbose mode is on, added date override parameter
    v2.5.2 - Working push mechanism and logging, added max concurrent jobs
             THIS IS PRODUCTION READY UNLESS THE HEADERS/AUTH/REQUEST NEED TO BE CHANGED
    v2.5.3 - Fixed email counters, made job processing more efficient
#>

# Accept command line parameter to choose secret delivery type, defaults to Header
param (
    [ValidateSet("Header", "HeaderCustom", "Query", "Body", "None")]
    [string]$SecretDelivery         = "None",
    [string]$scriptName             = "Push-Files",
    [string]$BaseUrl                = "https://dev.example.com:443",
    [string]$Endpoint               = "/upload/batch",
    [string]$BearerToken            = "token",
    [string]$Secret                 = "secret",
    [string]$rootFolder             = "C:\Scripts\ADreports",
    [string]$OutputFolder           = "output",
    [bool]  $enableConsoleOutput    = $true,
    [bool]  $enableVerboseMode      = $true,
    [bool]  $sendEmail              = $true,
    [bool]  $OnlyEmailIfFailures    = $false,
    [int]   $RetentionDays          = 30,
    [int]   $MaxRetries             = 2,
    [int]   $BatchSize              = 100,
    [int]   $ThrottleDelayMs        = 0,
    [string]$emailTo                = "user@company.com",
    [string]$emailFrom              = "script-bot@company.com",
    [string]$smtpServer             = "mail.company.com",
    [int]   $smtpPort               = 25,
    [string]$RunDate,
    [int]$attachmentSize            = 100KB,
    [switch]$Help
)

# Help Detection (bound or raw CLI)
$rawArgs = $args -join " "
$showHelp = $Help -or
             $rawArgs -match "(?i)\b(help|\/\?|--help|\?)\b" -or
             $PSBoundParameters.ContainsKey("help")

if ($showHelp) {
    Write-Host @"
Push-Files.ps1 — AD Export Push Utility

Parameters:
  -SecretDelivery       How to deliver the API secret (Header, HeaderCustom, Query, Body)
  -BearerToken          The bearer token for Authorization
  -Secret               The API secret
  -rootFolder           Where to look for AD exports (CSV)
  -OutputFolder         Subfolder for output batches (default: output)
  -enableConsoleOutput  Show real-time logs and progress (default: true)
  -enableVerboseMode    Enable detailed logs and JSON diagnostics
  -sendEmail            Whether to send a summary email (default: true)
  -OnlyEmailIfFailures  Skip summary emails if no failures occurred
  -RetentionDays        How many days of logs to keep (default: 30)
  -BatchSize            Number of records per job (default: 100)
  -MaxRetries           Attempts per failed record (default: 2)
  -ThrottleDelayMs      Optional delay (ms) between record pushes
  -smtpServer, -smtpPort, -emailTo, -emailFrom  Email configuration

Examples:
  .\Push-Files.ps1 -enableVerboseMode -ThrottleDelayMs 250
  .\Push-Files.ps1 -SecretDelivery Body -OnlyEmailIfFailures
"@
    exit
}

# Headers initialized
$Headers = [pscustomobject]@{
    "Authorization" = "Bearer $BearerToken"
    "Content-Type"  = "application/json"
}

# --- Email Config ---
$emailTo    = "user@company.com"
$emailFrom  = "script-bot@cernerasp.com"
$smtpServer = "mail.cernerasp.com"
$smtpPort   = 25

# --- Script Info ---
$scriptversion  = "v2.5.3"
$scriptauthor   = "Alex Cherry"
$scriptupdated  = "2025-07-14"

# --- Create variable dependent values ---
$outputRoot     = Join-Path $rootFolder $OutputFolder
$tempFolder     = Join-Path $rootfolder "temp"

# --- Allow parameter-based override of date, and build date-based variables
if ($RunDate) {
    try {
        $parsedDate = Get-Date $RunDate -ErrorAction Stop
        $DayStamp = $parsedDate.ToString("yyyy-MM-dd")
        $Date     = $parsedDate.ToString("HHmm_yyyy-MM-dd")
    } catch {
        Write-Error "Invalid -RunDate format. Use yyyy-MM-dd. Example: -RunDate '2025-07-15'"
        exit 1
    }
} else {
    $Date     = Get-Date -Format "HHmm_yyyy-MM-dd"
    $DayStamp = Get-Date -Format "yyyy-MM-dd"
}
$BaseUrl         = "$($BaseUrl.TrimEnd('/'))$($Endpoint)"
$dailyFolder     = Join-Path $outputRoot $DayStamp 
$pushFolder      = Join-Path $dailyFolder "DailyPush"
$tempFolder      = Join-Path $rootfolder "temp"
$failuresFolder  = Join-Path $pushFolder "FailedPushes"
$tempDailyFolder = Join-Path $tempFolder $OutputFolder
$tempPushFolder  = Join-Path $tempDailyFolder $DayStamp

# --- For Logging ---
$SuccessCount    = 0
$FailureCount    = 0
$CsvCount        = 0
$activityLogPath = Join-Path $dailyFolder "Push-ActivityLog-$Date.csv"
$scriptStartTime = Get-Date

# Create daily folder if it doesn't exist
if (-not (Test-Path -Path $dailyFolder)) {
    New-Item -Path $dailyFolder -ItemType Directory -Force | Out-Null
}

# Create the activity log file if it doesn't exist
if (-not (Test-Path $activityLogPath)) {
    New-Item -Path $activityLogPath -ItemType File -Force | Out-Null
}

# Log-Activity here is streamlined to write directly to the file, since each batch has its own log file
function Log-Activity {
    param (
        [string]$DomainName,
        [string]$RemoteComputer,
        [string]$ScriptName,
        [string]$ActionType,
        [string]$Message,
        [bool]$enableVerboseMode,
        [bool]$enableConsoleOutput
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    $allowedActions = @("INFO", "SUCCESS", "WARNING", "ERROR", "RUNTIME", "NOTIFY", "RETRY", "THROTTLE", "PROGRESS", "DEBUG")
    if ($allowedActions -notcontains $ActionType.ToUpper()) {
        $ActionType = "INFO"
    }

    $stackTag = ""
        if ($enableVerboseMode) {
            $invocation = $MyInvocation
            $callerFunc   = if ($invocation.MyCommand) { $invocation.MyCommand.Name } else { "<none>" }
            $callerScript = if ($invocation.ScriptName) { $invocation.ScriptName } else { "<none>" }
            $callerLine   = $invocation.ScriptLineNumber

            if ($callerFunc -and $callerScript) {
                $stackTag = " (at $($callerFunc):$callerLine in $callerScript)"
            } elseif ($callerFunc) {
                $stackTag = " (in $callerFunc)"
            } else {
                $stackTag = ""
            }
        }

    $line = "[$timestamp] [$ActionType] [$DomainName] [$RemoteComputer] [$ScriptName] $Message$stackTag"

    try {
        Add-Content -Path $activityLogPath -Value $line
    } catch {
        Write-Warning "Failed to write log entry to file: $($_.Exception.Message)"
    }

    if ($enableConsoleOutput) {
        $color = switch ($ActionType.ToUpper()) {
            "INFO"     { "Cyan" }
            "SUCCESS"  { "Green" }
            "WARNING"  { "Yellow" }
            "ERROR"    { "Red" }
            "RUNTIME"  { "White" }
            "NOTIFY"   { "Blue" }
            "RETRY"    { "DarkYellow" }
            "THROTTLE" { "Magenta" }
            "PROGRESS" { "Gray" }
            "DEBUG"    { "DarkGray" }
            default    { "Gray" }
        }
        Write-Host $line -ForegroundColor $color
    }
}

function Clean-OldPushes {
    param (
        [string]$outputRoot,
        [int]$RetentionDays,
        [bool]$enableVerboseMode,
        [bool]$enableConsoleOutput
    )

    $now = Get-Date
    $ageLimit = $now.AddDays(-$RetentionDays)

    # Clean folders like "2025-07-17" under outputRoot
    $folders = Get-ChildItem -Path $outputRoot -Directory | Where-Object {
        $_.Name -match "^\d{4}-\d{2}-\d{2}$"
    }

    foreach ($folder in $folders) {
        try {
            $folderDate = Get-Date $folder.Name -ErrorAction Stop
            if ($folderDate -lt $ageLimit) {
                Remove-Item -Path $folder.FullName -Recurse -Force
                Log-Activity "System" $folder.FullName "Clean-OldPushes" "INFO" "Deleted expired folder: $($folder.Name)" $enableVerboseMode $enableConsoleOutput
            }
        } catch {
            Log-Activity "System" $folder.FullName "Clean-OldPushes" "WARNING" "Failed to delete folder $($folder.Name): $($_.Exception.Message)" $enableVerboseMode $enableConsoleOutput
        }
    }

    # Clean up stale files by extension
    $extensionsToDelete = @(".zip", ".log", ".json", ".csv", ".manifest.json", ".stats.csv")
    $looseFiles = Get-ChildItem -Path $outputRoot -File -Recurse | Where-Object {
        ($_.LastWriteTime -lt $ageLimit) -and ($extensionsToDelete -contains $_.Extension.ToLower())
    }

    foreach ($file in $looseFiles) {
        try {
            Remove-Item -Path $file.FullName -Force
            Log-Activity "System" $file.FullName "Clean-OldPushes" "INFO" "Deleted expired file: $($file.Name)" $enableVerboseMode $enableConsoleOutput
        } catch {
            Log-Activity "System" $file.FullName "Clean-OldPushes" "WARNING" "Failed to delete file $($file.Name): $($_.Exception.Message)" $enableVerboseMode $enableConsoleOutput
        }
    }

    # Clean up $tempFolder content as well, if defined
    if ($script:tempFolder -and (Test-Path $script:tempFolder)) {
        try {
            $tempItems = Get-ChildItem -Path $script:tempFolder -Recurse -Force -ErrorAction Stop
            foreach ($item in $tempItems) {
                Remove-Item -Path $item.FullName -Recurse -Force -ErrorAction Stop
            }
            Log-Activity "System" $script:tempFolder "Clean-OldPushes" "INFO" "Cleaned up tempFolder contents: $script:tempFolder" $enableVerboseMode $enableConsoleOutput
        } catch {
            Log-Activity "System" $script:tempFolder "Clean-OldPushes" "WARNING" "Failed to clean tempFolder: $($_.Exception.Message)" $enableVerboseMode $enableConsoleOutput
        }
    }
}

function Show-Configuration {
    if (-not $enableVerboseMode) { return }

    $scriptName = "Show-Configuration"
    Log-Activity "<Config>" "<Local>" $scriptName "INFO" "Verbose mode is ON — dumping configuration variables..."

    # Authentication / API
    Log-Activity "<Config>" "<Local>" $scriptName "DEBUG" "BaseUrl               : $BaseUrl"
    Log-Activity "<Config>" "<Local>" $scriptName "DEBUG" "SecretDelivery        : $SecretDelivery"
    Log-Activity "<Config>" "<Local>" $scriptName "DEBUG" "BearerToken Set       : $($BearerToken -ne $null -and $BearerToken -ne '')"
    Log-Activity "<Config>" "<Local>" $scriptName "DEBUG" "Secret Set            : $($Secret -ne $null -and $Secret -ne '')"
    Log-Activity "<Config>" "<Local>" $scriptName "DEBUG" "ApiUrl                : $ApiUrl"

    # File paths / folders
    Log-Activity "<Config>" "<Local>" $scriptName "DEBUG" "RootFolder            : $rootFolder"
    Log-Activity "<Config>" "<Local>" $scriptName "DEBUG" "OutputFolder          : $OutputFolder"
    Log-Activity "<Config>" "<Local>" $scriptName "DEBUG" "DailyFolder           : $dailyFolder"
    Log-Activity "<Config>" "<Local>" $scriptName "DEBUG" "FailuresFolder        : $failuresFolder"
    Log-Activity "<Config>" "<Local>" $scriptName "DEBUG" "ActivityLogPath       : $activityLogPath"

    # Processing & retry
    Log-Activity "<Config>" "<Local>" $scriptName "DEBUG" "BatchSize             : $BatchSize"
    Log-Activity "<Config>" "<Local>" $scriptName "DEBUG" "ThrottleDelayMs       : $ThrottleDelayMs"
    Log-Activity "<Config>" "<Local>" $scriptName "DEBUG" "MaxRetries            : $MaxRetries"
    Log-Activity "<Config>" "<Local>" $scriptName "DEBUG" "RetentionDays         : $RetentionDays"
    Log-Activity "<Config>" "<Local>" $scriptName "DEBUG" "MaxConcurrentJobs     : $MaxConcurrentJobs"

    # Email settings
    Log-Activity "<Config>" "<Local>" $scriptName "DEBUG" "EmailTo               : $emailTo"
    Log-Activity "<Config>" "<Local>" $scriptName "DEBUG" "EmailFrom             : $emailFrom"
    Log-Activity "<Config>" "<Local>" $scriptName "DEBUG" "SmtpServer            : $smtpServer"
    Log-Activity "<Config>" "<Local>" $scriptName "DEBUG" "SmtpPort              : $smtpPort"
    Log-Activity "<Config>" "<Local>" $scriptName "DEBUG" "SendEmail             : $sendEmail"
    Log-Activity "<Config>" "<Local>" $scriptName "DEBUG" "OnlyEmailIfFailures   : $OnlyEmailIfFailures"

    # Flags
    Log-Activity "<Config>" "<Local>" $scriptName "DEBUG" "enableConsoleOutput   : $enableConsoleOutput"
    Log-Activity "<Config>" "<Local>" $scriptName "DEBUG" "enableVerboseMode     : $enableVerboseMode"

    # Script identity
    Log-Activity "<Config>" "<Local>" $scriptName "DEBUG" "Script Name           : $scriptName"
    Log-Activity "<Config>" "<Local>" $scriptName "DEBUG" "Script Version        : $scriptversion"
    Log-Activity "<Config>" "<Local>" $scriptName "DEBUG" "Script Author         : $scriptauthor"
    Log-Activity "<Config>" "<Local>" $scriptName "DEBUG" "Last Updated          : $scriptupdated"
}

function Expand-ZipsToTemp {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)][string]$rootFolder,
        [Parameter(Mandatory = $true)][string]$tempFolder,
        [switch]$Expand,
        [switch]$Cleanup
    )

    if ($Expand) {
        if (Test-Path $tempFolder) {
            Log-Activity $domainName $remoteComputer $scriptName "INFO" "Cleaning up existing temp folder: $tempFolder" $enableVerboseMode $enableConsoleOutput
            Remove-Item -Path $tempFolder -Recurse -Force
        }

        New-Item -ItemType Directory -Path $tempFolder -Force | Out-Null
        Log-Activity $domainName $remoteComputer $scriptName "INFO" "Created temp extraction folder: $tempFolder" $enableVerboseMode $enableConsoleOutput

        # Only match ZIPs with the current day's date and "results" in the name
        $pattern = "*-results-$DayStamp.zip"
        $zipFiles = Get-ChildItem -Path $rootFolder -Recurse -Filter *.zip | Where-Object {
            $_.Name -like $pattern
        }

        Log-Activity $domainName $remoteComputer $scriptName "INFO" "Found $($zipFiles.Count) zip files matching pattern '$pattern' in $rootFolder" $enableVerboseMode $enableConsoleOutput

        foreach ($zip in $zipFiles) {
            $relativePath = $zip.DirectoryName.Replace($rootFolder, "").TrimStart('\')
            $destinationFolder = Join-Path $tempFolder $relativePath

            if (!(Test-Path $destinationFolder)) {
                New-Item -ItemType Directory -Path $destinationFolder -Force | Out-Null
                Log-Activity $domainName $remoteComputer $scriptName "DEBUG" "Created folder for extraction: $destinationFolder" $enableVerboseMode $enableConsoleOutput
            }

            try {
                Log-Activity $domainName $remoteComputer $scriptName "INFO" "Extracting $($zip.FullName) to $destinationFolder" $enableVerboseMode $enableConsoleOutput
                Expand-Archive -LiteralPath $zip.FullName -DestinationPath $destinationFolder -Force
            }
            catch {
                Log-Activity $domainName $remoteComputer $scriptName "ERROR" "Failed to extract $($zip.FullName): $($_.Exception.Message)" $enableVerboseMode $enableConsoleOutput
            }
        }
    }

    if ($Cleanup) {
        if (Test-Path $tempFolder) {
            try {
                Remove-Item -Path $tempFolder -Recurse -Force
                Log-Activity $domainName $remoteComputer $scriptName "INFO" "Deleted temp folder: $tempFolder" $enableVerboseMode $enableConsoleOutput
            }
            catch {
                Log-Activity $domainName $remoteComputer $scriptName "ERROR" "Failed to delete temp folder: $($_.Exception.Message)" $enableVerboseMode $enableConsoleOutput
            }
        }
        else {
            Log-Activity $domainName $remoteComputer $scriptName "WARNING" "Temp folder does not exist: $tempFolder" $enableVerboseMode $enableConsoleOutput
        }
    }
}

function Send-EmailReport {
    param (
        [TimeSpan]$ScriptDuration,
        [int]$SuccessCount,
        [int]$FailureCount,
        [int]$CsvCount,
        [string]$Date,
        [string]$LogPath,
        [string]$ZipAttachmentPath
    )

    Log-Activity "<Summary>" "<Local>" "EmailReport" "INFO" "Preparing to send final summary email..."

    try {
        $scriptName = "Push-FilesToOlympus"
        $totalSeconds = $ScriptDuration.TotalSeconds
        $averagePerCsv = if ($CsvCount -gt 0) { [math]::Round($totalSeconds / $CsvCount, 2) } else { "N/A" }
        $runTimeString = "{0:F2} minutes ({1} seconds)" -f $ScriptDuration.TotalMinutes, [int]$totalSeconds
        $subject = "API Import Report: $SuccessCount Success, $FailureCount Failed ($Date)"

        $attachments = @()

        if ($ZipAttachmentPath -and (Test-Path $ZipAttachmentPath)) {
            $attachments += $ZipAttachmentPath
            Log-Activity "<Email>" "<Local>" $scriptName "DEBUG" "Added ZIP attachment for email: $ZipAttachmentPath"
        }
        elseif ($LogPath -and (Test-Path $LogPath)) {
            $attachments += $LogPath
            Log-Activity "<Email>" "<Local>" $scriptName "DEBUG" "Fallback to log file as attachment: $LogPath"
        }
        else {
            Log-Activity "<Email>" "<Local>" $scriptName "WARNING" "No valid ZIP or log file to attach to email."
        }

        $body = @"
<html>
<head>
  <style>
    body { font-family: Arial, sans-serif; }
    table {
      border-collapse: collapse;
      width: 600px;
      margin-bottom: 20px;
    }
    th, td {
      padding: 8px 12px;
      border: 1px solid #ddd;
      text-align: left;
    }
    th {
      background-color: #f5f5f5;
    }
    .section-title {
      font-size: 1.1em;
      font-weight: bold;
      margin-top: 25px;
    }
    .footer {
      font-size: 0.9em;
      color: #777;
    }
  </style>
</head>
<body>
  <h2>Push-FilesToOlympus Import Summary</h2>

<table>
  <tr><th>Script</th><td>$scriptName</td></tr>
  <tr><th>Run Date</th><td>$Date</td></tr>
  <tr><th>Host Name</th><td>$env:COMPUTERNAME</td></tr>
  <tr><th>Duration</th><td>$runTimeString</td></tr>
  <tr><th>CSV Files Processed</th><td>$CsvCount</td></tr>
  <tr><th>Records Imported</th><td>$SuccessCount</td></tr>
  <tr><th>Records Failed</th><td>$FailureCount</td></tr>
  <tr><th>Average Time/CSV</th><td>$averagePerCsv seconds</td></tr>
  <tr><th>Log Archive</th><td>$(Split-Path $attachments[0] -Leaf)</td></tr>
  <tr><th>Batch Logs Found</th><td>$((Get-ChildItem $pushFolder -Filter 'PushDiagnostics-Batch-*.log' -ErrorAction SilentlyContinue).Count)</td></tr>
  <tr><th>Verbose Logs Found</th><td>$((Get-ChildItem $pushFolder -Filter 'PushDiagnostics-Batch-*.json' -ErrorAction SilentlyContinue).Count)</td></tr>
  <tr><th>ZIP Files Created</th><td>$((Get-ChildItem $pushFolder -Filter '*.zip' -ErrorAction SilentlyContinue).Count)</td></tr>
  <tr><th>Retention Policy</th><td>$RetentionDays days</td></tr>
</table>

  <div class="section-title">Script Metadata</div>
  <table>
    <tr><th>Version</th><td>$scriptversion</td></tr>
    <tr><th>Author</th><td>$scriptauthor</td></tr>
    <tr><th>Last Updated</th><td>$scriptupdated</td></tr>
  </table>

  <p class="footer">
    This is an automated report generated by the <strong>Push-FilesToOlympus</strong> PowerShell script.
  </p>
</body>
</html>
"@

        if ($attachments.Count -gt 0) {
            Send-MailMessage -To $emailTo `
                            -From $emailFrom `
                            -Subject $subject `
                            -BodyAsHtml `
                            -Body $body `
                            -SmtpServer $smtpServer `
                            -Port $smtpPort `
                            -Attachments $attachments
            Log-Activity "<Email>" "<Local>" "EmailReport" "SUCCESS" "Sent email to $emailTo with import summary (HTML formatted)"
        } else {
            Send-MailMessage -To $emailTo `
                -From $emailFrom `
                -Subject $subject `
                -BodyAsHtml `
                -Body $body `
                -SmtpServer $smtpServer `
                -Port $smtpPort
            Log-Activity "<Email>" "<Local>" "EmailReport" "WARNING" "Email not sent: No attachment available"
        }
    } catch {
        Log-Activity "<Email>" "<Local>" "EmailReport" "ERROR" "Failed to send summary email: $_"
    }
}

switch ($SecretDelivery) {
    "Header" {
        Add-Member -InputObject $Headers -MemberType NoteProperty -Name "Secret" -Value $Secret
        $ApiUrl = $BaseUrl
        Log-Activity "<Init>" "<Local>" $scriptName "INFO" "Using SecretDelivery=Header"
    }
    "HeaderCustom" {
        Add-Member -InputObject $Headers -MemberType NoteProperty -Name "X-Api-Secret" -Value $Secret
        $ApiUrl = $BaseUrl
        Log-Activity "<Init>" "<Local>" $scriptName "INFO" "Using SecretDelivery=HeaderCustom"
    }
    "Query" {
        $ApiUrl = "$BaseUrl?secret=$Secret"
        Log-Activity "<Init>" "<Local>" $scriptName "INFO" "Using SecretDelivery=Query"
    }
    "Body" {
        $ApiUrl = $BaseUrl
        Log-Activity "<Init>" "<Local>" $scriptName "INFO" "Using SecretDelivery=Body"
    }
    "None" {
        $ApiUrl = $BaseUrl
        Log-Activity "<Init>" "<Local>" $scriptName "INFO" "Not delivering secret"
    }
    default {
        Log-Activity "<Init>" "<Local>" $scriptName "ERROR" "Invalid SecretDelivery type: $SecretDelivery"
        exit 1
    }
}


function Remove-NonAscii {
    param ([string]$text)
    return -join ($text.ToCharArray() | Where-Object { [int][char]$_ -le 127 })
}

function Convert-ToBool ($val) {
    if ($null -eq $val) { return $false }
    $str = $val.ToString().ToLower()
    return ($str -eq "true" -or $str -eq "1" -or $str -eq "yes")
}

function Convert-ToIsoDate ($val) {
    try {
        if ($val) { return ([datetime]$val).ToString("s") + "Z" }
    } catch { }
    return $null
}

function Push-EntriesToApi {
param (
    [string]$FilePath,
    [string]$FileType,
    [string]$DomainName,
    [int]$MaxRetries,
    [int]$BatchSize,
    [bool]$enableVerboseMode,
    [bool]$enableConsoleOutput,
    [int]$ThrottleDelayMs,
    [string]$tempDailyFolder,
    [string]$Date,
    [string]$activityLogPath,
    [string]$ApiUrl,
    [object]$Headers,
    [string]$SecretDelivery,
    [string]$Secret,
    [int]$MaxConcurrentJobs
)

    $csvData = Import-Csv -Path $FilePath
    $scriptName = "Push-EntriesToApi"
    $allBatches = @()
    $batch = @()

    function Log-Activity {
        param (
            [string]$DomainName,
            [string]$RemoteComputer,
            [string]$ScriptName,
            [string]$ActionType,
            [string]$Message,
            [bool]$enableVerboseMode,
            [bool]$enableConsoleOutput
        )

        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

        $allowedActions = @("INFO", "SUCCESS", "WARNING", "ERROR", "RUNTIME", "NOTIFY", "RETRY", "THROTTLE", "PROGRESS", "DEBUG")
        if ($allowedActions -notcontains $ActionType.ToUpper()) {
            $ActionType = "INFO"
        }

        $stackTag = ""
            if ($enableVerboseMode) {
                $invocation = $MyInvocation
                $callerFunc   = if ($invocation.MyCommand) { $invocation.MyCommand.Name } else { $null }
                $callerScript = $invocation.ScriptName
                $callerLine   = $invocation.ScriptLineNumber

                if ($callerFunc -and $callerScript) {
                    $stackTag = " (at $($callerFunc):$callerLine in $callerScript)"
                } elseif ($callerFunc) {
                    $stackTag = " (in $callerFunc)"
                } else {
                    $stackTag = ""
                }
            }

        $line = "[$timestamp] [$ActionType] [$DomainName] [$RemoteComputer] [$ScriptName] $Message$stackTag"

        try {
            Add-Content -Path $activityLogPath -Value $line
        } catch {
            Write-Warning "Failed to write log entry to file: $($_.Exception.Message)"
        }

        if ($enableConsoleOutput) {
            $color = switch ($ActionType.ToUpper()) {
                "INFO"     { "Cyan" }
                "SUCCESS"  { "Green" }
                "WARNING"  { "Yellow" }
                "ERROR"    { "Red" }
                "RUNTIME"  { "White" }
                "NOTIFY"   { "Blue" }
                "RETRY"    { "DarkYellow" }
                "THROTTLE" { "Magenta" }
                "PROGRESS" { "Gray" }
                "DEBUG"    { "DarkGray" }
                default    { "Gray" }
            }
            Write-Host $line -ForegroundColor $color
        }
    }


    foreach ($row in $csvData) {
        $batch += $row
        if ($batch.Count -eq $batchSize) {
            $allBatches += ,$batch
            $batch = @()
        }
    }
    if ($batch.Count -gt 0) { $allBatches += ,$batch }

    $jobs = @()
    $batchId = 0

    # Initialize variables for progress reporting
    $recordTotal = $csvData.Count
    $recordIndex = 0

    foreach ($batchData in $allBatches) {
        # Cleanup any completed jobs
        $jobs = $jobs | Where-Object { $_.State -in @('Running', 'NotStarted') }
        # Throttle: wait until the number of running jobs is below the limit
        while (@($jobs | Where-Object { $_.State -eq 'Running' }).Count -ge $MaxConcurrentJobs) {
            Start-Sleep -Milliseconds 500
        }
        $currentBatchId = $batchId++
        $logFileExt = if ($enableVerboseMode) { "json" } else { "log" }
        $logFile = Join-Path $tempDailyFolder "PushDiagnostics-Batch-$currentBatchId-$Date.$logFileExt"

        $batchCountTotal = $allBatches.Count
        
        Log-Activity $DomainName $FilePath $scriptName "DEBUG" "Starting batch $currentBatchId of $batchCountTotal (size: $($batchData.Count))"

        if ($enableConsoleOutput) {
            $percentComplete = if ($recordTotal -gt 0) { ($recordIndex / $recordTotal) * 100 } else { 0 }
            Write-Progress -Activity "Domain: $DomainName" `
                        -Status "Pushing record $recordIndex of $recordTotal in batch $logFile" `
                        -PercentComplete $percentComplete
        }

        $job = Start-ThreadJob -ScriptBlock {
            param (
                $BatchRows,           # 0
                $FileType,            # 1
                $ApiUrl,              # 2
                $Headers,             # 3
                $SecretDelivery,      # 4
                $Secret,              # 5
                $DomainName,          # 6
                $scriptName,          # 7
                $logFile,             # 8
                $MaxRetries,          # 9
                $enableVerboseMode,   # 10
                $ThrottleDelayMs,     # 11
                $enableConsoleOutput, # 12
                $activityLogPath,     # 13
                $currentBatchId,      # 14
                $Date                 # 15
            )

            # Ensure headers are a real hashtable before use in REST calls
            if ($Headers -isnot [hashtable]) {
                $headersHashtable = @{}
                foreach ($prop in $Headers.PSObject.Properties) {
                    $headersHashtable[$prop.Name] = $prop.Value
                }
                $Headers = $headersHashtable
            }


            function Remove-NonAscii {
                param ([string]$text)
                return -join ($text.ToCharArray() | Where-Object { [int][char]$_ -le 127 })
            }

            function Convert-ToBool ($val) {
                return [bool]::Parse(($val.ToString()).ToLower())
            }

            function Convert-ToIsoDate ($val) {
                try { if ($val) { return ([datetime]$val).ToUniversalTime().ToString("o") } } catch { return $null }
            }

            function Convert-RowToPayload {
                param ($row, $FileType)

                foreach ($key in $row.PSObject.Properties.Name) {
                    $row.$key = Remove-NonAscii $row.$key
                }

            switch ($FileType) {
                "User" {
                    return @{
                        UserDistinguishedName        = $row.DistinguishedName
                        UserEnabled                  = Convert-ToBool $row.Enabled
                        UserGivenName                = $row.GivenName
                        UserLastLogonDate            = Convert-ToIsoDate $row.LastLogonDate
                        UserName                     = $row.Name
                        UserObjectClass              = $row.ObjectClass
                        UserObjectGUID               = $row.ObjectGUID
                        UserPasswordExpired          = Convert-ToBool $row.PasswordExpired
                        UserPasswordLastSet          = Convert-ToIsoDate $row.PasswordLastSet
                        UserPasswordNeverExpires     = Convert-ToBool $row.PasswordNeverExpires
                        UserSamAccountName           = $row.SamAccountName
                        UserSID                      = $row.SID
                        UserSurname                  = $row.Surname
                        UserUserPrincipalName        = $row.UserPrincipalName
                        UserwhenCreated              = Convert-ToIsoDate $row.whenCreated
                    }
                }
                "Group" {
                    return @{
                        GroupDistinguishedName                 = $row.DistinguishedName
                        GroupForest                            = $row.Forest
                        GroupEnabled                           = Convert-ToBool $row.Enabled
                        GroupGroupDomain                       = $row.GroupDomain
                        GroupGroupName                         = $row.GroupName
                        GroupName                              = $row.Name
                        GroupObjectClass                       = $row.ObjectClass
                        GroupMemberObjectGUID                  = $row.ObjectGUID
                        GroupGroupScope                        = $row.GroupScope
                        GroupGroupCategory                     = $row.GroupCategory
                        GroupSamAccountName                    = $row.SamAccountName
                        GroupSID                               = $row.SID
                        GroupProtectedFromAccidentalDeletion   = Convert-ToBool $row.ProtectedFromAccidentalDeletion
                        GroupwhenChanged                       = Convert-ToIsoDate $row.whenChanged
                        GroupwhenCreated                       = Convert-ToIsoDate $row.whenCreated
                        GroupNestedTrail                       = $row.NestedTrail
                        GroupDomain                            = $row.UserDomain
                    }
                }
            }

            }

            function Log-Activity {
                param (
                    [string]$DomainName,
                    [string]$RemoteComputer,
                    [string]$ScriptName,
                    [string]$ActionType,
                    [string]$Message,
                    [bool]$enableVerboseMode,
                    [bool]$enableConsoleOutput
                )

                $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

                $allowedActions = @("INFO", "SUCCESS", "WARNING", "ERROR", "RUNTIME", "NOTIFY", "RETRY", "THROTTLE", "PROGRESS", "DEBUG")
                if ($allowedActions -notcontains $ActionType.ToUpper()) {
                    $ActionType = "INFO"
                }

                $stackTag = ""
                    if ($enableVerboseMode) {
                        $invocation = $MyInvocation
                        $callerFunc   = if ($invocation.MyCommand) { $invocation.MyCommand.Name } else { $null }
                        $callerScript = $invocation.ScriptName
                        $callerLine   = $invocation.ScriptLineNumber

                        if ($callerFunc -and $callerScript) {
                            $stackTag = " (at $($callerFunc):$callerLine in $callerScript)"
                        } elseif ($callerFunc) {
                            $stackTag = " (in $callerFunc)"
                        } else {
                            $stackTag = ""
                        }
                    }

                $line = "[$timestamp] [$ActionType] [$DomainName] [$RemoteComputer] [$ScriptName] $Message$stackTag"

                try {
                    Add-Content -Path $activityLogPath -Value $line
                } catch {
                    Write-Warning "Failed to write log entry to file: $($_.Exception.Message)"
                }

                if ($enableConsoleOutput) {
                    $color = switch ($ActionType.ToUpper()) {
                        "INFO"     { "Cyan" }
                        "SUCCESS"  { "Green" }
                        "WARNING"  { "Yellow" }
                        "ERROR"    { "Red" }
                        "RUNTIME"  { "White" }
                        "NOTIFY"   { "Blue" }
                        "RETRY"    { "DarkYellow" }
                        "THROTTLE" { "Magenta" }
                        "PROGRESS" { "Gray" }
                        "DEBUG"    { "DarkGray" }
                        default    { "Gray" }
                    }
                    Write-Host $line -ForegroundColor $color
                }
            }

            function Push-OneRecord {
                param (
                    $payload,
                    $identity,
                    [int]$attempt,
                    [bool]$enableVerboseMode,
                    [string]$logFile,
                    [bool]$enableConsoleOutput,
                    [int]$ThrottleDelayMs
                )

                if ($SecretDelivery -eq "Body") {
                    $payload = @{ data = $payload; secret = $Secret }
                }

                $start = [datetime]::UtcNow
                $entry = @{
                    Timestamp     = $start.ToString("o")
                    Domain        = $DomainName
                    FileType      = $FileType
                    Identity      = $identity
                    Attempt       = $attempt
                    DurationMs    = 0
                    Success       = $false
                    Error         = $null
                    StatusCode    = $null
                    ResponseBody  = $null
                    Url           = $finalUri
                    Headers       = $Headers

                    UserSamAccountName       = $payload.UserSamAccountName
                    GroupSamAccountName      = $payload.GroupSamAccountName
                    UserName                 = $payload.UserName
                    GroupName                = $payload.GroupName
                    UserDistinguishedName    = $payload.UserDistinguishedName
                    GroupDistinguishedName   = $payload.GroupDistinguishedName

                    Payload       = $payload
                }

                $entry.Url = $ApiUrl
                try {
                    if ($SecretDelivery -eq "Body") {
                        $payload = [pscustomobject]@{
                            data   = $payload
                            secret = $Secret
                        }
                    }
                    $json = ConvertTo-Json $payload -Depth 5
                    Invoke-RestMethod -Uri $ApiUrl -Method Post -Headers $Headers -Body $json

                    $end = [datetime]::UtcNow
                    $entry.DurationMs = [math]::Round(($end - $start).TotalMilliseconds, 2)
                    $entry.Success = $true
                } catch {
                    $entry.Error = $_.Exception.Message

                    if ($_.Exception.Response -ne $null) {
                        try {
                            $entry.StatusCode = $_.Exception.Response.StatusCode.value__
                        } catch {
                            $entry.StatusCode = -1
                        }

                        # Capture HTTP response body
                        try {
                            $stream = $_.Exception.Response.GetResponseStream()
                            if ($stream) {
                                $reader = New-Object System.IO.StreamReader($stream)
                                $entry.ResponseBody = $reader.ReadToEnd()
                            }
                        } catch {
                            $entry.ResponseBody = "<Could not read response body: $($_.Exception.Message)>"
                        }
                    } else {
                        $entry.StatusCode = -1
                    }
                }

                if ($enableVerboseMode -or -not $entry.Success) {
                    $entry | ConvertTo-Json -Depth 4 | Out-File -FilePath $logFile -Append -Encoding UTF8
                    Log-Activity $DomainName $logFile $scriptName "DEBUG" "Wrote verbose record to $logFile" $enableVerboseMode $enableConsoleOutput
                } else {
                    $summary = "$($entry.Timestamp),$($entry.Domain),$($entry.FileType),$($entry.Identity),$($entry.Attempt),$($entry.Success)"
                    Add-Content -Path $logFile -Value $summary
                }

                if ($enableVerboseMode -and $attempt -gt 1) {
                    $retryInfo = "Retry $attempt for $($identity): $($entry.Error)"
                    Log-Activity $DomainName $logFile $scriptName "RETRY" $retryInfo $enableVerboseMode $enableConsoleOutput
                }

                if ($ThrottleDelayMs -gt 0 -and $enableVerboseMode) {
                    Log-Activity $DomainName $logFile $scriptName "THROTTLE" "Sleeping $ThrottleDelayMs ms before next record" $enableVerboseMode $enableConsoleOutput
                }

                if ($ThrottleDelayMs -gt 0) {
                    Start-Sleep -Milliseconds $ThrottleDelayMs
                }

                return $entry.Success
            }


            function Log-Activity {
                param (
                    [string]$DomainName,
                    [string]$RemoteComputer,
                    [string]$ScriptName,
                    [string]$ActionType,
                    [string]$Message,
                    [bool]$enableVerboseMode,
                    [bool]$enableConsoleOutput
                )

                $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

                $allowedActions = @("INFO", "SUCCESS", "WARNING", "ERROR", "RUNTIME", "NOTIFY", "RETRY", "THROTTLE", "PROGRESS", "DEBUG")
                if ($allowedActions -notcontains $ActionType.ToUpper()) {
                    $ActionType = "INFO"
                }

                $stackTag = ""
                    if ($enableVerboseMode) {
                        $invocation = $MyInvocation
                        $callerFunc   = if ($invocation.MyCommand) { $invocation.MyCommand.Name } else { $null }
                        $callerScript = $invocation.ScriptName
                        $callerLine   = $invocation.ScriptLineNumber

                        if ($callerFunc -and $callerScript) {
                            $stackTag = " (at $($callerFunc):$callerLine in $callerScript)"
                        } elseif ($callerFunc) {
                            $stackTag = " (in $callerFunc)"
                        } else {
                            $stackTag = ""
                        }
                    }


                $line = "[$timestamp] [$ActionType] [$DomainName] [$RemoteComputer] [$ScriptName] $Message$stackTag"

                try {
                    Add-Content -Path $activityLogPath -Value $line
                } catch {
                    Write-Warning "Failed to write log entry to file: $($_.Exception.Message)"
                }

                if ($enableConsoleOutput) {
                    $color = switch ($ActionType.ToUpper()) {
                        "INFO"     { "Cyan" }
                        "SUCCESS"  { "Green" }
                        "WARNING"  { "Yellow" }
                        "ERROR"    { "Red" }
                        "RUNTIME"  { "White" }
                        "NOTIFY"   { "Blue" }
                        "RETRY"    { "DarkYellow" }
                        "THROTTLE" { "Magenta" }
                        "PROGRESS" { "Gray" }
                        "DEBUG"    { "DarkGray" }
                        default    { "Gray" }
                    }
                    Write-Host $line -ForegroundColor $color
                }
            }

            $success = 0
            $fail = 0
            $retryQueue = @()
            
            $batchStartTime = Get-Date
            $recordTotal = $BatchRows.Count
            $recordIndex = 0

            foreach ($row in $BatchRows) {
                $payload = Convert-RowToPayload -row $row -FileType $FileType
                if ($payload.UserSamAccountName) {
                    $identity = $payload.UserSamAccountName
                } elseif ($payload.GroupSamAccountName) {
                    $identity = $payload.GroupSamAccountName
                } else {
                    $identity = "<unknown>"
                }

                $recordIndex++
                if ($enableConsoleOutput) {
                    $percentComplete = if ($recordTotal -gt 0) { ($recordIndex / $recordTotal) * 100 } else { 0 }
                    Write-Progress -Activity "Domain: $DomainName" `
                                -Status "Pushing record $recordIndex of $recordTotal in batch $logFile" `
                                -PercentComplete $percentComplete

                }

                if (-not (Push-OneRecord -payload $payload -identity $identity -attempt 1 -enableVerboseMode $enableVerboseMode -logFile $logFile -enableConsoleOutput $enableConsoleOutput -ThrottleDelayMs $ThrottleDelayMs)) {
                    $retryQueue += ,@{ row = $row; id = $identity }
                } else {
                    $success++
                }
            }

            for ($i = 1; $i -le $MaxRetries; $i++) {
                if ($retryQueue.Count -eq 0) { break }
                $nextQueue = @()

                foreach ($item in $retryQueue) {
                    $payload = Convert-RowToPayload -row $item.row -FileType $FileType
                    if (-not (Push-OneRecord -payload $payload -identity $item.id -attempt ($i + 1) -enableVerboseMode $enableVerboseMode -logFile $logFile -enableConsoleOutput $enableConsoleOutput -ThrottleDelayMs $ThrottleDelayMs)) {
                        $nextQueue += ,$item
                    } else {
                        $success++
                    }
                }

                $retryQueue = $nextQueue
            }

            $fail = $retryQueue.Count
            return [PSCustomObject]@{
                Success = $success
                Failure = $fail
            }

            $batchEndTime = [datetime]::UtcNow
            $duration = [math]::Round(($batchEndTime - $batchStartTime).TotalSeconds, 2)

            $manifest = @{
                BatchId      = $currentBatchId
                Domain       = $DomainName
                FileType     = $FileType
                LogFile      = $logFile
                TotalRecords = $BatchRows.Count
                Successes    = $success
                Failures     = $fail
                DurationSec  = $duration
                Timestamp    = (Get-Date -Format "o")
            }

            try {
                $manifestPath = [System.IO.Path]::ChangeExtension($logFile, ".manifest.json")
                $manifest | ConvertTo-Json -Depth 5 | Out-File -FilePath $manifestPath -Encoding UTF8 -Force
                Log-Activity $DomainName $logFile $scriptName "DEBUG" "Exported $logFile to $manifestPath."
            } catch {
                Log-Activity $DomainName $logFile $scriptName "ERROR" "Unable to export $logFile to $manifestPath." 
            }

            # CSV stats
            try {
                $csvLine = "$currentBatchId,$DomainName,$FileType,$($BatchRows.Count),$success,$fail,$duration,$logFile"
                $csvPath = [System.IO.Path]::ChangeExtension($logFile, ".stats.csv")
                "BatchId,Domain,FileType,Total,Success,Fail,DurationSec,LogFile" | Out-File $csvPath -Encoding UTF8
                $csvLine | Out-File $csvPath -Append -Encoding UTF8
                Log-Activity $DomainName $logFile $scriptName "DEBUG" "Exported $csvPath."
            } catch {
                Log-Activity $DomainName $logFile $scriptName "ERROR" "Unable to export to $csvPath." 
            }

            Log-Activity $DomainName $logFile $scriptName "DEBUG" "Completed batch $logFile in $duration sec ($success succeeded, $fail failed)"
        } -ArgumentList @(
            $batchData,             # 0
            $FileType,              # 1
            $ApiUrl,                # 2
            $Headers,               # 3
            $SecretDelivery,        # 4
            $Secret,                # 5
            $DomainName,            # 6
            $scriptName,            # 7
            $logFile,               # 8
            $MaxRetries,            # 9
            $enableVerboseMode,     # 10
            $ThrottleDelayMs,       # 11
            $enableConsoleOutput,   # 12
            $activityLogPath,       # 13
            $currentBatchId,        # 14
            $Date                   # 15
        )

        # Check for nulls and add to the array if not
        if ($null -ne $job) {
            $jobs += $job
        } else {
            Log-Activity $DomainName $FilePath $scriptName "ERROR" "Thread job creation failed for batch $currentBatchId"
        }
    }

    # Wait for push batches to complete
    Log-Activity "<Batch>" $FilePath $scriptName "INFO" "Waiting for $($jobs.Count) push batches to finish..."
    $validJobs = $jobs | Where-Object { $_ -ne $null }
    Wait-Job -Job $validJobs

    $allResults = @()
    $failedCount = 0

    foreach ($job in $validJobs) {
        $jobName = if ($job.Name) { $job.Name } else { "JobId:$($job.Id)" }

        switch ($job.State) {
            'Completed' {
                try {
                    $allResults += Receive-Job -Job $job -ErrorAction Stop
                } catch {
                    Log-Activity $DomainName $jobName $scriptName "ERROR" "Failed to receive job output: $($_.Exception.Message)" $enableVerboseMode $enableConsoleOutput
                }
            }

            'Failed' {
                $failedCount++
                try {
                    $jobErrors = ($job.ChildJobs | ForEach-Object { $_.JobStateInfo.Reason }) -join '; '
                    if (-not $jobErrors) {
                        $jobErrors = $job.JobStateInfo.Reason.Exception.Message
                    }
                    Log-Activity $DomainName $jobName $scriptName "ERROR" "Thread job failed: $jobErrors" $enableVerboseMode $enableConsoleOutput
                } catch {
                    Log-Activity $DomainName $jobName $scriptName "ERROR" "Unable to retrieve error info: $($_.Exception.Message)" $enableVerboseMode $enableConsoleOutput
                }
            }

            default {
                Log-Activity $DomainName $jobName $scriptName "WARNING" "Job in unexpected state: $($job.State)" $enableVerboseMode $enableConsoleOutput
            }
        }
    }

    if ($failedCount -gt 0) {
        Log-Activity $DomainName "<ThreadJob>" $scriptName "ERROR" "$failedCount jobs failed unexpectedly." $enableVerboseMode $enableConsoleOutput
    }

    # Final success/failure counts
    $SuccessCount = ($allResults | Measure-Object Success -Sum).Sum
    $FailureCount = ($allResults | Measure-Object Failure -Sum).Sum

    # Cleanup
    Remove-Job -Job $validJobs
    Log-Activity "<Batch>" $FilePath $scriptName "SUCCESS" "All batches complete." $enableVerboseMode $enableConsoleOutput

}

function Zip-PushResults {
    param (
        [string]$tempFolder,
        [string]$dailyFolder,
        [string]$DayStamp,
        [string]$activityLogPath,
        [bool]$enableVerboseMode,
        [bool]$enableConsoleOutput,
        [int]$attachmentSize,  # In bytes
        [switch]$PushResults,
        [switch]$Attachment
    )

    $scriptName = "Zip-PushResults"

    if ($PushResults) {
        $domainFolders = Get-ChildItem -Path $tempFolder -Directory

        foreach ($domainFolder in $domainFolders) {
            $domainName = $domainFolder.Name
            $sourcePath = $domainFolder.FullName
            $targetPath = Join-Path $dailyFolder $domainName
            $zipNameBase = "$domainName-pushresults-$DayStamp.zip"
            $zipPath = Join-Path $targetPath $zipNameBase

            # Ensure target folder exists
            if (-not (Test-Path $targetPath)) {
                New-Item -Path $targetPath -ItemType Directory | Out-Null
            }

            # Handle name collisions with incrementing suffix
            $counter = 1
            while (Test-Path $zipPath) {
                $zipNameBase = "$domainName-pushresults-$DayStamp-$counter.zip"
                $zipPath = Join-Path $targetPath $zipNameBase
                $counter++
            }

            try {
                Compress-Archive -Path (Join-Path $sourcePath '*') -DestinationPath $zipPath -Force
                Log-Activity $domainName $zipPath $scriptName "SUCCESS" "Zipped processed results to $zipPath" $enableVerboseMode $enableConsoleOutput
            } catch {
                Log-Activity $domainName $zipPath $scriptName "ERROR" "Failed to zip ${sourcePath}: $($_.Exception.Message)" $enableVerboseMode $enableConsoleOutput
            }
        }
    }

    if ($Attachment) {
        try {
            $logFile = Get-Item -Path $activityLogPath -ErrorAction Stop
            if ($logFile.Length -gt $attachmentSize) {
                $zipName = [System.IO.Path]::ChangeExtension($activityLogPath, ".zip")
                $counter = 1

                while (Test-Path $zipName) {
                    $zipName = $activityLogPath -replace '\.csv$', "-$counter.zip"
                    $counter++
                }

                Compress-Archive -Path $activityLogPath -DestinationPath $zipName -Force
                Log-Activity "System" $activityLogPath $scriptName "INFO" "Activity log exceeded $attachmentSize bytes. Zipped to $zipName" $enableVerboseMode $enableConsoleOutput
                return $zipName
            } else {
                Log-Activity "System" $activityLogPath $scriptName "INFO" "Activity log size below $attachmentSize bytes. No action taken." $enableVerboseMode $enableConsoleOutput
                return $activityLogPath
            }
        } catch {
            Log-Activity "System" $activityLogPath $scriptName "ERROR" "Failed during attachment zip check: $($_.Exception.Message)" $enableVerboseMode $enableConsoleOutput
        }
    }
}

# Log configuration variables if verbose mode is enabled
Show-Configuration

# Run function to clean old reports, activity logs, and so on.
Clean-OldPushes -outputRoot $outputRoot -RetentionDays $RetentionDays -enableVerboseMode $enableVerboseMode -enableConsoleOutput $enableConsoleOutput

# Find the existing zipped output files - must match *-[domain]-results-$DayStamp.zip format - and expand into the temp folder
Expand-ZipsToTemp -rootFolder $rootFolder -tempFolder $tempFolder -Expand

# Build a list of CSV files from the temp folder
$csvFiles = Get-ChildItem -Path $tempFolder -Filter *.csv -Recurse

# Filter the CSV files for today's date
$matchedFiles = $csvFiles | Where-Object { $_.Name -like "*$dayStamp*"}

# If there's matching files, process the files
if ($matchedFiles.Count -eq 0) {
    Log-Activity "<API>" "<None>" $scriptName "INFO" "No matching CSV files found for today's date: $dayStamp"
} else {
    foreach ($file in $matchedFiles) {
        $domain = $file.BaseName -split '-' | Select-Object -First 1
        if ($file.Name -like "*AD_User_Export*") {
            Log-Activity "<Scan>" $file.FullName $scriptName "INFO" "Matched user export file: $($file.Name), importing."
            Push-EntriesToApi `
                -FilePath $file.FullName `
                -FileType "User" `
                -DomainName $domain `
                -MaxRetries $MaxRetries `
                -BatchSize $BatchSize `
                -enableVerboseMode $enableVerboseMode `
                -enableConsoleOutput $enableConsoleOutput `
                -ThrottleDelayMs $ThrottleDelayMs `
                -tempDailyFolder $tempDailyFolder `
                -Date $dayStamp `
                -activityLogPath $activityLogPath `
                -ApiUrl $ApiUrl `
                -Headers $Headers `
                -SecretDelivery $SecretDelivery `
                -Secret $Secret `
                -MaxConcurrentJobs $MaxConcurrentJobs
        }
        elseif ($file.Name -like "*GroupMembership*") {
            Log-Activity "<Scan>" $file.FullName $scriptName "INFO" "Matched group export file: $($file.Name), importing."
            Push-EntriesToApi `
                -FilePath $file.FullName `
                -FileType "Group" `
                -DomainName $domain `
                -MaxRetries $MaxRetries `
                -BatchSize $BatchSize `
                -enableVerboseMode $enableVerboseMode `
                -enableConsoleOutput $enableConsoleOutput `
                -ThrottleDelayMs $ThrottleDelayMs `
                -tempDailyFolder $tempDailyFolder `
                -Date $dayStamp `
                -activityLogPath $activityLogPath `
                -ApiUrl $ApiUrl `
                -Headers $Headers `
                -SecretDelivery $SecretDelivery `
                -Secret $Secret `
                -MaxConcurrentJobs $MaxConcurrentJobs
        }
        else {
            Log-Activity "<Scan>" $file.FullName $scriptName "ERROR" "File matched date but not user/group pattern"
        }
    }
}

# Create the path for the email attachment based on whether it's bigger than $attachmentSize
$zipAttachmentPath = Zip-PushResults -tempFolder $tempFolder -dailyFolder $dailyFolder -DayStamp $DayStamp `
                    -activityLogPath $activityLogPath -enableVerboseMode $enableVerboseMode `
                    -enableConsoleOutput $enableConsoleOutput -attachmentSize $attachmentSize `
                    -Attachment

# Compress the results from the temp folder into the standard daily folders, zipped by domain
Zip-PushResults -tempFolder $tempFolder -dailyFolder $dailyFolder -DayStamp $DayStamp `
                -activityLogPath $activityLogPath -enableVerboseMode $enableVerboseMode `
                -enableConsoleOutput $enableConsoleOutput -attachmentSize $attachmentSize `
                -PushResults

# After all files processed
$CsvCount       = $matchedFiles.Count
$ScriptDuration = (Get-Date) - $scriptStartTime
$TotalSeconds   = [int]$ScriptDuration.TotalSeconds
$scriptTimeMin  = "{0:F3}" -f $scriptDuration.TotalMinutes

# Log final summary
Log-Activity "<Summary>" "<Local>" $scriptName "INFO"  "CSV files processed : $CsvCount"
Log-Activity "<Summary>" "<Local>" $scriptName "INFO"  "Records imported     : $SuccessCount"
Log-Activity "<Summary>" "<Local>" $scriptName "INFO"  "Records failed       : $FailureCount"
Log-Activity "<Summary>" "<Local>" $scriptName "INFO"  "Avg time per CSV     : $([math]::Round($TotalSeconds / [math]::Max($CsvCount,1),2)) seconds"
Log-Activity "<Summary>" "<Local>" $scriptName "INFO"  "Total execution time: $ScriptTimeMin minutes ($TotalSeconds seconds)"

# Email report (if enabled)
if ($sendEmail -and (-not $OnlyEmailIfFailures -or $FailureCount -gt 0)) {
    Send-EmailReport -ScriptDuration $ScriptDuration `
                     -SuccessCount $SuccessCount `
                     -FailureCount $FailureCount `
                     -CsvCount     $CsvCount `
                     -Date         $Date `
                     -LogPath      $activityLogPath `
                     -ZipAttachmentPath $ZipAttachmentPath
} else {
    Log-Activity "<Summary>" "<Local>" "EmailReport" "INFO" "Email sending is DISABLED. No report was sent."
}