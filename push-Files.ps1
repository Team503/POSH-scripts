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
    .\Push-FilesToOlympus.ps1 -SecretDelivery Body -EnableVerboseMode:$true -enableConsoleOutput:$false

    Pushes records with secret in JSON body and logs everything in detail, useful for troubleshooting or dry runs.

.EXAMPLE
    powershell.exe -File "Push-FilesToOlympus.ps1" -ThrottleDelayMs 250 -OnlyEmailIfFailures:$true

    Runs with 250ms throttling and only sends emails if failures occurred.

.NOTES
    Author       : Alex Cherry
    Script Name  : Push-FilesToOlympus.ps1
    Version      : v2.4.1
    Last Updated : 2025-07-16

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
    v2.4.1 - Added HTTP logging when verbose mode is on, added date override parameter
    v2.5.2 - Working push mechanism and logging, added max concurrent jobs
             THIS IS PRODUCTION READY UNLESS THE HEADERS/AUTH/REQUEST NEED TO BE CHANGED
    v2.5.3 - Fixed email counters, made job processing more efficient
    v3.0.1 - Refactored script to create JSON entries into files, then stream those files with a compressed gZip binary stream
    v3.1.1 - Broke up push-entriesToApi function and moved threading into root for more logical script structure.
    v3.1.2 - Continued debugging of changes to structure
    v3.1.3 - Updated function Convert-ToIsoDate to handle different formats and invalid values
    v3.1.4 - Added file cleanup at the end, cleaned up a few error handling issues
    v3.1.5 - Cleaned up file paths in ZIP functions to be consistent, added HTTP response logging, corrected hashtable error for invoke-webrequest
    v3.1.6 - Added filters for null $Date values and improved error handling
    v3.1.7 - Added $FileType to entityKey and function Upload-GzippedBatch
    v3.1.8 - Added more robust job handling, fixed path error in $outputFiles
    v3.1.9 - Added $ApiURL logging, added retry/wait to log-activity to prevent collisions, updated Help function
    v3.2.0 - Closed $ms stream at the end of Upload-GzippedBatch function, changed batch logging to include a new GUID for uniqueness to prevent collisions
    v3.2.2 - Added additional logging and updated the Log-Activity function, changed $jobs to $pushJobs to avoid shadowing
    v3.3.1 - Cleaned up duplicate function declarations, added some debugging output
#>

# Accept command line parameter to choose secret delivery type, defaults to Header
param (
    [ValidateSet("Header", "HeaderCustom", "Query", "Body", "None")]
    [string]$SecretDelivery         = "None",
    [string]$scriptName             = "Push-FilesToRESTapi",
    [string]$BaseUrl                = "https://RestAPI.server.com:443",
    [string]$Endpoint               = "/upload/batch",
    [string]$BearerToken            = "token",
    [string]$Secret                 = "",
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
    [int]   $MaxConcurrentJobs      = 10,
    [string]$emailTo                = "user@company.com",
    [string]$emailFrom              = "script-bot@company.com",
    [string]$smtpServer             = "mail.company.com",
    [int]   $smtpPort               = 25,
    [string]$RunDate,
    [int]$attachmentSize            = 100KB,
    [int]$LogWriteRetries           = 5,
    [int]$retryDelayMs              = 200,
    [switch]$Help
)

# Help Detection (bound or raw CLI)
$rawArgs = $args -join " "
$showHelp = $Help -or
             $rawArgs -match "(?i)\b(help|\/\?|--help|\?)\b" -or
             $PSBoundParameters.ContainsKey("help")

if ($showHelp) {
    Write-Host @"
USAGE: .\Push-FilesToOlympus.ps1 [-RunDate yyyy-MM-dd] [-SecretDelivery Header|HeaderCustom|Query|Body|None] [-enableVerboseMode] [-sendEmail] ...

DESCRIPTION:
  Uploads Active Directory exports to Olympus ingestion API. Supports batching, retries, and configurable delivery settings.

PARAMETERS:

  -SecretDelivery         [$Secret location]: 'Header', 'HeaderCustom', 'Query', 'Body', or 'None'. Default: 'None'

  -scriptName             Script name tag for logs. Default: 'Push-FilesToRESTapi'

  -BaseUrl                Root ingestion API URL. Default: ''

  -Endpoint               API path to append to BaseUrl. Default: '/upload/batch'

  -BearerToken            Optional static bearer token for authorization header

  -Secret                 Optional static API secret (used with SecretDelivery)

  -rootFolder             Root folder for reports. Default: 'C:\Scripts\ADreports'

  -OutputFolder           Subfolder under root for exported files. Default: 'output'

  -RunDate                Optional override for export date. Format: yyyy-MM-dd

  -enableConsoleOutput    Display log entries to console. Default: true

  -enableVerboseMode      Include function+line context in log entries. Default: true

  -sendEmail              Send summary email on completion. Default: true

  -OnlyEmailIfFailures    Only send email if there were any errors. Default: false

  -RetentionDays          Days to retain log/output files. Default: 30

  -BatchSize              Max items per push batch. Default: 100

  -ThrottleDelayMs        Delay between push batches (in ms). Default: 0

  -MaxConcurrentJobs      Number of parallel jobs. Default: 10

  -emailTo                Email recipients (comma-separated). Default: user@company.com

  -emailFrom              SMTP from-address. Default: script-bot@company.com

  -smtpServer             SMTP server address. Default: mail.company.com

  -smtpPort               SMTP server port. Default: 25

  -attachmentSize         Max zipped attachment size per email (in KB). Default: 100KB

  -LogWriteRetries        Max attempts to log to file before warning. Default: 5

  -retryDelayMs           Milliseconds between log retries. Default: 200

  -Help                   Show this help message and exit

"@ | Write-Host
    exit 0
}

# Headers initialized
$Headers = [pscustomobject]@{
    "Authorization" = "Bearer $BearerToken"
    "Content-Type"  = "application/json"
}

# --- Email Config ---
$emailTo    = "alex.cherry@oracle.com"
$emailFrom  = "script-bot@cernerasp.com"
$smtpServer = "mail.cernerasp.com"
$smtpPort   = 25

# --- Script Info ---
$scriptversion  = "v3.3.1"
$scriptauthor   = "Alex Cherry"
$scriptupdated  = "2025-07-28"

# --- Create variable dependent values ---
$outputRoot     = Join-Path $rootFolder $OutputFolder
$tempFolder     = Join-Path $rootfolder "temp"

# --- Allow parameter-based override of date, and build date-based variables
if ($RunDate) {
    try {
        $parsedDate = Get-Date $RunDate -ErrorAction Stop
        $DayStamp = $parsedDate.ToString("yyyy-MM-dd")
        $Date     = $parsedDate.ToString("yyyy-MM-dd") # HHmm_
    } catch {
        Write-Error "Invalid -RunDate format. Use yyyy-MM-dd. Example: -RunDate '2025-07-15'"
        exit 1
    }
} else {
    $Date     = Get-Date -Format "yyyy-MM-dd" # HHmm_
    $DayStamp = Get-Date -Format "yyyy-MM-dd"
}
$BaseUrl         = "$($BaseUrl.TrimEnd('/'))$($Endpoint)"
$dailyFolder     = Join-Path $outputRoot $DayStamp 
$pushFolder      = Join-Path $dailyFolder "DailyPush"
$tempFolder      = Join-Path $rootfolder "temp"
$failuresFolder  = Join-Path $pushFolder "FailedPushes"
$tempDailyFolder = Join-Path $tempFolder $DayStamp


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

    # Append caller info if verbose mode is on
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
        }
    }

    $line = "[$timestamp] [$ActionType] [$DomainName] [$RemoteComputer] [$ScriptName] $Message$stackTag"

    # Respect enableVerboseMode for DEBUG logging
    $shouldLog = $ActionType.ToUpper() -ne 'DEBUG' -or $enableVerboseMode

    if ($shouldLog) {
        for ($i = 1; $i -le $LogWriteRetries; $i++) {
            try {
                Add-Content -Path $activityLogPath -Value $line
                break
            } catch {
                if ($i -eq $LogWriteRetries) {
                    Write-Warning "Log-Activity failed after $LogWriteRetries attempts: $($_.Exception.Message)"
                } else {
                    Start-Sleep -Milliseconds $retryDelayMs
                }
            }
        }
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
    Log-Activity "<Config>" "<Local>" $scriptName "DEBUG" "BearerToken Set       : $($null -ne $BearerToken -and $BearerToken -ne '')"
    Log-Activity "<Config>" "<Local>" $scriptName "DEBUG" "Secret Set            : $($null -ne $Secret -and $Secret -ne '')"
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
        [Parameter(Mandatory = $true)][string]$DayStamp,
        [switch]$Expand,
        [switch]$Cleanup
    )

    $domainName     = "Local"
    $remoteComputer = $env:ComputerName

    if ($Expand) {
        $fullTempPath = Join-Path $tempFolder $DayStamp

        if (Test-Path $fullTempPath) {
            Log-Activity $domainName $remoteComputer $scriptName "INFO" "Cleaning up existing temp folder: $fullTempPath" $enableVerboseMode $enableConsoleOutput
            Remove-Item -Path $fullTempPath -Recurse -Force
        }

        New-Item -ItemType Directory -Path $fullTempPath -Force | Out-Null
        Log-Activity $domainName $remoteComputer $scriptName "INFO" "Created temp extraction folder: $fullTempPath" $enableVerboseMode $enableConsoleOutput

        $pattern = "*-results-$DayStamp.zip"
        $zipFiles = Get-ChildItem -Path $rootFolder -Recurse -Filter *.zip | Where-Object {
            $_.Name -like $pattern
        }

        Log-Activity $domainName $remoteComputer $scriptName "INFO" "Found $($zipFiles.Count) zip files matching pattern '$pattern'" $enableVerboseMode $enableConsoleOutput

        foreach ($zip in $zipFiles) {
            $relativePath = $zip.DirectoryName.Replace($rootFolder, "").TrimStart('\')
            $destinationFolder = Join-Path $fullTempPath $relativePath

            if (!(Test-Path $destinationFolder)) {
                New-Item -ItemType Directory -Path $destinationFolder -Force | Out-Null
                Log-Activity $domainName $remoteComputer $scriptName "DEBUG" "Created folder: $destinationFolder" $enableVerboseMode $enableConsoleOutput
            }

            try {
                Log-Activity $domainName $remoteComputer $scriptName "INFO" "Extracting $($zip.FullName) to $destinationFolder" $enableVerboseMode $enableConsoleOutput
                Expand-Archive -LiteralPath $zip.FullName -DestinationPath $destinationFolder -Force
            } catch {
                Log-Activity $domainName $remoteComputer $scriptName "ERROR" "Failed to extract $($zip.FullName): $($_.Exception.Message)" $enableVerboseMode $enableConsoleOutput
            }
        }
    }

    if ($Cleanup) {
        $fullTempPath = Join-Path $tempFolder $DayStamp
        if (Test-Path $fullTempPath) {
            try {
                Remove-Item -Path $fullTempPath -Recurse -Force
                Log-Activity $domainName $remoteComputer $scriptName "INFO" "Deleted temp folder: $fullTempPath" $enableVerboseMode $enableConsoleOutput
            } catch {
                Log-Activity $domainName $remoteComputer $scriptName "ERROR" "Failed to delete temp folder: $($_.Exception.Message)" $enableVerboseMode $enableConsoleOutput
            }
        } else {
            Log-Activity $domainName $remoteComputer $scriptName "WARNING" "Temp folder does not exist: $fullTempPath" $enableVerboseMode $enableConsoleOutput
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

function Convert-ToBool ($val) {
    if ($null -eq $val) { return $false }
    $str = $val.ToString().ToLower()
    return ($str -eq "true" -or $str -eq "1" -or $str -eq "yes")
}

function Convert-ToIsoDate ($val) {
    try {
        if (-not $val) { return $null }

        # Handle format: "HHmm_yyyy-MM-dd"
        if ($val -match '^\d{4}_\d{4}-\d{2}-\d{2}$') {
            $dt = [datetime]::ParseExact($val, 'HHmm_yyyy-MM-dd', $null)
            return $dt.ToUniversalTime().ToString("o")
        }

        # Handle standard ISO-style date strings
        if ($val -match '^\d{4}-\d{2}-\d{2}([ T]\d{2}:\d{2}(:\d{2})?)?$') {
            $dt = [datetime]::Parse($val)
            return $dt.ToUniversalTime().ToString("o")
        }
    } catch { 
        Log-Activity "<DATE>" "<Local>" "CONVERT" "ERROR" "Failed convert to ISO date (function Convert-ToIsoDate): $_"
    }
    return $null
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

function Zip-PushResults {
    param (
        [string]$tempFolder,
        [string]$dailyFolder,
        [string]$DayStamp,
        [string]$activityLogPath,
        [bool]$enableVerboseMode,
        [bool]$enableConsoleOutput,
        [int]$attachmentSize,
        [switch]$PushResults,
        [switch]$Attachment
    )

    $scriptName = "Zip-PushResults"
    $domainName     = "Local"

    if ($PushResults) {
        $daystampFolder = Join-Path $tempFolder $DayStamp
        $domainFolders = Get-ChildItem -Path $daystampFolder -Directory

        foreach ($domainFolder in $domainFolders) {
            $domainName = $domainFolder.Name
            $sourcePath = $domainFolder.FullName
            $zipNameBase = "$domainName-pushresults-$DayStamp.zip"
            $zipPath = Join-Path $sourcePath $zipNameBase

            $counter = 1
            while (Test-Path $zipPath) {
                $zipNameBase = "$domainName-pushresults-$DayStamp-$counter.zip"
                $zipPath = Join-Path $dailyFolder $zipNameBase
                $counter++
            }

            $outputFiles = Get-ChildItem -Path (Join-Path $daystampFolder $domainFolder) -File | Where-Object {
                $_.Name -match '\.gz$|\.response\.json$|^PushDiagnostics.*\.log$'
            }

            try {
                if ($outputFiles.Count -eq 0) {
                    Log-Activity $domainName $zipPath $scriptName "WARNING" "No output files to zip." $enableVerboseMode $enableConsoleOutput
                } else {
                    Compress-Archive -Path $outputFiles.FullName -DestinationPath $zipPath -Force -ErrorAction Stop
                }

                Log-Activity $domainName $zipPath $scriptName "SUCCESS" "Zipped results to $zipPath" $enableVerboseMode $enableConsoleOutput

            foreach ($file in $outputFiles) {
                try {
                    Remove-Item -Path $file.FullName -Force
                    Log-Activity $domainName $zipPath $scriptName "SUCCESS" "Removed output file: $($file.Name)" $enableVerboseMode $enableConsoleOutput
                } catch {
                    Log-Activity $domainName $zipPath $scriptName "WARNING" "Failed to remove: $($file.FullName): $($_.Exception.Message)" $enableVerboseMode $enableConsoleOutput
                }
            }

            } catch {
                Log-Activity $domainName $zipPath $scriptName "ERROR" "Failed to zip $($file.FullName): $($_.Exception.Message)" $enableVerboseMode $enableConsoleOutput
            }
        }
    }

    if ($Attachment) {
        try {
            $ActivitylogFile = Get-Item -Path $activityLogPath -ErrorAction Stop
            if ($ActivitylogFile.Length -gt $attachmentSize) {
                $zipName = [System.IO.Path]::ChangeExtension($activityLogPath, ".zip")
                $counter = 1
                while (Test-Path $zipName) {
                    $zipName = $activityLogPath -replace '\.csv$', "-$counter.zip"
                    $counter++
                }
                Compress-Archive -Path $activityLogPath -DestinationPath $zipName -Force
                Log-Activity "System" $activityLogPath $scriptName "INFO" "Activity log zipped to $zipName" $enableVerboseMode $enableConsoleOutput
                return $zipName
            } else {
                Log-Activity "System" $activityLogPath $scriptName "INFO" "Activity log small; no zip needed." $enableVerboseMode $enableConsoleOutput
                return $activityLogPath
            }
        } catch {
            Log-Activity "System" $activityLogPath $scriptName "ERROR" "Attachment zip error: $($_.Exception.Message)" $enableVerboseMode $enableConsoleOutput
        }
    }
}


# Display configuration if verbose mode is enabled
Show-Configuration

# Run cleanup
Clean-OldPushes -outputRoot $outputRoot -RetentionDays $RetentionDays -enableVerboseMode $enableVerboseMode -enableConsoleOutput $enableConsoleOutput

# Expand zipped export files
Expand-ZipsToTemp -rootFolder $rootFolder -tempFolder $tempFolder -DayStamp $DayStamp -Expand

# Locate CSVs matching today’s date
$csvFiles     = Get-ChildItem -Path $tempFolder -Filter *.csv -Recurse
$matchedFiles = $csvFiles | Where-Object { $_.Name -like "*$DayStamp*" }

if ($matchedFiles.Count -eq 0) {
    Log-Activity "<API>" "<None>" $scriptName "INFO" "No matching CSV files found for today's date: $DayStamp"
    return
}

# Create job tracker
$pushJobs = @()

foreach ($file in $matchedFiles) {
    $domain = $file.BaseName -split '-' | Select-Object -First 1
    $fileType = if ($file.Name -like "*AD_User_Export*") { "User" }
                elseif ($file.Name -like "*GroupMembership*") { "Group" }
                else { $null }

    if (-not $fileType) {
        Log-Activity "<Scan>" $file.FullName $scriptName "ERROR" "File matched date but not user/group pattern"
        continue
    }

    Log-Activity "<Scan>" $file.FullName $scriptName "INFO" "Matched $fileType export file: $($file.Name), importing."

    # Enforce job throttling
    while (($pushJobs | Where-Object { $_.State -eq 'Running' }).Count -ge $MaxConcurrentJobs) {
        Start-Sleep -Seconds 1
        $pushJobs = $pushJobs | Where-Object { $_.State -ne 'Completed' -and $_.State -ne 'Failed' }
    }

    # Serialize headers
    $headersJson = $Headers | ConvertTo-Json -Compress

    $argList = @(
        $Date,
        $file.FullName,
        $fileType,
        $domain,
        $ApiUrl,
        $headersJson,
        $MaxRetries,
        $BatchSize,
        $ThrottleDelayMs,
        $enableVerboseMode,
        $enableConsoleOutput,
        $tempDailyFolder,
        $activityLogPath,
        $scriptName,
        $LogWriteRetries,
        $retryDelayMs
    )

    Log-Activity "JobParam" $file.FullName $scriptName "DEBUG" "Preparing to start job with parameters (Type: Value):"
    Log-Activity "JobParam" $file.FullName $scriptName "DEBUG" "Date: [$($Date.GetType().Name): $Date]"
    Log-Activity "JobParam" $file.FullName $scriptName "DEBUG" "FilePath: [$($file.FullName.GetType().Name): $($file.FullName)]"
    Log-Activity "JobParam" $file.FullName $scriptName "DEBUG" "FileType: [$($fileType.GetType().Name): $fileType]"
    Log-Activity "JobParam" $file.FullName $scriptName "DEBUG" "DomainName: [$($domain.GetType().Name): $domain]"
    Log-Activity "JobParam" $file.FullName $scriptName "DEBUG" "ApiUrl: [$($ApiUrl.GetType().Name): $ApiUrl]"
    Log-Activity "JobParam" $file.FullName $scriptName "DEBUG" "HeadersJson: [$($headersJson.GetType().Name): $headersJson]"
    Log-Activity "JobParam" $file.FullName $scriptName "DEBUG" "MaxRetries: [$($MaxRetries.GetType().Name): $MaxRetries]"
    Log-Activity "JobParam" $file.FullName $scriptName "DEBUG" "BatchSize: [$($BatchSize.GetType().Name): $BatchSize]"
    Log-Activity "JobParam" $file.FullName $scriptName "DEBUG" "ThrottleDelayMs: [$($ThrottleDelayMs.GetType().Name): $ThrottleDelayMs]"
    Log-Activity "JobParam" $file.FullName $scriptName "DEBUG" "enableVerboseMode: [$($enableVerboseMode.GetType().Name): $enableVerboseMode]"
    Log-Activity "JobParam" $file.FullName $scriptName "DEBUG" "enableConsoleOutput: [$($enableConsoleOutput.GetType().Name): $enableConsoleOutput]"
    Log-Activity "JobParam" $file.FullName $scriptName "DEBUG" "tempDailyFolder: [$($tempDailyFolder.GetType().Name): $tempDailyFolder]"
    Log-Activity "JobParam" $file.FullName $scriptName "DEBUG" "activityLogPath: [$($activityLogPath.GetType().Name): $activityLogPath]"
    Log-Activity "JobParam" $file.FullName $scriptName "DEBUG" "scriptName: [$($scriptName.GetType().Name): $scriptName]"
    Log-Activity "JobParam" $file.FullName $scriptName "DEBUG" "LogWriteRetries: [$($LogWriteRetries.GetType().Name): $LogWriteRetries]"
    Log-Activity "JobParam" $file.FullName $scriptName "DEBUG" "retryDelayMs: [$($retryDelayMs.GetType().Name): $retryDelayMs]"


    # Start job using your existing functions inline
    $pushJobs += Start-Job -ArgumentList $argList -ScriptBlock {
        param (
            [string]$Date,
            [string]$FilePath,
            [string]$FileType,
            [string]$DomainName,
            [string]$ApiUrl,
            [string]$HeadersJson,
            [int]$MaxRetries,
            [int]$BatchSize,
            [int]$ThrottleDelayMs,
            [bool]$enableVerboseMode,
            [bool]$enableConsoleOutput,
            [string]$tempDailyFolder,
            [string]$activityLogPath,
            [string]$scriptName,
            [int]$LogWriteRetries,
            [int]$retryDelayMs
        )


        function Write-BatchCsvReport {
            param (
                [int]$BatchId,
                [string]$Domain,
                [string]$FileType,
                [string]$FileName,
                [int]$SuccessCount,
                [int]$FailureCount,
                [double]$DurationSec,
                [string]$EntityKey,
                [string]$UploadUrl,
                [string]$ContentType,
                [string]$OutputFolder
            )

            $timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
            $total = $SuccessCount + $FailureCount

            $csvLine = [PSCustomObject]@{
                BatchId      = $BatchId
                Domain       = $Domain
                FileType     = $FileType
                FileName     = $FileName
                Success      = $SuccessCount
                Failure      = $FailureCount
                Total        = $total
                DurationSec  = [Math]::Round($DurationSec, 3)
                EntityKey    = $EntityKey
                UploadUrl    = $UploadUrl
                UploadTime   = $timestamp
                ContentType  = $ContentType
            }

            $reportFile = Join-Path $OutputFolder "PushDiagnostics-Batch-$BatchId-$($timestamp.Split('T')[0]).csv"

            # Create CSV if it doesn't exist, otherwise append
            if (-not (Test-Path $reportFile)) {
                $csvLine | Export-Csv -Path $reportFile -NoTypeInformation
            } else {
                $csvLine | Export-Csv -Path $reportFile -NoTypeInformation -Append
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

            # Append caller info if verbose mode is on
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
                }
            }

            $line = "[$timestamp] [$ActionType] [$DomainName] [$RemoteComputer] [$ScriptName] $Message$stackTag"

            # Respect enableVerboseMode for DEBUG logging
            $shouldLog = $ActionType.ToUpper() -ne 'DEBUG' -or $enableVerboseMode

            if ($shouldLog) {
                for ($i = 1; $i -le $LogWriteRetries; $i++) {
                    try {
                        Add-Content -Path $activityLogPath -Value $line
                        break
                    } catch {
                        if ($i -eq $LogWriteRetries) {
                            Write-Warning "Log-Activity failed after $LogWriteRetries attempts: $($_.Exception.Message)"
                        } else {
                            Start-Sleep -Milliseconds $retryDelayMs
                        }
                    }
                }
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

        function Convert-ToBool ($val) {
            if ($null -eq $val) { return $false }
            $str = $val.ToString().ToLower()
            return ($str -eq "true" -or $str -eq "1" -or $str -eq "yes")
        }

        function Convert-ToIsoDate ($val) {
            try {
                if (-not $val) { return $null }

                # Handle format: "HHmm_yyyy-MM-dd"
                if ($val -match '^\d{4}_\d{4}-\d{2}-\d{2}$') {
                    $dt = [datetime]::ParseExact($val, 'HHmm_yyyy-MM-dd', $null)
                    return $dt.ToUniversalTime().ToString("o")
                }

                # Handle standard ISO-style date strings
                if ($val -match '^\d{4}-\d{2}-\d{2}([ T]\d{2}:\d{2}(:\d{2})?)?$') {
                    $dt = [datetime]::Parse($val)
                    return $dt.ToUniversalTime().ToString("o")
                }
            } catch { 
                Log-Activity "<DATE>" "<Local>" "CONVERT" "ERROR" "Failed convert to ISO date (nested function Convert-ToIsoDate): $_"
            }
            return $null
        }

        function Remove-NonAscii {
            param ([string]$text)
            return -join ($text.ToCharArray() | Where-Object { [int][char]$_ -le 127 })
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

        function Upload-GzippedBatch {
            param (
                [string]$GzipFile,
                [string]$DomainName,
                [string]$ApiUrl,
                [hashtable]$Headers,
                [string]$FileType
            )

            $boundary = "----boundary123456"
            $crlf = "`r`n"
            $binary = [System.IO.File]::ReadAllBytes($GzipFile)

            $timestamp = [int][double]::Parse((Get-Date -UFormat %s))
            $entityKey = "AD_EXPORT:AD_EXPORT/nodename:$($env:COMPUTERNAME)/forestname:$DomainName/objectType:$FileType/timestamp:$timestamp"
            $filename = [System.IO.Path]::GetFileName($GzipFile)

            $partHeaderLines = @(
                "--$boundary",
                "Content-Type: application/octet-stream",
                "Content-Disposition: attachment; filename=""$filename""",
                "Entity-Type: AD_EXPORT:string/nodename:string/forestname:string/objectType:string/timestamp:int64",
                "Entity-Key: $entityKey",
                "Payload-Size: $($binary.Length)",
                "",
                ""
            )
            $partHeader = $partHeaderLines -join $crlf
            $partHeaderBytes = [System.Text.Encoding]::UTF8.GetBytes($partHeader)
            $closing = "$crlf--$boundary--$crlf"
            $closingBytes = [System.Text.Encoding]::UTF8.GetBytes($closing)

            $ms = New-Object System.IO.MemoryStream
            $ms.Write($partHeaderBytes, 0, $partHeaderBytes.Length)
            $ms.Write($binary, 0, $binary.Length)
            $ms.Write($closingBytes, 0, $closingBytes.Length)
            $ms.Position = 0

            $Headers["Content-Type"] = "multipart/mixed; boundary=$boundary"

            # Write to log file explicitly (in addition to Log-Activity)
            $entityLogEntry = "Entity-Key: $entityKey"
            Add-Content -Path $logFile -Value $entityLogEntry

            Log-Activity $DomainName $logFile "Upload-GzippedBatch" "DEBUG" "EntityKey: $entityLogEntry" $enableVerboseMode $enableConsoleOutput
            Log-Activity $domainName $ApiUrl "Upload-GzippedBatch" "DEBUG" "Target API URL for upload" $enableVerboseMode $enableConsoleOutput


            foreach ($header in $Headers.PSObject.Properties) {
                $headerLog = "Header: $($header.Name) = $($header.Value)"
                Add-Content -Path $logFile -Value $headerLog
                Log-Activity $DomainName $logFile "Upload-GzippedBatch" "DEBUG" $headerLog $enableVerboseMode $enableConsoleOutput
            }

            try {
                # Convert [pscustomobject] to hashtable
                $HeadersHashtable = @{}
                foreach ($property in $Headers.PSObject.Properties) {
                    $HeadersHashtable[$property.Name] = $property.Value
                }

                if ($enableVerboseMode) {
                    # Flatten headers for readable logging
                    $headersFlat = $HeadersHashtable.GetEnumerator() | ForEach-Object { "$($_.Key): $($_.Value)" } -join "`n"

                    # Get raw body bytes and compute size
                    $bodyBytes = $ms.ToArray()
                    $bodySize = $bodyBytes.Length

                    # Construct the request log message correctly (closing @" must be on its own line, no indent!)
                    $logMessage = @"
HTTP REQUEST:
POST $ApiUrl

Headers:
$headersFlat

Content-Type: $($HeadersHashtable["Content-Type"])
Body Length: $bodySize bytes

Entity-Key: $entityKey
"@

                    # Write to log
                    Log-Activity $DomainName $env:COMPUTERNAME $scriptName "DEBUG" $logMessage $enableVerboseMode $enableConsoleOutput

                }
                

                # Use this with Invoke-WebRequest
                $response = Invoke-WebRequest -Uri $ApiUrl -Method Post -Headers $HeadersHashtable -Body $ms.ToArray() -UseBasicParsing
                return $response.StatusCode
            } catch {
                $httpCode = $_.Exception.Response.StatusCode.Value__
                $httpReason = $_.Exception.Response.StatusDescription
                Log-Activity $domain $logFile "Write-Manifest" "ERROR" "Upload failed: [$httpCode] $httpReason — $($_.Exception.Message)" $enableVerboseMode $enableConsoleOutput

                # Attempt to extract the response body
                try {
                    $responseStream = $_.Exception.Response.GetResponseStream()
                    if ($responseStream) {
                        $reader = New-Object System.IO.StreamReader($responseStream)
                        $responseBody = $reader.ReadToEnd()

                        # Determine where to write the response file
                        $responsePath = $logFile -replace '\.json$', '.response.json'

                        # Write the body
                        $responseBody | Out-File -FilePath $responsePath -Encoding UTF8 -Force

                        Log-Activity $domain $logFile "Write-Manifest" "DEBUG" "Saved failed HTTP response to $responsePath" $enableVerboseMode $enableConsoleOutput
                    }
                } catch {
                    Log-Activity $domain $logFile "Write-Manifest" "WARNING" "Could not capture HTTP response body: $($_.Exception.Message)" $enableVerboseMode $enableConsoleOutput
                }

                return 10
            }

        }

        function Compress-BatchToGzip {
            param (
                [array]$BatchRows,
                [string]$FileType,
                [string]$outputBasePath
            )

            $jsonPath = "$outputBasePath.json"
            $gzipPath = "$outputBasePath.json.gz"

            $payloads = $BatchRows | ForEach-Object { Convert-RowToPayload -row $_ -FileType $FileType}
            $payloads | ConvertTo-Json -Depth 5 | Out-File -FilePath $jsonPath -Encoding UTF8 -Force

            try {
                $sourceStream = [System.IO.File]::OpenRead($jsonPath)
                $targetStream = [System.IO.File]::Create($gzipPath)
                $gzipStream = New-Object System.IO.Compression.GzipStream($targetStream, [System.IO.Compression.CompressionMode]::Compress)
                $sourceStream.CopyTo($gzipStream)
                $gzipStream.Close(); $sourceStream.Close(); $targetStream.Close()
                return $gzipPath
            } catch {
                throw "Compression failed: $($_.Exception.Message)"
            }
        }

        Log-Activity "JobParam" $FilePath $scriptName "DEBUG" "Parameters received inside job (Type: Value):"
        Log-Activity "JobParam" $FilePath $scriptName "DEBUG" "Date: [$($Date.GetType().Name): $Date]"
        Log-Activity "JobParam" $FilePath $scriptName "DEBUG" "FilePath: [$($FilePath.GetType().Name): $FilePath]"
        Log-Activity "JobParam" $FilePath $scriptName "DEBUG" "FileType: [$($FileType.GetType().Name): $FileType]"
        Log-Activity "JobParam" $FilePath $scriptName "DEBUG" "DomainName: [$($DomainName.GetType().Name): $DomainName]"
        Log-Activity "JobParam" $FilePath $scriptName "DEBUG" "ApiUrl: [$($ApiUrl.GetType().Name): $ApiUrl]"
        Log-Activity "JobParam" $FilePath $scriptName "DEBUG" "HeadersJson: [$($HeadersJson.GetType().Name): $HeadersJson]"
        Log-Activity "JobParam" $FilePath $scriptName "DEBUG" "MaxRetries: [$($MaxRetries.GetType().Name): $MaxRetries]"
        Log-Activity "JobParam" $FilePath $scriptName "DEBUG" "BatchSize: [$($BatchSize.GetType().Name): $BatchSize]"
        Log-Activity "JobParam" $FilePath $scriptName "DEBUG" "ThrottleDelayMs: [$($ThrottleDelayMs.GetType().Name): $ThrottleDelayMs]"
        Log-Activity "JobParam" $FilePath $scriptName "DEBUG" "enableVerboseMode: [$($enableVerboseMode.GetType().Name): $enableVerboseMode]"
        Log-Activity "JobParam" $FilePath $scriptName "DEBUG" "enableConsoleOutput: [$($enableConsoleOutput.GetType().Name): $enableConsoleOutput]"
        Log-Activity "JobParam" $FilePath $scriptName "DEBUG" "tempDailyFolder: [$($tempDailyFolder.GetType().Name): $tempDailyFolder]"
        Log-Activity "JobParam" $FilePath $scriptName "DEBUG" "activityLogPath: [$($activityLogPath.GetType().Name): $activityLogPath]"
        Log-Activity "JobParam" $FilePath $scriptName "DEBUG" "scriptName: [$($scriptName.GetType().Name): $scriptName]"
        Log-Activity "JobParam" $FilePath $scriptName "DEBUG" "LogWriteRetries: [$($LogWriteRetries.GetType().Name): $LogWriteRetries]"
        Log-Activity "JobParam" $FilePath $scriptName "DEBUG" "retryDelayMs: [$($retryDelayMs.GetType().Name): $retryDelayMs]"

        Log-Activity "<ThreadInspect>" "<Thread-$batchId>" $scriptName "DEBUG" `
            ("Functions loaded: " + `
                (@(Get-Command -CommandType Function |
                    Where-Object { $_.ModuleName -notmatch '^Microsoft\.|^PSReadLine|^PackageManagement|^PowerShellGet|^Utility' } |
                    Select-Object -ExpandProperty Name) -join ', ') `
            ) $enableVerboseMode $enableConsoleOutput

        # Safely rehydrate a PSCustomObject to true hashtable
        if ($Headers -isnot [hashtable]) {
            $newHeaders = @{}
            foreach ($property in $Headers.PSObject.Properties) {
                $newHeaders[$property.Name] = $property.Value
            }
            $Headers = $newHeaders
        }

        $rows = Import-Csv -Path $FilePath
        $batchId = 1
        for ($i = 0; $i -lt $rows.Count; $i += $BatchSize) {
            $batchRows = $rows[$i..([math]::Min($i + $BatchSize - 1, $rows.Count - 1))]
            $domainFolder = Join-Path $tempDailyFolder $DomainName
            if (-not (Test-Path $domainFolder)) {
                New-Item -Path $domainFolder -ItemType Directory -Force | Out-Null
            }

            $threadId = [System.Guid]::NewGuid().ToString()
            $logFile = Join-Path $domainFolder "PushDiagnostics-Batch-$batchId-$Date-$threadId.log"

            try {
                $jsonFile = [System.IO.Path]::ChangeExtension($logFile, ".json")
                $gzipFile = "$jsonFile.gz"

                # Convert to payload and compress
                $gzipFile = Compress-BatchToGzip -BatchRows $batchRows -FileType $FileType -outputBasePath ([System.IO.Path]::ChangeExtension($logFile, $null))


                # Upload
                $startTime = Get-Date
                $code = Upload-GzippedBatch -GzipFile $gzipFile -DomainName $DomainName -ApiUrl $ApiUrl -Headers $Headers -FileType $FileType
                $success = $batchRows.Count
                $fail    = 0
                $duration = [math]::Round((Get-Date - $startTime).TotalSeconds, 2)

                Log-Activity $DomainName $logFile $scriptName "SUCCESS" "Upload success ($success records), code $code" $enableVerboseMode $enableConsoleOutput

            } catch {
                $success = 0
                $fail    = $batchRows.Count
                $duration = 0
                Log-Activity $DomainName $logFile $scriptName "ERROR" "Upload failed: $($_.Exception.Message)" $enableVerboseMode $enableConsoleOutput
            }

            Write-BatchCsvReport -BatchId $batchId `
                                -Domain $DomainName `
                                -FileType $fileType `
                                -FileName $file.Name `
                                -SuccessCount $successCount `
                                -FailureCount $failureCount `
                                -DurationSec $duration `
                                -EntityKey $entityKey `
                                -UploadUrl $ApiUrl `
                                -ContentType $Headers['Content-Type'] `
                                -OutputFolder $tempDailyFolder

            $batchId++
            Start-Sleep -Milliseconds $ThrottleDelayMs
        }

        # Return per-job summary
        [PSCustomObject]@{
            Success = ($rows.Count - $fail)
            Failure = $fail
        }
    }
}

# Wait and receive all jobs
Log-Activity "<Threading>" "<Local>" $scriptName "INFO" "Waiting for $($pushJobs.Count) thread jobs to complete..."

Wait-Job -Job $pushJobs

$allResults = @()
foreach ($job in $pushJobs) {
    try {
        if ($job.State -eq 'Completed' -and $job.HasMoreData) {
            try {
                $result = Receive-Job -Job $job -ErrorAction Stop
                $allResults += $result

                # Retry Log-Activity output if file is locked
                for ($i = 1; $i -le 5; $i++) {
                    try {
                        foreach ($entry in $result) {
                            Log-Activity $entry.DomainName $entry.RemoteComputer $entry.ScriptName $entry.ActionType $entry.Message $entry.enableVerboseMode $entry.enableConsoleOutput
                        }
                        break
                    } catch {
                        if ($i -eq 5) { throw $_ }
                        Start-Sleep -Milliseconds 200
                    }
                }

            } catch {
                Log-Activity "<Job>" "<Thread-$($job.Id)>" $scriptName "ERROR" "Receive-Job failed: $($_.Exception.Message)" $enableVerboseMode $enableConsoleOutput
            }
        } else {
            $errMsg = $job.ChildJobs | ForEach-Object { $_.JobStateInfo.Reason } | Where-Object { $_ } | Out-String
            Log-Activity "<Job>" "<Thread-$($job.Id)>" $scriptName "ERROR" "Job incomplete or output unavailable. State: $($job.State). Reason: $errMsg" $enableVerboseMode $enableConsoleOutput
        }
    } catch {
        Log-Activity "<Job>" "<Thread-$($job.Id)>" $scriptName "ERROR" "Exception while checking job state: $($_.Exception.Message)" $enableVerboseMode $enableConsoleOutput
    }
}

$SuccessCount = ($allResults | Measure-Object -Property Success -Sum).Sum
$FailureCount = ($allResults | Measure-Object -Property Failure -Sum).Sum
Remove-Job -Job $pushJobs


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

# Cleanup temp files and such
Expand-ZipsToTemp -rootFolder $rootFolder -tempFolder $tempFolder -DayStamp $DayStamp -Cleanup

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