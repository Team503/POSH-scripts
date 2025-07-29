<#
.SYNOPSIS
	Audits Active Directory group memberships and domain configurations across local and trusted 
    domains using multi-threaded processing with domain controller discovery and error-resilient logging.

.DESCRIPTION
    This script is designed for AD administrators to perform cross-domain reporting on group memberships, 
    user accounts, trusts, and administrative accounts across all trusted domains, including the local 
    one if enabled. 

    It discovers trusted domains via Get-ADTrust, resolves a preferred domain controller (favoring the PDC), 
    verifies authentication connectivity, and then executes a suite of audit reports in parallel using 
    thread jobs. It intelligently handles slow lookups, cross-domain recursion, and memory usage. Group 
    membership lookups support both standard AD cmdlets and fast LDAP mode, with adjustable recursion 
    depth and performance warnings.

    Script output is organized into per-domain folders with CSV and LOG files.  For faster processing,
    groups are separated into "chunks" and processed a chunk at a time.  The chunk size and number of
    chunks are goverend by variables in the parameter statement.
    log. A centralized activity log tracks all operations, warnings, errors, and runtime metrics. The
    script optionally sends a summary email with execution statistics and any detected failures.

    Key features:
    - Trusted DC resolution with fallback logic
    - Threaded domain processing with configurable throttle limit
    - Optional local domain processing
    - Optional full domain group scan or targeted CSV-based input
    - LDAP optimization for faster group member resolution
    - Nested group recursion with depth limit and per-group timers
    - Domain-specific output folders and logs
    - Email summary reporting with attachments
    - Automated cleanup of old reports
    - Explicit confirmation required using -ConfirmExecution IUnderstand

    This script is suitable for running interactively or as a background task with configurable console output.

.EXAMPLE
    .\get-ActiveDirectoryReports-TrustedDomains.ps1
    Executes the script with all default settings. Required for the script to proceed.

.EXAMPLE
    .\get-ActiveDirectoryReports-TrustedDomains.ps1 -EnableVerboseMode $true -SendEmail $false
    Enables debug output and disables the email summary report.

.EXAMPLE
    .\get-ActiveDirectoryReports-TrustedDomains.ps1 -Help
    Shows parameter help and usage examples.

.NOTES
	Author: Alex Cherry | License: CC0
    Initially Published: 27 May 2025 1122GMT
    Last Updated       : 28 Jul 2025 1547GMT
.CHANGELOG 
    20250603 - 13.7.6 - Version 13.7.6 is confirmed working with one exception: cross-domain lookups fail
    20250603 - 14.0.1 - Adding cross-domain lookups with an enable/disable flag
    20250603 - 14.1.1 - Moved domain controller lookups and connectivity testing to a function
    20250603 - 14.2.1 - Added additional output file for domains that fail authentication negotiation and included in email
    20250603 - 14.3.1 - Added display and logging of PDC name, fixed DC handling logic to not show incorrect error
    20250603 - 14.3.2 - Added auth test prior to looping through the scripts to avoid unnecessary junk errors.
    20250603 - 15.0.1 - Changed logging function to streaming to save memory usage and improve performance
    20250603 - 15.0.2 - Refactored domain status to use a single array instead of multiple objects for the same reasons
    20250603 - 15.0.3 - Moved domain status logic into Log-Activity function for the same reasons
    20250603 - 16.0.1 - Updated Set-TrustedHost to shorter name and stricter hostname checks for validity to avoid adding malformed or rogue hosts
    20250603 - 16.0.2 - Added toggle to disable console output since this is intended as a background task and it will improve performance to have it off
    20250604 - 16.0.3 - Resolve issue with scripts running anyway when DC is unreachable
    20250604 - 16.0.4 - Remove extraneous $domainsError statements, domain status is tracked in the log-activity function now
    20250605 - 16.0.5 - Added domain-specific subfolder creation
    20250605 - 17.0.1 - Added local domain context and toggle
    20250605 - 17.1.1 - Solved local group membership query issue by adding a copy of the report inside the local block; TESTED GOOD VERSION
    20250605 - 18.0.1 - Changed logic to execute locally on the host server in order to reduce complexity and allow for GMSA use
    20250605 - 18.0.2 - Removed run as admin logic, as without the trusted hosts function it's no longer required
    20250605 - 18.0.3 - Removed redundant GroupMembership block in if(EnableLocalDomain)
    20250605 - 18.0.4 - Implemented new authentication test now that the WinRM tests are deprecated and included deeper error logging
    20250605 - 18.0.5 - Fixing null group value issue
    20250605 - 18.0.6 - Fixed group splatting issue with lookups
    20250605 - 18.0.7 - Restored all scripts to EnableLocalDomain
    20250605 - 18.1.1 - A lot of small work in the groupmembership section to resolve groups as the right kind of objects and handle the right arrays
                        as well as adding a section in the EnableLocalDomain to resolve local DC and use it rather than trying to run on the local box
                        TESTED GOOD AT THIS STAGE
    20250605 - 18.2.1 - Added an old file/folder cleanup function with logging
    20250606 - 18.2.2 - Added lookup for domain admins group to verify group resolution.
    20250609 - 19.0.1 - Adding new logic to allow for queries of all domains via variable toggle
    20250609 - 19.0.2 - Fixed localRemoteComputer reference in enableLocalDomain loop
    20250609 - 19.1.1 - Fixed logic for all domains toggle missing in trusted loop
    20250609 - 1.0.0 -  Reset version now that we're using threading; implemented parallel processing of domains
    20250609 - 1.1.0 -  Switched to using function instead of inline processing to reduce complexity for local domain processing
    20250609 - 1.1.1 -  Added memory tracking for each report, cleaned up logic, added error passthrough for jobs
    20250609 - 2.0.1 -  Replaced start-job with threadjob, an improved MS provided multithreading module
    20250610 - 2.1.1 -  Removed streaming log and went back to objects since the stream was locking a file and crashing the script
    20250610 - 2.1.2 -  Fixed job wait code, updated Log-Activity function to use an array inside of the job to avoid file collisions
    20250610 - 2.2.1 -  Shifted to using group DN instead of name to resolve lookup issues
    20250610 - 2.2.2 -  Added log-activity function to GroupMembershipScript block to resolve failed function calls
    20250610 - 2.3.1 -  Cleaned up group member resolution (again!) and removed extraneous AD calls by making a resolvedMembers cache
    20250610 - 2.3.2 -  Added MaxGroupRecursionDepth to prevent infinite lookups and absurd nesting levels
    20250610 - 2.3.3 -  Added per-group recursion warnings
    20250610 - 2.3.4 -  Added per-group lookup timers and flagged warnings for anything that exceeds the threshold
    20250610 - 2.3.5 -  Updated notice email to include new timers and warnings, corrected $Date format
    20250610 - 2.3.6 ¬  Changed CSV loader to use -Filter instead of -Identity for speed improvement
    20250610 - 2.3.7 -  Moved DN resolution from CSV loader to the domain job, as the script would otherwise try to resolve every group 
                        and fail when the domain is not connectable
    20250610 - 2.3.8 -  Added logic to watch for null group names - group names that fail to resolve - and handle them
    20250610 - 2.3.9 -  Fixed incorrect email body in email summary
    20250610 - 3.0.1 -  New version, moved outputfolder into a variable in the user config section
    20250611 - 3.0.2 -  Include missing return of logs from start-domainjob function that caused empty activity log
    20250611 - 3.1.2 -  Include the option to use significantly faster LDAP queries instead of AD cmdlets, controlled by variable flag.
                        Only the initial query can use it, though, as it doesn't support recursion.
    20250612 - 3.1.3 -  Adjust formatting of email to make it more readable
    20250612 - 4.0.1 -  $groupMembershipScript inside the Start-Threadjob to prevent scope leakage and reduce duplicate function definitions
    20250612 - 4.0.2 -  Moved excluded domains to a variable and added logging of excluded domains
    20250612 - 4.0.3 -  Cleaned up and resolved parameter mismatches and conflicts
    20250612 - 4.1.3 -  Moved groupmembership scriptblock into the actual report assignment since it errors otherwise
    20250612 - 4.2.0 -  Fixed group memebership calling logic and object type mismatch
    20250613 - 4.2.1 -  Working to remove junk input and clutter from group objects
    20250613 - 4.2.2 -  Added sanity checks for group objects
    20250613 - 4.3.1 -  Still working group objects, added verbose logging mode to Log-Activity functions
    20250616 - 4.3.2 -  Fixed recursion function call to explicitly pass parameters to resolve 0 recursion layer issue
    20250616 - 4.3.3 -  Reworked $depth and $maxrecursiondepth; was using the max value as the depth previously
    20250617 - 4.3.4 -  Added hardcoding the $MaxGroupRecursionDepth inside the functions as shadowing/memory ***** cause it to define itself as 1
    20250617 - 4.3.5 -  Added error handling for $member.DistinguishedName being null
    20250617 - 4.4.1 -  Added function Resolve-Memberkey to add safe handling for null values in recursive lookups, as well as built-in groups like Domain Users
    20250625 - 4.5.1 -  Reconfigured jobs to process groups in chunks to avoid memory ***** and hangs
    20250625 - 4.5.2 -  Redefined param block for function start-DomainJobs with CmdletBinding to support the passage of global variables
    20250625 - 4.5.3 -  Resolve array passing issues for enableAllGroupsQuery
    20250625 - 4.5.5 -  Resolving hang issues
    20250625 - 4.5.6 -  Still on hang issues, but incrementing to for checkpoint AND corrected group logic
    20250626 - 4.5.7 -  Corrected Recurse-Members params and calls to align variables
    20250626 - 4.6.1 -  Moved export of group memberships into the recurse members loop to remove the need to return anything to address memory leak
    20250626 - 4.7.1 -  Revised memberDN loop in groupmembership scriptblock
    20250626 - 4.8.1 -  Revised loop logic to eliminate redundant lookups and address scalar output in $localResults
    20250701 - 5.0.1 -  Removed visited check since it was skipping groups it needed to resolve.  Fixed log flusher, removed duplicate log array,
                        added a number of sanity checks and input sanitizers
    20250701 - 5.1.1 -  Updated recursion logic to not attempt recursing an individual member but add it to the array anyway
    20250701 - 5.2.1 -  Adjusted recursion logic yet again
    20250707 - 5.2.2 -  Working on correcting logging and chunk output consolidation
    20250711 - 5.3.1 -  Refactoring logging to write after each chunk; keeping output in an array causes the script to crash when processing large domains
    20250711 - 5.3.2 -  Removed $warning array and used Write-Chunklog function instead to reduce memory consumption
    20250711 - 5.3.3 -  Removed mandatory tags from params to reduce memory usage and improve runtimes.
    20250711 - 5.3.4 -  Commented out consolidation functionality - it will be easier to process these files to push up as small files individually, and it allows
                        easier log reading.  Left code in place just in case we decide to change methodologies in the future
    20250711 - 5.3.5 -  Fixed Function Write-ChunkLog not respecting $enableVerboseMode
    20250714 - 5.3.6 -  Looking to solve logging issues - email report contains only one line, domain processing stats are missing
    20250714 - 5.4.1 -  Refactored function Resolve-TrustedDomainDC to use PSCustomObject
    20250715 - 5.4.2 -  Fixed domain trusts output, updated cleanup function to catch loose files and not just folders.
                        NOTE: At this point the script is in production but there are still groups that don't resolve - I think they're foreign and need to add
                        handling for them
    20250715 - 5.5.1 -  Added SID-to-DOMAIN mapping and foreign group handling
    20250715 - 5.6.1 -  Added params and help function, refactored clear-allvariables function to adjust to those changes
    20250715 - 5.6.2 -  Moved DomainSIDMap into existing DC processing to prevent double lookups slowing the script down significantly
    20250715 - 5.6.3 -  Removed Resolve-MemberKey, as $resolvedMembers serves the same purpose, if slightly less precisely, added job counters, fixed blank
                        line ",,,,,,,,,,,," so it just doesn't insert anything if there's no values
    20250715 - 5.7.1 -  Corrected throttling logic that was locking to one job at a time, effectively serial instead of parallel, also change handling of EnableLocalDomain
                        so that the first domain (which is the largest) isn't processed on its own
    20250716 - 5.7.2 -  Added better job handling to the log flusher so it doesn't leave a job hanging, and switched to start-threadjob for the log as well
    20250717 - 5.8.1 -  Added report that creates just a list of groups in a single CSV
    20250707 - 6.0.1 -  Replaced individual pscustomobject creations with a function to ensure schema adherence for group member entries and allow adaptability
    20250722 - 6.0.2 -  Fixed mismatched params on recurse-members and edited properties for group pulls as well as fixed incorrect server variable on get-adgroups
    20250722 - 7.0.1 -  Removed start-domainjobs function and moved logic inline instead; easier logging and less parameters/etc
    20250723 - 7.1.1 -  Added throttling for main domain threadjobs
    20250723 - 7.2.1 -  Reverting to start-job because some hosts don't support start-threadjob
    20250728 - 7.2.2 -  Updated clear-allvariables and clean-oldreports functions, added Compress-DomainResults
#>

param (
    [string]$RootFolder = "C:\Scripts\ADreports",
    [string]$OutputFolder = "output",
    [int]$RetentionDays = 30,
    [int]$MaxParallelDomainJobs = 10,
    [int]$GroupsPerJob = 25,
    [int]$MaxGroupRecursionDepth = 10,
    [int]$GroupProcessingTimeThresholdSec = 5,
    [string[]]$ExcludedDomains = @("*.example.com"),

    [bool]$EnableAllGroupsQuery = $true,
    [bool]$EnableCrossDomainMemberLookups = $true,
    [bool]$EnableConsoleOutput = $true,
    [bool]$EnableVerboseMode = $false,
    [bool]$EnableLocalDomain = $true,
    [bool]$SendEmail = $true,
    [bool]$UseFastLDAPLookups = $true,
    [bool]$EnableExcludedDomains = $true,

    [string]$EmailTo = "user@company.com",
    [string]$EmailFrom = "script-bot@company.com",
    [string]$SmtpServer = "mail.company.com",
    [int]$SmtpPort = 25,

    [switch]$Help
)

# Assign global variable (legacy compatibility)
$global:EnableVerboseMode = $EnableVerboseMode

function Show-Help {
    @"
NAME
    get-ActiveDirectoryReports-TrustedDomains_v7.2.2_threaded.ps1

SYNOPSIS
    Performs threaded Active Directory audit across trusted domains with CSV report generation, compression, and optional email summary.

SYNTAX
    .\get-ActiveDirectoryReports-TrustedDomains_v7.2.2_threaded.ps1 [options]

DESCRIPTION
    This script enumerates groups, users, and trusts across all trusted AD domains.
    It discovers domain controllers, validates authentication, executes audits in parallel,
    and generates structured logs and reports per domain. Optional email summary and
    cleanup features included.

PARAMETERS

    -RootFolder <string>
        Root working directory. Default: C:\Scripts\ADreports

    -OutputFolder <string>
        Subfolder under RootFolder for audit results. Default: output

    -RetentionDays <int>
        Number of days to keep prior reports. Default: 30

    -MaxParallelDomainJobs <int>
        Maximum concurrent threads for domain auditing. Default: 10

    -GroupsPerJob <int>
        Number of groups processed per thread chunk. Default: 25

    -MaxGroupRecursionDepth <int>
        Depth to recurse nested group memberships. Default: 10

    -GroupProcessingTimeThresholdSec <int>
        Threshold (in seconds) for logging slow group evaluations. Default: 5

    -ExcludedDomains <string[]>
        Wildcard patterns to exclude domains (e.g. *.dev, *.lab). Default: *.ohaihs.com

    -EnableAllGroupsQuery <bool>
        Query all groups in each domain instead of using CSV input. Default: true

    -EnableCrossDomainMemberLookups <bool>
        Enable recursion into group members across domain boundaries. Default: true

    -EnableConsoleOutput <bool>
        Enable live logging output to console. Default: true

    -EnableVerboseMode <bool>
        Enables full variable dump and debug logging. Default: true
        ⚠ WARNING: Can produce large logs!

    -EnableLocalDomain <bool>
        Include local (current) domain in the audit process. Default: true

    -SendEmail <bool>
        Send an email summary with logs attached. Default: true

    -UseFastLDAPLookups <bool>
        Use LDAP queries instead of AD cmdlets for performance. Default: true

    -EnableExcludedDomains <bool>
        Apply ExcludedDomains filtering. Default: true

    -EmailTo <string>
        Recipient of email summary report. Default: user@company.com

    -EmailFrom <string>
        Sender address for email summary. Default: script-bot@company.com

    -SmtpServer <string>
        SMTP server used to send emails. Default: mail.company.com

    -SmtpPort <int>
        Port for SMTP communication. Default: 25

    -Help
        Displays this help message and exits.

EXAMPLES

    .\get-ActiveDirectoryReports-TrustedDomains_v7.2.2_threaded.ps1
        Runs with all default settings.

    .\get-ActiveDirectoryReports-TrustedDomains_v7.2.2_threaded.ps1 -SendEmail $false -EnableVerboseMode $true
        Runs with verbose logging but disables email reporting.

    .\get-ActiveDirectoryReports-TrustedDomains_v7.2.2_threaded.ps1 -Help
        Prints this help message.

"@ | Write-Host
    exit
}

if ($Help) { Show-Help }

function Clear-AllScriptVariables {
    [CmdletBinding()]
    param (
        [switch]$IncludeGlobals
    )

    $paramVars = @(
        'RootFolder', 'OutputFolder', 'RetentionDays', 'MaxParallelDomainJobs',
        'GroupsPerJob', 'MaxGroupRecursionDepth', 'GroupProcessingTimeThresholdSec',
        'ExcludedDomains', 'EnableAllGroupsQuery', 'EnableCrossDomainMemberLookups',
        'EnableConsoleOutput', 'EnableVerboseMode', 'EnableLocalDomain',
        'SendEmail', 'UseFastLDAPLookups', 'EnableExcludedDomains',
        'EmailTo', 'EmailFrom', 'SmtpServer', 'SmtpPort', 'Help'
    )

    $varsToClear = @(
        # Runtime/Temp/Internal
        'scriptStartTime', 'Date', 'DayStamp', 'outputRoot', 'dailyFolder',
        'activityLogPath', 'failedAuthPath', 'DomainStatusPath', 'GroupInputFolder',
        'domainName', 'domainFolder', 'domainGroupEntries', 'rawGroups',
        'remoteComputer', 'Forest', 'ForestName', 'trusts', 'trustList',
        'reportScripts', 'groupMembershipScript', 'domainJobs',
        'AD_User_Export', 'AdminCount', 'DomainTrusts',
        'job', 'jobId', 'jobDomain', 'result', 'allLogs',
        'inputArray', 'targetDomain', 'GroupObject', 'GroupDomain', 'GroupName',
        'resolvedMembers', 'results', 'warnings', 'Trail', 'Depth',
        'groupDN', 'groupStart', 'elapsed',
        'g', 'entry', 'member', 'memberDomain',
        'scriptDuration', 'scriptTime', 'scriptTimeMin',
        'argList', 'arglist', 'sharedConsoleOutput', 'sharedVerboseMode',
        'groupData', 'csvFiles', 'rawData', 'nullCount',
        'activityLog', 'logQueue', 'logFilePath', 'logWriteFailures',
        'domainStatusTable', 'domainStatusCsv', 'logFlusher'
    )

    $varsToClear = $varsToClear | Where-Object { $_ -notin $paramVars }
    $removed = [System.Collections.Generic.List[string]]::new()

    foreach ($var in $varsToClear | Sort-Object -Unique) {
        foreach ($scope in @('Script', 'Local')) {
            try {
                $ref = Get-Variable -Name $var -Scope $scope -ErrorAction SilentlyContinue
                if ($null -ne $ref) {
                    # If it's a collection, empty it first
                    if ($ref.Value -is [System.Collections.IList] -or $ref.Value -is [System.Collections.IDictionary]) {
                        $ref.Value.Clear()
                    }
                    elseif ($ref.Value -is [System.Collections.Concurrent.ConcurrentQueue[object]]) {
                        while ($null -ne ($null = $ref.Value.TryDequeue([ref]$null))) {}
                    }
                    # Now remove the variable
                    Remove-Variable -Name $var -Scope $scope -Force
                    $removed.Add("$scope::$var")
                }
            } catch {
                Write-Warning "Failed to clear/remove variable: $scope::$var"
            }
        }

        if ($IncludeGlobals) {
            try {
                $gref = Get-Variable -Name $var -Scope Global -ErrorAction SilentlyContinue
                if ($null -ne $gref) {
                    if ($gref.Value -is [System.Collections.IList] -or $gref.Value -is [System.Collections.IDictionary]) {
                        $gref.Value.Clear()
                    }
                    elseif ($gref.Value -is [System.Collections.Concurrent.ConcurrentQueue[object]]) {
                        while ($null -ne ($null = $gref.Value.TryDequeue([ref]$null))) {}
                    }
                    Remove-Variable -Name $var -Scope Global -Force
                    $removed.Add("Global::$var")
                }
            } catch {
                Write-Warning "Failed to clear/remove Global::$var"
            }
        }
    }

    Write-Host "Cleared variables and emptied collections:" -ForegroundColor Cyan
    $removed | Sort-Object | ForEach-Object { Write-Host " - $_" }
}

Clear-AllScriptVariables -IncludeGlobal

$scriptStartTime = Get-Date

# --- Create variable dependent values ---
$Date = Get-Date -Format "HHmm_MM-yyyy-MM-dd"
$DayStamp = Get-Date -Format "yyyy-MM-dd"
$outputRoot = Join-Path $rootFolder $OutputFolder
$dailyFolder = Join-Path $outputRoot $DayStamp
$activityLogPath = Join-Path $outputRoot "GetReports-ActivityLog-$Date.csv"
$global:GroupInputFolder = Join-Path $rootFolder "group-input"
$failedAuthPath = Join-Path $dailyFolder "FailedAuthentication-$Date.txt"
$DomainStatusPath = Join-Path $OutputRoot "DomainStatus-$Date.csv"

# --- Script Info ---
$scriptversion  = "v7.2.2"
$scriptauthor   = "Alex Cherry"
$scriptupdated  = "2025-07-28"

# --- Globals for logging ---
$global:activityLog = @()
$global:logQueue = [System.Collections.Concurrent.ConcurrentQueue[object]]::new()
$global:logFilePath = $activityLogPath
$global:logWriteFailures = @()

# Ensure output dirs
foreach ($path in @($outputRoot, $dailyFolder)) {
    if (-not (Test-Path $path)) {
        New-Item -ItemType Directory -Path $path -Force | Out-Null
    }
}

# Not needed in start-job version
# # Check if Start-ThreadJob is available and working
# if (-not (Get-Command -Name Start-ThreadJob -ErrorAction SilentlyContinue)) {
#     try {
#         Import-Module ThreadJob -ErrorAction Stop
#         Write-Host "THreadjob loaded."
#         $threadfail = $false
#     } catch {
#         Write-Error "The 'ThreadJob' module is not installed or failed to load. Install it using: Install-Module ThreadJob -Scope CurrentUser -Force -AllowClobber"
#         $threadfail = $true
#     }

#     # Check again after import attempt
#     if (-not (Get-Command -Name Start-ThreadJob -ErrorAction SilentlyContinue)) {
#         $threadfail = $true
#     } else {
#         $threadfail = $false
#     }
# }

# if ($threadfail) {
#     $subject = "ThreadJob Module Load Failure on $env:COMPUTERNAME"
#     $body    = "The 'ThreadJob' module failed to load or is missing on $env:COMPUTERNAME at $(Get-Date -Format 's')."

#     Send-MailMessage -From $EmailFrom -To $EmailTo -Subject $subject -Body $body -SmtpServer $smtpServer -Port $smtpPort
#     "ThreadJob module failed to load. Exit code 20." | Out-File $activityLogPath -Append
#     exit 20
# }


# Start background flushing job for logs (one per run)
$global:logFlusher = Start-Job -ScriptBlock {
    while ($true) {
        Start-Sleep -Milliseconds 250

        try {
            $logRecord = $null

            while ($global:logQueue.TryDequeue([ref]$logRecord)) {
                $line = "[$($logRecord.Timestamp)] [$($logRecord.ActionType)] [$($logRecord.DomainName)] [$($logRecord.RemoteComputer)] [$($logRecord.ScriptName)] $($logRecord.Message)"

                $success = $false

                for ($i = 0; $i -lt 3; $i++) {
                    try {
                        Add-Content -Path $using:activityLogPath -Value $line -ErrorAction Stop
                        $success = $true
                        break
                    } catch {
                        Start-Sleep -Milliseconds 100
                    }
                }

                if (-not $success -and $using:EnableVerboseMode) {
                    Write-Warning "Failed to write log record after 3 attempts: $line"
                }
            }

        } catch {
            if ($using:EnableVerboseMode) {
                Write-Warning "Log flusher error: $($_.Exception.Message)"
            }
        }
    }
}

function Stop-LogFlusher {
    param (
        [string]$LogFilePath,
        [System.Collections.Concurrent.ConcurrentQueue[object]]$LogQueue
    )

    Write-Verbose "Stopping log flusher and flushing remaining log records..."

    # Wait a moment for jobs to finish enqueuing final logs
    Start-Sleep -Seconds 2

    # Final flush loop
    $logRecord = $null
    while ($LogQueue.TryDequeue([ref]$logRecord)) {
        try {
            $line = "[$($logRecord.Timestamp)] [$($logRecord.ActionType)] [$($logRecord.DomainName)] [$($logRecord.RemoteComputer)] [$($logRecord.ScriptName)] $($logRecord.Message)"
            Add-Content -Path $LogFilePath -Value $line -ErrorAction Stop
        } catch {
            Write-Warning "Failed to flush final log record: $($_.Exception.Message)"
        }
    }

    # Stop and remove the background job
    if ($global:logFlusher -and (Get-Job -Id $global:logFlusher.Id -ErrorAction SilentlyContinue)) {
        try {
            if ($global:logFlusher.State -ne 'Stopped' -and $global:logFlusher.State -ne 'Completed') {
                Stop-Job -Job $global:logFlusher -ErrorAction SilentlyContinue
                Wait-Job -Job $global:logFlusher -Timeout 5 -ErrorAction SilentlyContinue | Out-Null
            }
            Receive-Job -Job $global:logFlusher -ErrorAction SilentlyContinue | Out-Null
            Remove-Job -Job $global:logFlusher -Force -ErrorAction SilentlyContinue
        } catch {
            Write-Warning "Could not clean up log flusher job: $($_.Exception.Message)"
        }
    }

    Write-Verbose "Log flusher cleanup complete."
}

# Initialize logs
$activityLog = @()

function Log-Activity {
    param (
        [string]$DomainName,
        [string]$RemoteComputer,
        [string]$ScriptName,
        [string]$ActionType,
        [string]$Message
    )

    # Normalize ActionType before evaluating
    $normalizedType = $ActionType.ToUpperInvariant()

    if ($normalizedType -eq 'DEBUG' -and -not $EnableVerboseMode) {
        return
    }


    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    # Read values from global scope
    $sharedLogQueue      = $logQueue
    $sharedConsoleOutput = $EnableConsoleOutput
    $sharedVerboseMode   = $EnableVerboseMode

    # Optional debug information
    $callerInfo = ""
    if ($sharedVerboseMode) {
        $invocation = $MyInvocation
        $callerInfo = " (from $($invocation.ScriptName):$($invocation.ScriptLineNumber) in $($invocation.MyCommand.Name))"
    }

    $fullMessage = "$Message$callerInfo"

    $logRecord = [PSCustomObject]@{
        Timestamp       = $timestamp
        DomainName      = $DomainName
        RemoteComputer  = $RemoteComputer
        ScriptName      = $ScriptName
        ActionType      = $ActionType
        Message         = $fullMessage
    }

    # Enqueue log safely if queue exists
    if ($sharedLogQueue -is [System.Collections.Concurrent.ConcurrentQueue[object]]) {
        $sharedLogQueue.Enqueue($logRecord)
    }

    # Console output (if enabled)
    if ($sharedConsoleOutput -ne $false) {
        $color = switch ($ActionType.ToUpper()) {
            "INFO"    { "Cyan" }
            "SUCCESS" { "Green" }
            "WARNING" { "Yellow" }
            "ERROR"   { "Red" }
            "RUNTIME" { "White" }
            "NOTIFY"  { "Blue" }
            default   { "Gray" }
        }

        Write-Host "[$timestamp] [$ActionType] [$DomainName] [$RemoteComputer] [$ScriptName] $fullMessage" -ForegroundColor $color
    }

    # Domain status tracking
    if (-not $script:domainStatusTable) {
        $script:domainStatusTable = @{}
    }

    if ($DomainName -and $DomainName -notlike "<*>" -and $DomainName -ne $hostname) {
        $statusPriority = @{ "SUCCESS" = 1; "WARNING" = 2; "ERROR" = 3 }

        $current = if ($script:domainStatusTable.ContainsKey($DomainName)) {
            $script:domainStatusTable[$DomainName]
        } else {
            "SUCCESS"
        }

        $defaultPriority = 0
        $currentPriority = if ($statusPriority.ContainsKey($current)) { $statusPriority[$current] } else { $defaultPriority }

        if ($statusPriority.ContainsKey($ActionType.ToUpper()) -and
            $statusPriority[$ActionType.ToUpper()] -gt $currentPriority) {
            $script:domainStatusTable[$DomainName] = $ActionType.ToUpper()
        }
    }
}

function Clean-OldReports {
    param (
        [string]$ReportRoot,
        [int]$RetentionDays = 30
    )

    $scriptName = "Cleanup"
    Log-Activity "<Init>" $hostname $scriptName "INFO" "Running cleanup for folders older than $RetentionDays days under $ReportRoot"

    try {
        $cutoff = (Get-Date).AddDays(-$RetentionDays)

        $oldFolders = Get-ChildItem -Path $ReportRoot -Directory -ErrorAction Stop |
            Where-Object {
                $_.Name -match '^\d{4}-\d{2}-\d{2}$' -and $_.LastWriteTime -lt $cutoff
            }

        if ($oldFolders.Count -eq 0) {
            Log-Activity "<Init>" $hostname $scriptName "INFO" "No old folders found to delete."
            return
        }

        # Cleanup loose report files like domain trusts, status, logs, etc.
        $filePatterns = @(
            "*-DomainTrusts-*.csv",
            "*-DomainStatus-*.csv",
            "*-ActivityLog-*.log",
            "*-results-*.zip"
        )

        foreach ($pattern in $filePatterns) {
            $filesToDelete = Get-ChildItem -Path $ReportRoot -Recurse -File -Filter $pattern -ErrorAction SilentlyContinue |
                Where-Object { $_.LastWriteTime -lt $cutoff }

            foreach ($file in $filesToDelete) {
                try {
                    $sizeKB = [math]::Round($file.Length / 1KB, 2)
                    Log-Activity "<Cleanup>" $file.FullName $scriptName "INFO" "Deleting loose file ($sizeKB KB)"
                    Remove-Item -Path $file.FullName -Force -ErrorAction Stop
                } catch {
                    Log-Activity "<Cleanup>" $hostname $scriptName "ERROR" "Failed to delete file $($file.FullName): $($_.Exception.Message)"
                }
            }
        }

        foreach ($folder in $oldFolders) {
            try {
                # Log each file before deletion
                $files = Get-ChildItem -Path $folder.FullName -Recurse -File -ErrorAction SilentlyContinue
                foreach ($file in $files) {
                    $sizeKB = [math]::Round($file.Length / 1KB, 2)
                    Log-Activity "<Cleanup>" $file.FullName $scriptName "INFO" "Deleting file ($sizeKB KB)"
                }

                # Now delete the folder
                Remove-Item -Path $folder.FullName -Recurse -Force -ErrorAction Stop
                Log-Activity "<Cleanup>" $hostname $scriptName "SUCCESS" "Deleted folder: $($folder.FullName)"
            } catch {
                Log-Activity "<Cleanup>" $hostname $scriptName "ERROR" "Failed to delete folder $($folder.FullName): $($_.Exception.Message)"
            }
        }
    } catch {
        Log-Activity "<Cleanup>" $hostname $scriptName "ERROR" "Cleanup process failed: $($_.Exception.Message)"
    }
}

function Show-StartupConfig {
    [CmdletBinding()]
    param ()

    if (-not $EnableVerboseMode) { return }

    $scriptName = "ConfigSummary"
    Log-Activity "<Config>" $hostname $scriptName "INFO" "Verbose mode is enabled — logging all defined configuration variables"

    $protected = @(
        'args','input','this','Error','Host','ExecutionContext','MyInvocation',
        'PSItem','pwd','HOME','PSVersionTable','null','true','false',
        'ENV','PID'
    )

    # Collect variables from Script and Local scopes
    $allVars = @()
    foreach ($scope in @('Script','Local')) {
        $allVars += Get-Variable -Scope $scope -ErrorAction SilentlyContinue
    }

    # Optionally also include Global scope for completeness
    $allVars += Get-Variable -Scope Global -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '^GroupInputFolder$' -or $_.Name -like 'global:*' }

    # Filter and deduplicate
    $logged = @{}
    foreach ($v in $allVars) {
        if ($v.Name -in $protected -or $logged.ContainsKey($v.Name)) { continue }
        $logged[$v.Name] = $true

        # Format value
        $val = $v.Value
        switch ($val) {
            { $_ -eq $null }        { $display = '[null]' ; break }
            { $_ -is [Array] }      { $display = ($val -join ', ') ; break }
            { $_ -is [string] }     { $display = $val.Trim() ; break }
            { $_ -is [object] }     { $display = "$($val.ToString())" ; break }
            default                 { $display = "$val" }
        }

        Log-Activity "<Config>" $hostname $scriptName "DEBUG" "{0,-22}: {1}" -f $v.Name, $display
    }
}


function Test-DomainAuth {
    param (
        [string]$DomainName,
        [string]$RemoteComputer
    )

    try {
        Get-ADDomain -Server $RemoteComputer -ErrorAction Stop | Out-Null
        Log-Activity -DomainName $DomainName -RemoteComputer $RemoteComputer -ScriptName "AuthTest" -ActionType "SUCCESS" -Message "Authenticated successfully."
        return $true
    } catch {
        $outer   = $_.Exception
        $deepest = $outer
        while ($deepest.InnerException) {
            $deepest = $deepest.InnerException
        }

        $baseMessage = "Authentication failed against ${RemoteComputer}: $($outer.Message)"
        $innerNote = if ($deepest -ne $outer) { " | InnerException: $($deepest.Message)" } else { "" }
        $fullMessage = "$baseMessage$innerNote"

        Log-Activity -DomainName $DomainName -RemoteComputer $RemoteComputer -ScriptName "AuthTest" -ActionType "ERROR" -Message $fullMessage
        return $false
    }
}

function Resolve-TrustedDomainDC {
    param (
        [string]$DomainName
    )

    $logName = "DC-Resolve"
    $testedDCs = @()
    $pdc = $null

    # Attempt to discover and log the Preferred PDC
    try {
        $pdc = Get-ADDomainController -Discover -Service "PrimaryDC" -DomainName $DomainName -ErrorAction Stop
        $pdcName = $pdc.DNSHostName 
        if (-not $pdcName) { $pdcName = $pdc.HostName } 
        if (-not $pdcName) { $pdcName = $pdc.Name }
        Log-Activity $DomainName $pdcName $logName "INFO" "Preferred PDC discovered: $pdcName"
    } catch {
        Log-Activity $DomainName "<None>" $logName "WARNING" "PDC resolution failed: $($_.Exception.Message)"
    }

    # Try the preferred PDC first
    if ($pdc) {
        $pdcCandidates = @($pdc.DNSHostName, $pdc.HostName, $pdc.Name) | Where-Object { $_ }

        foreach ($candidate in $pdcCandidates) {
            $testedDCs += $candidate
            if (Test-Connection -ComputerName $candidate -Count 1 -Quiet) {
                Log-Activity $DomainName $candidate $logName "INFO" "Selected preferred PDC: $candidate"
                
                # Add SID to global DomainSidMap if resolution succeeds
                try {
                    $domainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $DomainName)
                    $domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($domainContext)
                    $sid = $domainObj.GetDirectoryEntry().objectSID.Value
                    $script:DomainSidMap[$DomainName.ToLower()] = $sid
                    Log-Activity $DomainName $candidate "SID-Map" "DEBUG" "Mapped SID: $sid"
                } catch {
                    Log-Activity $DomainName $candidate "SID-Map" "WARNING" "Failed to resolve SID: $($_.Exception.Message)"
                }

                return [PSCustomObject]@{
                    Computer    = $candidate
                    DcsTested   = $testedDCs
                    Domain      = $DomainName
                    Status      = "Success"
                    SID         = $sid
                }
            }
        }

        Log-Activity $DomainName "<None>" $logName "WARNING" "Could not reach preferred PDC after testing known candidates"
    }

    # Try fallback DCs
    try {
        $dcs = Get-ADDomainController -Filter * -Server $DomainName
        foreach ($dc in $dcs) {
            $candidate = $dc.DNSHostName
            if (-not $candidate) { $candidate = $dc.HostName }
            if (-not $candidate) { $candidate = $dc.Name }
            if (-not $candidate) { continue }

            $testedDCs += $candidate
            Log-Activity $DomainName $candidate $logName "INFO" "Testing fallback DC: $candidate"

            if (Test-Connection -ComputerName $candidate -Count 1 -Quiet) {
                Log-Activity $DomainName $candidate $logName "INFO" "Fallback DC selected: $candidate"
                # Add SID to global DomainSidMap if resolution succeeds
                try {
                    $domainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $DomainName)
                    $domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($domainContext)
                    $sid = $domainObj.GetDirectoryEntry().objectSID.Value
                    $script:DomainSidMap[$DomainName.ToLower()] = $sid
                    Log-Activity $DomainName $candidate "SID-Map" "INFO" "Mapped SID: $sid"
                } catch {
                    Log-Activity $DomainName $candidate "SID-Map" "WARNING" "Failed to resolve SID: $($_.Exception.Message)"
                }

                return [PSCustomObject]@{
                    Computer    = $candidate
                    DcsTested   = $testedDCs
                    Domain      = $DomainName
                    Status      = "Success"
                    SID         = $sid
                }
            } else {
                Log-Activity $DomainName $candidate $logName "WARNING" "Fallback DC $candidate unreachable via ping — skipping"
            }
        }

        $dcList = $testedDCs -join ", "
        Log-Activity $DomainName "<None>" $logName "ERROR" "All fallback DCs failed. Tested: $dcList"
    } catch {
        Log-Activity $DomainName "<None>" $logName "ERROR" "Fallback DC lookup failed: $($_.Exception.Message)"
        return [PSCustomObject]@{
            Computer    = $null
            DcsTested   = $testedDCs
            Domain      = $DomainName
            Status      = "Fallback DC lookup failed: $($_.Exception.Message)"
        }
    }

    # Final fallback return
    return [PSCustomObject]@{
        Computer    = $null
        DcsTested   = $testedDCs
        Domain      = $DomainName
        Status      = "No reachable DCs responded to ping"
    }
}

function Send-EmailReport {
    param ([string]$Date)

    Log-Activity "<AllDomains>" $hostname "EmailReport" "INFO" "Email sending is ENABLED. Attempting to send report..."

    try {
        $activityLog = Import-Csv -Path $activityLogPath -Encoding UTF8

        $warningsAndErrors = $activityLog | Where-Object { $_.ActionType -match "ERROR|WARNING" }
        $countErrors = ($warningsAndErrors | Where-Object { $_.ActionType -eq "ERROR" }).Count
        $countWarnings = ($warningsAndErrors | Where-Object { $_.ActionType -eq "WARNING" }).Count

        $slowGroupLookups = $activityLog | Where-Object {
            $_.ActionType -eq "WARNING" -and
            $_.Message -like "*exceeded time threshold*"
        }
        $countSlowLookups = $slowGroupLookups.Count

        # Domain grouping
        $domainsSuccess = ($activityLog | Where-Object { $_.ActionType -eq "SUCCESS" }).DomainName | Sort-Object -Unique
        $domainsWarning = ($activityLog | Where-Object { $_.ActionType -eq "WARNING" }).DomainName | Sort-Object -Unique
        $domainsError   = ($activityLog | Where-Object { $_.ActionType -eq "ERROR"   }).DomainName | Sort-Object -Unique

        $failedAuthReport = ""
        if (Test-Path $failedAuthPath) {
            $failedAuthDomains = Get-Content $failedAuthPath | Where-Object { $_ -match '\S' }
            $failedAuthReport = if ($failedAuthDomains.Count -gt 0) {
                "`nDomains with Failed Authentication:`n" + ($failedAuthDomains -join "`n") + "`n"
            } else {
                "`nNo authentication failures were detected.`n"
            }
        }

        $crossDomainStatus     = if ($EnableCrossDomainMemberLookups) { "ENABLED" } else { "DISABLED" }
        $allGroupsQueryStatus  = if ($EnableAllGroupsQuery) { "ENABLED" } else { "DISABLED" }
        $consoleOutputStatus   = if ($EnableConsoleOutput) { "ENABLED" } else { "DISABLED" }
        $localDomainStatus     = if ($EnableLocalDomain) { "ENABLED" } else { "DISABLED" }

        $configSummary = @"
Script Configuration:
All Groups Query             : $allGroupsQueryStatus
Cross-Domain Lookups        : $crossDomainStatus
Console Output              : $consoleOutputStatus
Local Domain Processing     : $localDomainStatus
Max Group Recursion Depth   : $MaxGroupRecursionDepth
Slow Group Lookup Time      : $GroupProcessingTimeThresholdSec seconds
"@

        $summaryHeader = @"
Summary of Domain Processing:
  Success : $($domainsSuccess.Count) - $($domainsSuccess -join ", ")
  Warnings: $($domainsWarning.Count) - $($domainsWarning -join ", ")
  Errors  : $($domainsError.Count) - $($domainsError -join ", ")

Cross-domain member resolution: $crossDomainStatus
Slow GroupMembership lookups with threshold $GroupProcessingTimeThresholdSec seconds: $countSlowLookups
`n`n
$failedAuthReport
"@

        # improved formatting of error lines
        $details = if ($warningsAndErrors.Count -eq 0) {
            "No errors or warnings occurred during the audit."
        } else {
            $warningsAndErrors | ForEach-Object {
                "[{0}] [{1}] [{2}] [{3}] {4}" -f $_.ActionType, $_.DomainName, $_.RemoteComputer, $_.ScriptName, $_.Message
            } -join "`n"
        }

        $scriptInfoLine = "Script: $($MyInvocation.MyCommand.Name) | Version: $scriptversion | Author: $scriptauthor | Last Updated: $scriptupdated`n`n"
        $body = $scriptInfoLine + $summaryHeader + $configSummary + $details
        $subject = "AD Audit Summary: $countErrors ERROR(s), $countWarnings WARNING(s) - $Date"

        $attachments = @($activityLogPath)
        if (Test-Path $failedAuthPath) {
            $attachments += $failedAuthPath
        }

        # Pause to allow the buffer to flush to write the log file.
        Start-Sleep -Milliseconds 300
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()


        Send-MailMessage -To $emailTo -From $emailFrom -Subject $subject -Body $body -SmtpServer $smtpServer -Port $smtpPort -Attachments $attachments
        Log-Activity "<AllDomains>" $hostname "EmailReport" "NOTIFY" "Email sent to $emailTo with activity log and any failed authentication log"
    } catch {
        Log-Activity "<AllDomains>" $hostname "EmailReport" "ERROR" "Failed to send email: $_"
    }
}

function Get-AllGroupInputsFromCsvFolder {
    [CmdletBinding()]
    param ()

    $scriptName = "GroupInputLoader"
    $groupData = @()  # Native array of PSCustomObjects

    if (-not (Test-Path $global:GroupInputFolder)) {
        Log-Activity "<Init>" $hostname $scriptName "WARNING" "Group input folder does not exist: $global:GroupInputFolder"
        return $groupData
    }

    $csvFiles = Get-ChildItem -Path $global:GroupInputFolder -Filter *.csv -File -ErrorAction SilentlyContinue

    if ($csvFiles.Count -eq 0) {
        Log-Activity "<Init>" $hostname $scriptName "WARNING" "No CSV files found in folder: $global:GroupInputFolder"
        return $groupData
    }

    foreach ($csvFile in $csvFiles) {
        try {
            $rawData = Import-Csv -Path $csvFile.FullName
            if ($rawData.Count -eq 0) {
                Log-Activity "<Init>" $hostname $scriptName "WARNING" "$($csvFile.Name) is empty"
                continue
            }

            $sampleHeaders = $rawData[0].PSObject.Properties.Name
            $domainCol = $sampleHeaders | Where-Object { $_ -match 'domain' } | Select-Object -First 1
            $groupCol  = $sampleHeaders | Where-Object { $_ -match 'group'  } | Select-Object -First 1

            if (-not $domainCol -or -not $groupCol) {
                Log-Activity "<Init>" $hostname $scriptName "WARNING" "Could not identify Domain and Group columns in $($csvFile.Name)"
                continue
            }

            $entryCount = 0
            foreach ($entry in $rawData) {
                $domainVal = $entry.$domainCol
                $groupVal  = $entry.$groupCol

                if ([string]::IsNullOrWhiteSpace($domainVal) -or [string]::IsNullOrWhiteSpace($groupVal)) {
                    continue
                }

                # Strip quotes and whitespace
                $cleanDomain = ($domainVal -replace "^[\'""]+|[\'""]+$", "").ToLower().Trim()
                $cleanGroup  = ($groupVal -replace "^[\'""]+|[\'""]+$", "").Trim()

                if ($cleanDomain -and $cleanGroup) {
                    $groupData += [PSCustomObject]@{
                        Domain    = $cleanDomain
                        GroupName = $cleanGroup
                }

                $entryCount++
                }
            }

            Log-Activity "<Init>" $hostname $scriptName "INFO" "Loaded $entryCount valid entries from $($csvFile.Name) using columns '$domainCol' and '$groupCol'"
        } catch {
            Log-Activity "<Init>" $hostname $scriptName "ERROR" "Failed to process $($csvFile.FullName): $_"
        }
    }

    return $groupData
}

function Compress-DomainResults {
    [CmdletBinding()]
    param ()

    $root = Join-Path $outputRoot $DayStamp

    if (-not (Test-Path $root)) {
        Log-Activity -Level "ERROR" -Message "Compression failed: root path not found - $root"
        return
    }

    Get-ChildItem -Path $root -Directory | ForEach-Object {
        $domainFolder = $_.FullName
        $domainName = $_.Name
        $zipName = "$domainName-results-$Date.zip"
        $zipPath = Join-Path $domainFolder $zipName

        $filesToZip = Get-ChildItem -Path $domainFolder -File | Where-Object { $_.Name -ne $zipName }

        if ($filesToZip.Count -eq 0) {
            Log-Activity -Level "WARN" -Message "Skipping compression: No files to zip in '$domainFolder'"
            return
        }

        try {
            Compress-Archive -Path $filesToZip.FullName -DestinationPath $zipPath -Force

            if (Test-Path $zipPath) {
                $filesToZip | Remove-Item -Force
                Log-Activity -Level "INFO" -Message "Compressed '$domainName' folder to '$zipName' and cleaned up originals"
            }
            else {
                Log-Activity -Level "ERROR" -Message "Compression failed: ZIP not found after Compress-Archive in '$domainFolder'"
            }
        }
        catch {
            Log-Activity -Level "ERROR" -Message "Exception during compression in '$domainFolder': $_"
        }
    }
}

# Log script start time
$hostName = [System.Net.Dns]::GetHostName()
Log-Activity "<SCRIPT>" $hostName "Init" "INFO" "Script starting at $DayStamp"
Show-StartupConfig
Write-Host "Please be aware that long pauses are normal as the script waits for each domain's job and group sub-jobs to finish, as job output can only be" -ForegroundColor Yellow -BackgroundColor Black
Write-Host "displayed on the console once the job is finished." -ForegroundColor Yellow -BackgroundColor Black

# Load the group values from the CSVs if the all groups toggle is false
if (-not $EnableAllGroupsQuery) {
    $global:GroupInputArray = @(Get-AllGroupInputsFromCsvFolder)
}

# # Check that Start-ThreadJob is available
# if (-not (Get-Command Start-ThreadJob -ErrorAction SilentlyContinue)) {
#     Write-Warning "Start-ThreadJob is not available. Please install the ThreadJob module: Install-Module ThreadJob"
#     Exit 1
# }

# Domain and trust discovery that exports the trust list for logging purposes and import purposes
Import-Module ActiveDirectory

# Logging if domain exclusions are enabled
if (-not $enableExcludedDomains) {
    Log-Activity "<Trusts>" $hostname "TrustDiscovery" "INFO" "Domain exclusions are disabled. All domains will be processed."
} else {
    Log-Activity "<Init>" $hostname "TrustDiscovery" "INFO" ("Excluded domains list: " + ($ExcludedDomains -join ", "))
}

# Ensure $enableExcludedDomains is not null before using it
if ($null -eq $enableExcludedDomains) {
    $enableExcludedDomains = @()
}

# Get the forest name, create the trust list, export to a file, and build the domain SID map
try {
    $Forest = Get-ADForest -ErrorAction Stop
    $ForestName = $Forest.Name
    # Grab raw trusts list
    $trusts = Get-ADTrust -Filter * -ErrorAction Stop
    # If the EnableLocalDomain variable is true, process the host's local domain
    if ($EnableLocalDomain) {
        $localTrust = [PSCustomObject]@{
            Name            = $contextDomain
            TrustType       = '<Local>'
            TrustDirection  = '<Local>'
            TrustAttributes = '<Local>'
        }

        # Append to trust list array
        $trusts += $localTrust
    }
    # Export CSV before removing domains that are excluded
    $csvPath1 = Join-Path $outputRoot "$ForestName-DomainTrusts-$Date.csv"
    $trusts | Export-Csv -Path $csvPath1 -NoTypeInformation

    # Apply wildcard-aware exclusion and direction filter after export
    $trusts = $trusts | Where-Object {
        $name = $_.Name
        if ([string]::IsNullOrWhiteSpace($name)) { return $false }

        $name = $name.ToLower().Trim()

        $excluded = $EnableExcludedDomains -and ($ExcludedDomains | Where-Object { $name -like $_ })
        $directionOK = $_.TrustDirection -ne 'Outbound'

        return -not $excluded -and $directionOK
    }

    $trustList = $trusts | Select-Object Name, TrustType, TrustDirection, TrustAttributes
    Log-Activity -DomainName $ForestName -RemoteComputer $hostname -ScriptName "Get-ADTrust" -ActionType "INFO" -Message "Exported domain trusts to $csvPath1"
} catch {
    Log-Activity -DomainName "<LocalForest>" -RemoteComputer $hostname -ScriptName "Get-ADTrust" -ActionType "ERROR" -Message $_.Exception.Message
    Exit
}

# Remove function and move logic to root script for better logging

# Initialize the domain and output the numbers of trusts if in debug
$domainJobs = @()
$jobStartTimes = @{}
Log-Activity "<Init>" $hostname "DomainJobs" "DEBUG" "Total jobs for trust $($TrustList.Name): $($TrustList.Count)"
Log-Activity "<Init>" $hostname "DomainJobs" "DEBUG" "`$MaxParallelDomainJobs is set to $MaxParallelDomainJobs"
$TrustList | ForEach-Object { Log-Activity "<Init>" $hostname "DomainJobs" "DEBUG" "[TRACE] Trust: $($_.Name)" }

# Initialize the job counters
[int]$totalJobs   = 0
[int]$jobsDone    = 0
[int]$jobsRunning = 0


foreach ($trust in $TrustList) {
    $domainName = $trust.Name
    if ([string]::IsNullOrWhiteSpace($domainName)) {
        Log-Activity "<Init>" $hostname "DomainExclusion" "ERROR" "Trust object missing domain name. Skipping."
        continue
    }
    # Wildcard-aware exclusion check (compact)
    if ($EnableExcludedDomains -and $ExcludedDomains | Where-Object { $domainName -like $_ }) {
        Log-Activity "<Init>" $hostname "DomainExclusion" "INFO" "Skipping excluded domain: $domainName"
        continue
    }

    Log-Activity $domainName $hostname "DomainJobs" "DEBUG" "Started domain job for trustList: $trust"
    Log-Activity $domainName $hostname "DomainJobs" "DEBUG"  "[DEBUG] Inspecting trust: $($trust.Name)"
    Log-Activity $domainName $hostname "DomainJobs" "DEBUG"  "[DEBUG] Current domainJobs count: $($domainJobs.Count)"

    while ($domainJobs.Count -ge $MaxParallelDomainJobs) {
        Start-Sleep -Milliseconds 500
        $domainJobs = $domainJobs | Where-Object { $_.State -eq 'Running' }
    }

    Log-Activity "$domainName" $hostname "DomainJobs" "DEBUG" "Start-DomainJobs returning $($domainJobs.Count) job(s)"

    # Start parallel job
    $job = Start-Job -Name "DomainJob-$domainName" `
    -InitializationScript {
        $script:StartTime = Get-Date
    } `
    -ScriptBlock {
        param (
            $DomainName,
            $Trust,
            $OutputRoot,
            $Date,
            $EnableAllGroupsQuery,
            $EnableCrossDomainMemberLookups,
            $EnableConsoleOutput,
            $GroupInputArray,
            $ActivityLogPath,
            $DailyFolder,
            $UseFastLDAPLookups,
            [int]$GroupProcessingTimeThresholdSec,
            $EnableVerboseMode,
            $global:logQueue,
            [int]$MaxGroupRecursionDepth,
            [int]$GroupsPerJob,
            [hashtable] $DomainSidMap
        )

        # Parallelism test: show thread & timestamp
        Log-Activity $DomainName $hostname "DomainJobs" "DEBUG" "Thread start time: $($script:StartTime.ToString('HH:mm:ss')) on thread $([Threading.Thread]::CurrentThread.ManagedThreadId)"

        Import-Module ActiveDirectory

        # Initialize job log
        $jobLog = New-Object System.Collections.Generic.List[Object]

        # Includee the required functions
        function Log-Activity {
            param (
                [string]$DomainName,
                [string]$RemoteComputer,
                [string]$ScriptName,
                [string]$ActionType,
                [string]$Message
            )

            # Normalize ActionType before evaluating
            $normalizedType = $ActionType.ToUpperInvariant()

            if ($normalizedType -eq 'DEBUG' -and -not $EnableVerboseMode) {
                return
            }

            $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

            $callerInfo = ""
            if ($using:EnableVerboseMode) {
                $invocation = $MyInvocation
                $callerInfo = " (from $($invocation.ScriptName):$($invocation.ScriptLineNumber) in $($invocation.MyCommand.Name))"
            }

            $fullMessage = "$Message$callerInfo"

            $logRecord = [PSCustomObject]@{
                Timestamp       = $timestamp
                DomainName      = $DomainName
                RemoteComputer  = $RemoteComputer
                ScriptName      = $ScriptName
                ActionType      = $ActionType
                Message         = $fullMessage
            }

            # Thread-safe enqueue to shared log
            # Safely localize shared values
            $sharedLogQueue        = $logQueue

            if ($sharedLogQueue -is [System.Collections.Concurrent.ConcurrentQueue[object]]) {
                $sharedLogQueue.Enqueue($logRecord)
            }

            # Console output
            if ($using:EnableConsoleOutput -ne $false) {
                $color = switch ($ActionType.ToUpper()) {
                    "INFO"    { "Cyan" }
                    "SUCCESS" { "Green" }
                    "WARNING" { "Yellow" }
                    "ERROR"   { "Red" }
                    "RUNTIME" { "White" }
                    "NOTIFY"  { "Blue" }
                    default   { "Gray" }
                }
                Write-Host "[$timestamp] [$ActionType] [$DomainName] [$RemoteComputer] [$ScriptName] $fullMessage" -ForegroundColor $color
            }

            # Domain status table
            if (-not $script:domainStatusTable) {
                $script:domainStatusTable = @{}
            }

            if ($DomainName -and $DomainName -notlike "<*>" -and $DomainName -ne $hostname) {
                $statusPriority = @{ "SUCCESS" = 1; "WARNING" = 2; "ERROR" = 3 }

                $current = if ($script:domainStatusTable.ContainsKey($DomainName)) {
                    $script:domainStatusTable[$DomainName]
                } else {
                    "SUCCESS"
                }

                $defaultPriority = 0
                $currentPriority = if ($statusPriority.ContainsKey($current)) { $statusPriority[$current] } else { $defaultPriority }

                if ($statusPriority.ContainsKey($ActionType.ToUpper()) -and
                    $statusPriority[$ActionType.ToUpper()] -gt $currentPriority) {
                    $script:domainStatusTable[$DomainName] = $ActionType.ToUpper()
                }
            }
        }

        function Resolve-TrustedDomainDC {
            param (
                [string]$DomainName
            )

            $logName = "DC-Resolve"
            $testedDCs = @()
            $pdc = $null

            # Attempt to discover and log the Preferred PDC
            try {
                $pdc = Get-ADDomainController -Discover -Service "PrimaryDC" -DomainName $DomainName -ErrorAction Stop
                $pdcName = $pdc.DNSHostName 
                if (-not $pdcName) { $pdcName = $pdc.HostName } 
                if (-not $pdcName) { $pdcName = $pdc.Name }
                Log-Activity $DomainName $pdcName $logName "INFO" "Preferred PDC discovered: $pdcName"
            } catch {
                Log-Activity $DomainName "<None>" $logName "WARNING" "PDC resolution failed: $($_.Exception.Message)"
            }

            # Try the preferred PDC first
            if ($pdc) {
                $pdcCandidates = @($pdc.DNSHostName, $pdc.HostName, $pdc.Name) | Where-Object { $_ }

                foreach ($candidate in $pdcCandidates) {
                    $testedDCs += $candidate
                    if (Test-Connection -ComputerName $candidate -Count 1 -Quiet) {
                        Log-Activity $DomainName $candidate $logName "INFO" "Selected preferred PDC: $candidate"
                        return [PSCustomObject]@{
                            Computer    = $candidate
                            DcsTested   = $testedDCs
                            Domain      = $DomainName
                            Status      = "Success"
                        }
                    }
                }

                Log-Activity $DomainName "<None>" $logName "WARNING" "Could not reach preferred PDC after testing known candidates"
            }

            # Try fallback DCs
            try {
                $dcs = Get-ADDomainController -Filter * -Server $DomainName
                foreach ($dc in $dcs) {
                    $candidate = $dc.DNSHostName
                    if (-not $candidate) { $candidate = $dc.HostName }
                    if (-not $candidate) { $candidate = $dc.Name }
                    if (-not $candidate) { continue }

                    $testedDCs += $candidate
                    Log-Activity $DomainName $candidate $logName "INFO" "Testing fallback DC: $candidate"

                    if (Test-Connection -ComputerName $candidate -Count 1 -Quiet) {
                        Log-Activity $DomainName $candidate $logName "INFO" "Fallback DC selected: $candidate"
                        return [PSCustomObject]@{
                            Computer    = $candidate
                            DcsTested   = $testedDCs
                            Domain      = $DomainName
                            Status      = "Success"
                        }
                    } else {
                        Log-Activity $DomainName $candidate $logName "WARNING" "Fallback DC $candidate unreachable via ping — skipping"
                    }
                }

                $dcList = $testedDCs -join ", "
                Log-Activity $DomainName "<None>" $logName "ERROR" "All fallback DCs failed. Tested: $dcList"
            } catch {
                Log-Activity $DomainName "<None>" $logName "ERROR" "Fallback DC lookup failed: $($_.Exception.Message)"
                return [PSCustomObject]@{
                    Computer    = $null
                    DcsTested   = $testedDCs
                    Domain      = $DomainName
                    Status      = "Fallback DC lookup failed: $($_.Exception.Message)"
                }
            }

            # Final fallback return
            return [PSCustomObject]@{
                Computer    = $null
                DcsTested   = $testedDCs
                Domain      = $DomainName
                Status      = "No reachable DCs responded to ping"
            }
        }
        function Test-DomainAuth {
            param (
                [string]$DomainName,
                [string]$RemoteComputer
            )

            try {
                Get-ADDomain -Server $RemoteComputer -ErrorAction Stop | Out-Null
                Log-Activity -DomainName $DomainName -RemoteComputer $RemoteComputer -ScriptName "AuthTest" -ActionType "SUCCESS" -Message "Authenticated successfully."
                return $true
            } catch {
                $outer   = $_.Exception
                $deepest = $outer
                while ($deepest.InnerException) {
                    $deepest = $deepest.InnerException
                }

                $baseMessage = "Authentication failed against ${RemoteComputer}: $($outer.Message)"
                $innerNote = if ($deepest -ne $outer) { " | InnerException: $($deepest.Message)" } else { "" }
                $fullMessage = "$baseMessage$innerNote"

                Log-Activity -DomainName $DomainName -RemoteComputer $RemoteComputer -ScriptName "AuthTest" -ActionType "ERROR" -Message $fullMessage
                return $false
            }
        }

        function Split-Array {
            param (
                [array]$InputArray,
                [int]$ChunkSize
            )

            $chunks = @()
            for ($i = 0; $i -lt $InputArray.Count; $i += $ChunkSize) {
                $end = [math]::Min($i + $ChunkSize, $InputArray.Count)
                $chunks += ,@($InputArray[$i..($end - 1)])
            }
            return $chunks
        }

        $groupMembershipScript = {
            param (
                [array]$inputArray,
                [string]$targetDomain,
                [string]$remoteComputer,
                [bool]$EnableCrossDomainMemberLookups,
                [bool]$UseFastLDAPLookups,
                [int]$GroupProcessingTimeThresholdSec,
                [int]$MaxGroupRecursionDepth,
                [string]$csvPath,
                [string]$chunkLogPath,
                [bool]$EnableConsoleOutput,
                [bool]$EnableVerboseMode,
                [hashtable] $DomainSidMap
            )

            function Write-ChunkLog {
                param (
                    [string]$DomainName,
                    [string]$RemoteComputer,
                    [string]$ScriptName,
                    [string]$ActionType,
                    [string]$Message,
                    [string]$LogFilePath,
                    [bool]$EnableConsoleOutput,
                    [bool]$EnableVerboseMode
                )

                $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

                # Include debug caller info if verbose
                $callerInfo = ""
                if ($EnableVerboseMode) {
                    $invocation = $MyInvocation
                    $callerInfo = " (from $($invocation.ScriptName):$($invocation.ScriptLineNumber) in $($invocation.MyCommand.Name))"
                }

                $fullMessage = "$Message$callerInfo"
                $logLine = "[$timestamp] [$ActionType] [$DomainName] [$RemoteComputer] [$ScriptName] $fullMessage"

                # Define levels that are always shown
                $alwaysShowLevels = @("ERROR", "SUCCESS")

                $shouldShow = $EnableVerboseMode -or $alwaysShowLevels -contains $ActionType.ToUpper()

                if ($shouldShow) {
                    try {
                        Add-Content -Path $LogFilePath -Value $logLine -ErrorAction Stop
                    } catch {
                        if ($EnableVerboseMode) {
                            Write-Warning "Write-ChunkLog failed to write to log file: $($_.Exception.Message)"
                        }
                    }

                    if ($EnableConsoleOutput -ne $false) {
                        $color = switch ($ActionType.ToUpper()) {
                            "INFO"    { "Cyan" }
                            "SUCCESS" { "Green" }
                            "WARNING" { "Yellow" }
                            "ERROR"   { "Red" }
                            "RUNTIME" { "White" }
                            "NOTIFY"  { "Blue" }
                            default   { "Gray" }
                        }

                        Write-Host $logLine -ForegroundColor $color
                    }
                }

                # Per-domain status logic (always needed regardless of verbosity)
                if (-not $script:domainStatusTable) {
                    $script:domainStatusTable = @{}
                }

                if ($DomainName -and $DomainName -notlike "<*>" -and $DomainName -ne $hostname) {
                    $statusPriority = @{ "SUCCESS" = 1; "WARNING" = 2; "ERROR" = 3 }

                    $current = if ($script:domainStatusTable.ContainsKey($DomainName)) {
                        $script:domainStatusTable[$DomainName]
                    } else {
                        "SUCCESS"
                    }

                    $defaultPriority = 0
                    $currentPriority = if ($statusPriority.ContainsKey($current)) { $statusPriority[$current] } else { $defaultPriority }

                    if ($statusPriority.ContainsKey($ActionType.ToUpper()) -and
                        $statusPriority[$ActionType.ToUpper()] -gt $currentPriority) {
                        $script:domainStatusTable[$DomainName] = $ActionType.ToUpper()
                    }
                }
            }

            Import-Module ActiveDirectory
            $forestRoot = (Get-ADForest).RootDomain
            $resolvedMembers = @{}
            $groupFailures = New-Object System.Collections.Generic.List[Object]

            if ($inputArray.Count -eq 1 -and $inputArray[0] -is [string]) {
                Write-ChunkLog "<Debug>" "" "GroupMembershipScriptBlock" "ERROR" "inputArray is a single string: $($inputArray[0])" $chunkLogPath $EnableConsoleOutput $EnableVerboseMode
                throw "inputArray contains a string instead of group objects. Check argument wrapping with ,\$domainGroupEntries"
            }

            function Split-Array {
                param (
                    [array]$InputArray,
                    [int]$ChunkSize
                )

                $chunks = @()
                for ($i = 0; $i -lt $InputArray.Count; $i += $ChunkSize) {
                    $end = [math]::Min($i + $ChunkSize, $InputArray.Count)
                    $chunks += ,@($InputArray[$i..($end - 1)])
                }
                return $chunks
            }
            function Get-DomainFromDN {
                param ($dn)
                if ($dn -match "DC=") {
                    return ($dn -split "," | Where-Object { $_ -like "DC=*" } | ForEach-Object { $_ -replace "DC=", "" }) -join "."
                }
            }

            function Normalize-Domain {
                param ($domainName)
                if ($null -eq $domainName) { return $null }
                return $domainName.ToLower().Trim()
            }

            function Convert-ToSchemaCompliantObject {
                param (
                    [Parameter(Mandatory = $false)]
                    [psobject]$InputObject,

                    [Parameter()]
                    [hashtable]$AdditionalProperties = @{},
                    
                    [switch]$SchemaOnly
                )

                function BlankString { return '' }

                function Get-PropValue {
                    param (
                        [psobject]$obj,
                        [string]$propName
                    )
                    if ($SchemaOnly) { return BlankString }
                    if ($null -ne $obj -and $obj.PSObject.Properties[$propName]) {
                        return $obj.$propName
                    }
                    return BlankString
                }

                $value = if ($SchemaOnly) { '' } else { Get-PropValue $InputObject 'ObjectClass' }
                $objectClassString = if ($value -is [array]) { $value -join ',' } else { "$value" }

                $distinguishedName = if ($SchemaOnly) { '' } else { Get-PropValue $InputObject 'DistinguishedName' }

                $inferredUserDomain = ''
                if (-not $SchemaOnly -and $distinguishedName -is [string] -and $distinguishedName -match 'DC=') {
                    $inferredUserDomain = ($distinguishedName -split ',' | Where-Object { $_ -like 'DC=*' }) -replace '^DC=', '' -join '.'
                }

                $output = [ordered]@{
                    CanonicalName                   = Get-PropValue $InputObject 'CanonicalName'
                    CN                              = Get-PropValue $InputObject 'CN'
                    Created                         = Get-PropValue $InputObject 'Created'
                    createTimeStamp                 = Get-PropValue $InputObject 'createTimeStamp'
                    Deleted                         = Get-PropValue $InputObject 'Deleted'
                    Description                     = Get-PropValue $InputObject 'Description'
                    DisplayName                     = Get-PropValue $InputObject 'DisplayName'
                    DistinguishedName               = Get-PropValue $InputObject 'DistinguishedName'
                    Domain                          = Get-PropValue $InputObject 'Domain'
                    GroupCategory                   = Get-PropValue $InputObject 'GroupCategory'
                    GroupName                       = Get-PropValue $InputObject 'GroupName'
                    GroupScope                      = Get-PropValue $InputObject 'GroupScope'
                    groupType                       = Get-PropValue $InputObject 'groupType'
                    HomePage                        = Get-PropValue $InputObject 'HomePage'
                    instanceType                    = Get-PropValue $InputObject 'instanceType'
                    isCriticalSystemObject          = Get-PropValue $InputObject 'isCriticalSystemObject'
                    isDeleted                       = Get-PropValue $InputObject 'isDeleted'
                    LastKnownParent                 = Get-PropValue $InputObject 'LastKnownParent'
                    ManagedBy                       = Get-PropValue $InputObject 'ManagedBy'
                    MemberOf                        = Get-PropValue $InputObject 'MemberOf'
                    Members                         = Get-PropValue $InputObject 'Members'
                    Modified                        = Get-PropValue $InputObject 'Modified'
                    modifyTimeStamp                 = Get-PropValue $InputObject 'modifyTimeStamp'
                    Name                            = Get-PropValue $InputObject 'Name'
                    ObjectCategory                  = Get-PropValue $InputObject 'ObjectCategory'
                    ObjectClass                     = $objectClassString
                    ObjectGUID                      = Get-PropValue $InputObject 'ObjectGUID'
                    objectSid                       = Get-PropValue $InputObject 'objectSid'
                    ProtectedFromAccidentalDeletion = Get-PropValue $InputObject 'ProtectedFromAccidentalDeletion'
                    SamAccountName                  = Get-PropValue $InputObject 'SamAccountName'
                    sAMAccountType                  = Get-PropValue $InputObject 'sAMAccountType'
                    sDRightsEffective               = Get-PropValue $InputObject 'sDRightsEffective'
                    SID                             = Get-PropValue $InputObject 'SID'
                    whenChanged                     = Get-PropValue $InputObject 'whenChanged'
                    whenCreated                     = Get-PropValue $InputObject 'whenCreated'

                    # Always included summary/reporting fields
                    UserDomain                      = Get-PropValue $InputObject 'UserDomain'
                    GroupDomain                     = Get-PropValue $InputObject 'GroupDomain'
                    NestedTrail                     = Get-PropValue $InputObject 'NestedTrail'
                }


                foreach ($key in $AdditionalProperties.Keys) {
                    $output[$key] = $AdditionalProperties[$key]
                }

                if (-not ($output.Keys -contains 'UserDomain') -or [string]::IsNullOrWhiteSpace($output['UserDomain'])) {
                    $output['UserDomain'] = $inferredUserDomain
                }

                return [pscustomobject]$output
            }

            function Recurse-Members {
                param (
                    [object]$GroupObject,
                    [string]$Trail,
                    [string]$GroupDomain,
                    [string]$GroupName,
                    [string]$DomainController,
                    [int]$Depth,
                    [bool]$UseFastLDAPLookups,
                    [int]$GroupProcessingTimeThresholdSec,
                    [int]$MaxGroupRecursionDepth,
                    [bool]$EnableCrossDomainMemberLookups,
                    [bool]$EnableConsoleOutput,
                    [bool]$EnableVerboseMode,
                    [string]$chunkLogPath,
                    [hashtable] $DomainSidMap
                )

                # Declare local results object
                $localResults = New-Object System.Collections.Generic.List[Object]

                # Hard coding $MaxGroupRecursionDepth
                $MaxGroupRecursionDepth = 10

                $delimiter = "|"
                $trailDN = "$delimiter$($GroupObject.DistinguishedName)$delimiter"
                if ($Trail -like "*$trailDN*")  {
                    Write-ChunkLog $GroupDomain $DomainController $reportName "WARNING" "Detected circular reference: $Trail -> $($GroupObject.DistinguishedName)" $chunkLogPath $EnableConsoleOutput $EnableVerboseMode
                    return (New-Object System.Collections.Generic.List[object])
                }

                Write-ChunkLog $GroupDomain $remoteComputer $reportName "INFO" "Recurse-Members called for '$GroupName' at depth $Depth" $chunkLogPath $EnableConsoleOutput $EnableVerboseMode
                Write-ChunkLog $GroupDomain $remoteComputer $reportName "DEBUG" "Group '$GroupName' has $($GroupObject.Member.Count) members" $chunkLogPath $EnableConsoleOutput $EnableVerboseMode
                Write-ChunkLog $GroupDomain $remoteComputer $reportName "DEBUG" "IN: Depth=$Depth Max=$MaxGroupRecursionDepth" $chunkLogPath $EnableConsoleOutput $EnableVerboseMode

                if ($Depth -gt $script:maxDepthSeen) {
                    $script:maxDepthSeen = $Depth
                }

                if ($Depth -ge $MaxGroupRecursionDepth) {
                    $script:maxDepthSeen = [Math]::Max($script:maxDepthSeen, $Depth)
                    Write-ChunkLog $GroupDomain $remoteComputer $reportName "WARNING" "Max recursion depth $MaxGroupRecursionDepth hit for group '$($GroupObject.DistinguishedName)' — recursion halted." $chunkLogPath $EnableConsoleOutput $EnableVerboseMode
                    return $localResults
                }

                if (-not $GroupObject.DistinguishedName) {
                    Write-ChunkLog $GroupDomain $remoteComputer $reportName "WARNING" "Skipping group with emtpy DN, $GroupName" $chunkLogPath $EnableConsoleOutput $EnableVerboseMode
                    return $localResults
                }

                # Resolve members once per group
                $memberDNs = @()

                if ($UseFastLDAPLookups -and $GroupObject.DistinguishedName) {
                    try {
                        $ldapPath = "LDAP://$remoteComputer/$($GroupObject.DistinguishedName)"
                        $entry = New-Object System.DirectoryServices.DirectoryEntry($ldapPath)
                        $ds = New-Object System.DirectoryServices.DirectorySearcher($entry)
                        $ds.Filter = "(objectClass=group)"
                        $ds.SearchScope = [System.DirectoryServices.SearchScope]::Base
                        $ds.PropertiesToLoad.Add("member")
                        $ds.PageSize = 1000
                        $result = $ds.FindOne()
                        if ($result -and $result.Properties["member"]) {
                            $memberDNs = $result.Properties["member"]
                            Write-ChunkLog $GroupDomain $remoteComputer $reportName "INFO" "Resolved $($memberDNs.Count) members via LDAP for group '$GroupName'" $chunkLogPath $EnableConsoleOutput $EnableVerboseMode
                        } else {
                            Write-ChunkLog $targetDomain $remoteComputer $reportName "WARNING" "LDAP query returned no members for $GroupName" $chunkLogPath $EnableConsoleOutput $EnableVerboseMode
                        }
                    } catch {
                        Write-ChunkLog $targetDomain $remoteComputer $reportName "WARNING" "LDAP query failed for $GroupName ($($GroupObject.DistinguishedName)): $($_.Exception.Message)" $chunkLogPath $EnableConsoleOutput $EnableVerboseMode
                        $memberDNs = $GroupObject.Member  # fallback
                    }
                } else {
                    if (-not $GroupObject.PSObject.Properties["Member"]) {
                        try {
                            $GroupObject = Get-ADGroup -Server $remoteComputer -Identity $GroupObject.DistinguishedName -Properties *
                        } catch {
                            Write-ChunkLog $targetDomain $remoteComputer $reportName "WARNING" "Fallback member fetch failed for $($GroupObject.DistinguishedName): $($_.Exception.Message)" $chunkLogPath $EnableConsoleOutput $EnableVerboseMode
                        }
                    }
                    $memberDNs = $GroupObject.Member
                }

                # Iterate once over resolved members
                foreach ($memberDN in $memberDNs) {
                    $memberDomain = Normalize-Domain (Get-DomainFromDN -dn $memberDN)
                    $normalizedTarget = $targetDomain.ToLower()
                    $member = $null

                    Write-ChunkLog $GroupDomain $remoteComputer $reportName "INFO" "Attempting to resolve memberDN: $memberDN" $chunkLogPath $EnableConsoleOutput $EnableVerboseMode

                    if ($resolvedMembers.Keys -contains $memberDN) {
                        $member = $resolvedMembers[$memberDN]
                    } elseif ($memberDomain -eq $normalizedTarget) {
                        try {
                            try {
                                $objectClass = $null

                                # Fast object class probe
                                $meta = Get-ADObject -Identity $memberDN -Server $remoteComputer -Properties objectClass -ErrorAction Stop
                                $objectClass = $meta.ObjectClass

                                switch ($objectClass) {
                                    'user' {
                                        $member = Get-ADUser -Server $remoteComputer -Identity $memberDN -Properties *
                                    }
                                    'group' {
                                        $member = Get-ADGroup -Server $remoteComputer -Identity $memberDN -Properties *
                                    }
                                    default {
                                        # fallback or keep original Get-ADObject
                                        $member = Get-ADObject -Server $remoteComputer -Identity $memberDN -Properties *
                                    }
                                }
                            } catch {
                                Write-ChunkLog $domainName $remoteComputer $reportName "ERROR" "Failed to resolve member '$memberDN': $_"
                                continue
                            }

                            if ($member) { $resolvedMembers[$memberDN] = $member }
                            Write-ChunkLog $targetDomain $remoteComputer $reportName "INFO" "Fetched member: $($member.SamAccountName) from $memberDomain" $chunkLogPath $EnableConsoleOutput $EnableVerboseMode
                        } catch {
                            Write-ChunkLog $targetDomain $remoteComputer $reportName "WARNING" "Failed to get member '$memberDN': $($_.Exception.Message)" $chunkLogPath $EnableConsoleOutput $EnableVerboseMode

                            $fallbackName = ($memberDN -split ",")[0] -replace "^CN=", ""

                            $obj = Convert-ToSchemaCompliantObject -InputObject ([pscustomobject]@{ DistinguishedName = $memberDN }) -AdditionalProperties @{
                                Forest        = $forestRoot
                                GroupDomain   = $GroupDomain
                                GroupName     = $GroupName
                                Name          = $fallbackName
                                UserDomain    = ''
                                NestedTrail   = ''
                            }
                            # Only add if at least one property is not null or empty
                            if ($obj.PSObject.Properties.Value | Where-Object { $_ -ne $null -and "$_".Trim() -ne "" }) {
                                $localResults.Add($obj)
                                Write-ChunkLog $GroupDomain $remoteComputer $reportName "WARNING" "Added unresolved member fallback: $fallbackName" $chunkLogPath $EnableConsoleOutput $EnableVerboseMode
                            } else {
                                Write-ChunkLog $GroupDomain $remoteComputer $reportName "WARNING" "Skipped unresolved member fallback: all values blank for $fallbackName" $chunkLogPath $EnableConsoleOutput $EnableVerboseMode
                            }
                        }
                    } elseif ($EnableCrossDomainMemberLookups) {
                        $foreignDC = $null
                        try {
                            if (-not $memberDomain -or $memberDomain -isnot [string]) {
                            Write-ChunkLog $targetDomain $remoteComputer "GroupMembership-Block" "ERROR" "Invalid memberDomain passed to Get-ADDomainController: '$($memberDomain | Out-String)'" $chunkLogPath $EnableConsoleOutput $EnableVerboseMode
                            return
                        }
                            $foreignDCInfo = Get-ADDomainController -Discover -DomainName $memberDomain -Service PrimaryDC -ErrorAction Stop
                            $foreignDC = $foreignDCInfo.DNSHostName
                            Write-ChunkLog $targetDomain $remoteComputer $reportName "INFO" "Discovered foreign DC for ${memberDomain}: $foreignDC" $chunkLogPath $EnableConsoleOutput $EnableVerboseMode
                        } catch {
                            Write-ChunkLog $targetDomain $remoteComputer $reportName "WARNING" "Could not resolve DC for ${memberDomain}: $($_.Exception.Message)" $chunkLogPath $EnableConsoleOutput $EnableVerboseMode
                            continue
                        }

                        if ($foreignDC) {
                            try {
                                $member = Get-ADObject -Server $foreignDC -Identity $memberDN -Properties objectClass, samAccountName, name, distinguishedName
                                Write-ChunkLog $targetDomain $remoteComputer $reportName "INFO" "Fetched foreign member: $($member.SamAccountName) from $memberDomain" $chunkLogPath $EnableConsoleOutput $EnableVerboseMode
                            } catch {
                                Write-ChunkLog $targetDomain $remoteComputer $reportName "WARNING" "Failed remote fetch for $memberDN from ${foreignDC}: $($_.Exception.Message)" $chunkLogPath $EnableConsoleOutput $EnableVerboseMode
                                continue
                            }
                        }
                    } else {
                        Write-ChunkLog $targetDomain $remoteComputer $reportName "INFO" "Skipping cross-domain lookup for $memberDN (domain=$memberDomain) — feature disabled" $chunkLogPath $EnableConsoleOutput $EnableVerboseMode
                        continue
                    }

                    if ($null -eq $member) { continue }
                    if ($member.objectClass -contains 'user' -or $member.objectClass -contains 'computer') {
                    if (
                        $member.DistinguishedName -or
                        $member.Name -or
                        $member.SamAccountName -or
                        $member.ObjectGUID -or
                        $member.SID -or
                        $GroupName -or
                        $GroupDomain
                    ) {
                        $localResults.Add( 
                            (Convert-ToSchemaCompliantObject -InputObject $member -AdditionalProperties @{
                                Forest       = $forestRoot
                                GroupDomain  = $GroupDomain
                                GroupName    = $GroupName
                                NestedTrail  = $Trail
                                UserDomain   = $GroupDomain
                            })
                        )
                    }
                    Write-ChunkLog $memberDomain $remoteComputer $reportName "DEBUG" "Creating localResults PSObject, $GroupDomain, $GroupName, $memberDomain, ${member.SamAccountName}, $Trail" $chunkLogPath $EnableConsoleOutput $EnableVerboseMode

                } elseif ($member.objectClass -contains 'group') {
                            $memberRef = $null
                            $member = $memberRef

                            if ([string]::IsNullOrWhiteSpace($key)) {
                                Write-ChunkLog $GroupDomain $remoteComputer $reportName "WARNING" "Resolved key was null — skipping $($member.DistinguishedName)" $chunkLogPath $EnableConsoleOutput $EnableVerboseMode
                                continue
                            }

                            if ($member.SID -and $member.SID.Value -like "S-1-5-32-*") {
                                Write-ChunkLog $GroupDomain $remoteComputer $reportName "INFO" "Skipping built-in group (SID=$($member.SID.Value))" $chunkLogPath $EnableConsoleOutput $EnableVerboseMode
                                continue
                            }

                            if (-not $member.PSObject.Properties["Member"]) {
                                try {
                                    $member = Get-ADGroup -Server $remoteComputer -Identity $member.DistinguishedName -Properties *
                                } catch {
                                    Write-ChunkLog $GroupDomain $remoteComputer $reportName "WARNING" "Nested group refresh failed: $($_.Exception.Message)" $chunkLogPath $EnableConsoleOutput $EnableVerboseMode
                                    continue
                                }
                            }

                            $nextTrail = if ($Trail) { "$Trail > $($member.Name)@$memberDomain" } else { "$($member.Name)@$memberDomain" }

                            try {
                                $childResults = Recurse-Members -GroupObject $member `
                                                                -Trail $nextTrail `
                                                                -GroupDomain $GroupDomain `
                                                                -GroupName "$GroupName" `
                                                                -DomainController $remoteComputer `
                                                                -Depth ($Depth + 1) `
                                                                -UseFastLDAPLookups $UseFastLDAPLookups `
                                                                -GroupProcessingTimeThresholdSec $GroupProcessingTimeThresholdSec `
                                                                -MaxGroupRecursionDepth $MaxGroupRecursionDepth `
                                                                -EnableCrossDomainMemberLookups $EnableCrossDomainMemberLookups `
                                                                -EnableConsoleOutput $EnableConsoleOutput `
                                                                -EnableVerboseMode $EnableVerboseMode `
                                                                -chunkLogPath $chunkLogPath `
                                                                -DomainSidMap $DomainSidMap

                                Write-ChunkLog $GroupDomain $DomainController $reportName "DEBUG" "childResults is $($childResults.GetType().FullName)" $chunkLogPath $EnableConsoleOutput $EnableVerboseMode

                                $childResults = $childResults | Where-Object {$_ -is [psobject] -and $_.PSObject.Properties.Count -gt 0}

                                if ($null -eq $childResults -or $childResults -isnot [System.Collections.IEnumerable]) {
                                    Write-ChunkLog $GroupDomain $DomainController $reportName "ERROR" "childResults is invalid: $($childResults.GetType().FullName)" $chunkLogPath $EnableConsoleOutput $EnableVerboseMode
                                    continue
                                }

                                foreach ($r in $childResults) {
                                    if ($r -is [int]) {
                                        Write-ChunkLog $GroupDomain $remoteComputer $reportName "ERROR" "Integer found in results: $r — skipping" $chunkLogPath $EnableConsoleOutput $EnableVerboseMode
                                        continue
                                    }
                                    if ($r -isnot [psobject]) {
                                        Write-ChunkLog $GroupDomain $remoteComputer $reportName "ERROR" "Unexpected object type: $($r.GetType().FullName)" $chunkLogPath $EnableConsoleOutput $EnableVerboseMode
                                        continue
                                    }
                                    Write-ChunkLog $targetDomain $remoteComputer $reportName "DEBUG" "Adding $r ($($r.GetType().FullName)) to localResults object" $chunkLogPath $EnableConsoleOutput $EnableVerboseMode
                                    $localResults.Add($r)
                                }
                            } catch {
                                Write-ChunkLog $GroupDomain $remoteComputer $reportName "ERROR" "Recursion failed for nested group: $($_.Exception.Message)" $chunkLogPath $EnableConsoleOutput $EnableVerboseMode
                                # Attempt to resolve foreign domain via SID
                                $foreignDomain = $null
                                if ($member -and $member.SID -and $member.SID.Value) {
                                    $sidParts = $member.SID.Value -split '-'
                                    if ($sidParts.Count -gt 3) {
                                        $domainSid = ($sidParts[0..($sidParts.Length - 2)] -join '-')

                                        if ($DomainSidMap.Keys -contains $domainSid) {
                                            $foreignDomain = $DomainSidMap[$domainSid]
                                        }
                                    }
                                }                                                                    
                                if ($foreignDomain) {
                                    if (
                                        $member.DistinguishedName -or
                                        $member.Name -or
                                        $GroupName -or
                                        $member.SamAccountName -or
                                        $member.SID.Value -or
                                        $Trail
                                    ) {
                                        $localResults.Add(
                                            (Convert-ToSchemaCompliantObject -InputObject $member -AdditionalProperties @{
                                                Forest         = $forestRoot
                                                GroupDomain    = $foreignDomain
                                                GroupName      = $GroupName
                                                Name           = $member.Name
                                                ObjectClass    = 'group'
                                                GroupScope     = 'Unknown (Foreign)'
                                                GroupCategory  = 'Security'
                                                SamAccountName = $member.SamAccountName
                                                SID            = $member.SID.Value
                                                NestedTrail    = $Trail
                                                UserDomain     = $foreignDomain
                                            })
                                        )

                                        Write-ChunkLog $GroupDomain $remoteComputer $reportName "INFO" "Added placeholder for foreign group '$GroupName' from SID $($member.SID.Value)" $chunkLogPath $EnableConsoleOutput $EnableVerboseMode
                                    } else {
                                        # Log unresolved group normally
                                        $groupFailures.Add([PSCustomObject]@{
                                            GroupName = $GroupName
                                            Domain    = $GroupDomain
                                            Server    = $remoteComputer
                                            SID       = $member.SID.value
                                            Error     = $_.Exception.Message                                    
                                        })
                                    }
                                }
                            }
                        } elseif ($member.objectClass -contains 'foreignSecurityPrincipal') {
                            # Create a schema-compliant object for foreignSecurityPrincipal objects in AD
                            if (
                                $member.DistinguishedName -or
                                $member.Name -or
                                $member.SamAccountName -or
                                $entry.GroupName -or
                                $entry.GroupDomain
                            ) {
                                $localResults.Add(
                                    (Convert-ToSchemaCompliantObject -InputObject $member -AdditionalProperties @{
                                        Forest         = $forestRoot
                                        GroupDomain    = $entry.GroupDomain
                                        GroupName      = $entry.GroupName
                                        GroupScope     = $entry.GroupScope
                                        GroupCategory  = $entry.GroupCategory
                                        NestedTrail    = $Trail
                                        UserDomain     = $entry.GroupDomain
                                    })
                                )

                                Write-ChunkLog $entry.GroupDomain $remoteComputer $reportName "INFO" "Added standardized foreignSecurityPrincipal: $($member.DistinguishedName)" $chunkLogPath $EnableConsoleOutput $EnableVerboseMode
                            } else {
                                # Log unresolved group normally
                                $groupFailures.Add([PSCustomObject]@{
                                    GroupName = $GroupName
                                    Domain    = $GroupDomain
                                    Server    = $remoteComputer
                                    SID       = $member.SID.value
                                    Error     = $_.Exception.Message                                    
                                })
                            }
                            continue
                        }  elseif ($member.objectClass -contains 'msDS-ManagedServiceAccount') {
                                if (
                                    $member.DistinguishedName -or
                                    $member.Name -or
                                    $member.SamAccountName -or
                                    $member.SID -or
                                    $GroupName -or
                                    $GroupDomain
                                ) {
                                    $localResults.Add(
                                        (Convert-ToSchemaCompliantObject -InputObject $member -AdditionalProperties @{
                                            Forest         = $forestRoot
                                            GroupDomain    = $GroupDomain
                                            GroupName      = $GroupName
                                            NestedTrail    = $Trail
                                            UserDomain     = $GroupDomain
                                        })
                                    )

                                    Write-ChunkLog $GroupDomain $remoteComputer $reportName "INFO" "Handled Managed Service Account: $($member.SamAccountName)" $chunkLogPath $EnableConsoleOutput $EnableVerboseMode
                                } else {
                                    # Log unresolved group normally
                                    $groupFailures.Add([PSCustomObject]@{
                                        GroupName = $GroupName
                                        Domain    = $GroupDomain
                                        Server    = $remoteComputer
                                        SID       = $member.SID.value
                                        Error     = $_.Exception.Message                                    
                                    })
                                }

                                
                                continue
                            } else {
                            Write-ChunkLog $GroupDomain $remoteComputer $reportName "WARNING" "Unhandled objectClass: $($member.objectClass -join ', ') for $($member.DistinguishedName)" $chunkLogPath $EnableConsoleOutput $EnableVerboseMode
                            continue
                        }
                    }
                    if ($null -eq $localResults -or $localResults -isnot [System.Collections.IEnumerable]) {
                        Write-ChunkLog $GroupDomain $DomainController $reportName "ERROR" "Recurse-Members return corrupted: $($localResults.GetType().FullName)" $chunkLogPath $EnableConsoleOutput $EnableVerboseMode
                        return (New-Object System.Collections.Generic.List[object])
                    }
                return $localResults
            }

            Write-ChunkLog $domainName $remoteComputer $reportName "DEBUG" "Starting group membership job for chunk with $($chunk.Count) groups" $chunkLogPath $EnableConsoleOutput $EnableVerboseMode

            # Clear maximum recursion depth
            $script:maxDepthSeen = 0

            # Sanity check
            if ($null -eq $inputArray -or $inputArray.Count -eq 0) {
                Write-ChunkLog $targetDomain $remoteComputer $reportName "WARNING" "Input array was null or empty. Skipping execution." $chunkLogPath $EnableConsoleOutput $EnableVerboseMode
                return (New-Object System.Collections.Generic.List[object])
            }

            $Depth = 0
            $trail = ""

            # One shared result collection for the entire chunk
            $localResults = New-Object System.Collections.Generic.List[Object]
            $hasExportedAnyResults = $false

            foreach ($entry in $inputArray) {
                try {
                    $groupName = $entry.GroupName
                    $dn = $entry.DistinguishedName


                    # Rehydrate if not a proper ADGroup
                    if ($entry -isnot [Microsoft.ActiveDirectory.Management.ADGroup]) {
                        try {
                            $entry = Get-ADGroup -Server $remoteComputer -Identity $dn -Properties *
                            Write-ChunkLog $targetDomain $remoteComputer $reportName "INFO" "Refreshed group '$groupName' into real ADGroup object" $chunkLogPath $EnableConsoleOutput $EnableVerboseMode
                        } catch {
                            Write-ChunkLog $targetDomain $remoteComputer $reportName "WARNING" "Failed to convert '$groupName' to ADGroup: $($_.Exception.Message)" $chunkLogPath $EnableConsoleOutput $EnableVerboseMode
                            continue
                        }
                    }

                    # Refresh if Member property missing or empty
                    if (-not $entry.PSObject.Properties["Member"] -or -not $entry.Member -or $entry.Member.Count -eq 0) {
                        try {
                            $refreshed = Get-ADGroup -Server $remoteComputer -Identity $entry.DistinguishedName -Properties *
                            $entry = [Microsoft.ActiveDirectory.Management.ADGroup]$refreshed
                            Write-ChunkLog $targetDomain $remoteComputer $reportName "INFO" "Refreshed member list for group '$($entry.Name)'" $chunkLogPath $EnableConsoleOutput $EnableVerboseMode
                        } catch {
                            Write-ChunkLog $targetDomain $remoteComputer $reportName "WARNING" "Failed to refresh members for group '$($entry.Name)': $($_.Exception.Message)" $chunkLogPath $EnableConsoleOutput $EnableVerboseMode
                        }
                    }

                    # Ensure DistinguishedName is present
                    $dn = $entry.DistinguishedName
                    if (-not $dn) {
                        Write-ChunkLog $targetDomain $remoteComputer $reportName "WARNING" "Entry missing DistinguishedName — skipping" $chunkLogPath $EnableConsoleOutput $EnableVerboseMode
                        continue
                    }

                    # Fallback GroupName if missing
                    if (-not $entry.PSObject.Properties["GroupName"] -or [string]::IsNullOrWhiteSpace($entry.GroupName)) {
                        try {
                            if (-not $groupName) {
                                $groupName = ($dn -split ",")[0] -replace "^CN=", ""
                            }
                            $entry | Add-Member -NotePropertyName "GroupName" -NotePropertyValue $groupName -Force
                            Write-ChunkLog $targetDomain $remoteComputer $reportName "DEBUG" "Set missing GroupName to '$groupName'" $chunkLogPath $EnableConsoleOutput $EnableVerboseMode
                        } catch {
                            Write-ChunkLog $targetDomain $remoteComputer $reportName "WARNING" "Could not extract GroupName from DN: $dn" $chunkLogPath $EnableConsoleOutput $EnableVerboseMode
                            continue
                        }
                    }

                    # Fallback GroupDomain if missing
                    if (-not ($entry -and $entry.PSObject.Properties["GroupDomain"] -and -not [string]::IsNullOrWhiteSpace($entry.GroupDomain))) {
                        try {
                            $groupDomain = Normalize-Domain (Get-DomainFromDN -dn $dn)
                            $entry | Add-Member -NotePropertyName "GroupDomain" -NotePropertyValue $groupDomain -Force
                            Write-ChunkLog $targetDomain $remoteComputer $reportName "DEBUG" "Set missing GroupDomain to '$groupDomain'" $chunkLogPath $EnableConsoleOutput $EnableVerboseMode
                        } catch {
                            Write-ChunkLog $targetDomain $remoteComputer $reportName "WARNING" "Could not extract GroupDomain from DN: $dn" $chunkLogPath $EnableConsoleOutput $EnableVerboseMode
                            continue
                        }
                    }

                    # Parse members
                    $memberArray = switch ($entry.Member) {
                        $null { @() }
                        { $_ -is [string] } { @($_) }
                        { $_ -is [array] } { $_ }
                        default { @($_.ToString()) }
                    }

                    Write-ChunkLog $targetDomain $remoteComputer $reportName "DEBUG" "Group '$groupName' member count after refresh: $($memberArray.Count)" $chunkLogPath $EnableConsoleOutput $EnableVerboseMode

                    foreach ($memberDN in $memberArray) {
                        $memberDomain = Normalize-Domain (Get-DomainFromDN -dn $memberDN)
                        $normalizedTarget = $targetDomain.ToLower()
                        if ($null -eq $nextTrail) {
                            $nextTrail = if ($trail) { "$trail > $($member.Name)@$memberDomain" } else { "$($member.Name)@$memberDomain" }
                        }
                        $member = $null

                        Write-ChunkLog $targetDomain $remoteComputer $reportName "INFO" "Attempting to resolve memberDN: $memberDN" $chunkLogPath $EnableConsoleOutput $EnableVerboseMode

                        if ($resolvedMembers.Keys -contains $memberDN) {
                            $member = $resolvedMembers[$memberDN]
                        } elseif ($memberDomain -eq $normalizedTarget) {
                            try {
                                $member = Get-ADObject -Server $remoteComputer -Identity $memberDN -Properties objectClass, samAccountName, name, distinguishedName
                                if ($member) {
                                    $resolvedMembers[$memberDN] = $member
                                    Write-ChunkLog $targetDomain $remoteComputer $reportName "INFO" "Fetched member: $($member.SamAccountName) from $memberDomain" $chunkLogPath $EnableConsoleOutput $EnableVerboseMode
                                }
                            } catch {
                                Write-ChunkLog $targetDomain $remoteComputer $reportName "WARNING" "Failed to get member '$memberDN': $($_.Exception.Message)" $chunkLogPath $EnableConsoleOutput $EnableVerboseMode
                            }
                        }

                        if ($member -and ($member.ObjectClass -eq 'group' -or $member.objectClass -eq 'group')) {
                            $resultsFromRecursion = Recurse-Members `
                                -GroupObject $member `
                                -Trail $nextTrail `
                                -GroupDomain $memberDomain `
                                -GroupName $member.Name `
                                -DomainController $remoteComputer `
                                -Depth ($Depth + 1) `
                                -UseFastLDAPLookups $UseFastLDAPLookups `
                                -GroupProcessingTimeThresholdSec $GroupProcessingTimeThresholdSec `
                                -MaxGroupRecursionDepth $MaxGroupRecursionDepth `
                                -EnableCrossDomainMemberLookups $EnableCrossDomainMemberLookups `
                                -EnableConsoleOutput $EnableConsoleOutput `
                                -EnableVerboseMode $EnableVerboseMode `
                                -chunkLogPath $chunkLogPath `
                                -DomainSidMap $DomainSidMap

                            if ($resultsFromRecursion -is [System.Collections.IEnumerable]) {
                                $localResults.AddRange($resultsFromRecursion)
                                $hasExportedAnyResults = $true
                            }
                        } elseif ($member) {
                            $NestedTrail = if ($Trail) { $Trail } else { "<TopLevel>" }
                            $leafObject = Convert-ToSchemaCompliantObject -InputObject $member -AdditionalProperties @{
                                Forest        = "$forestRoot"
                                GroupDomain   = "$($entry.GroupDomain)"
                                GroupName     = "$($entry.GroupName)"
                                GroupScope    = "$($entry.GroupScope)"
                                GroupCategory = "$($entry.GroupCategory)"
                                NestedTrail   = "$NestedTrail"
                                UserDomain    = ($member.DistinguishedName -split ',' | Where-Object { $_ -like 'DC=*' }) -join '.'
                            }

                            $localResults.Add($leafObject)
                            $hasExportedAnyResults = $true
                        }
                    }
                } catch {
                    Write-ChunkLog $targetDomain $remoteComputer $reportName "ERROR" "Unexpected failure while processing group '$groupName': $($_.Exception.Message)" $chunkLogPath $EnableConsoleOutput $EnableVerboseMode
                    $groupFailures.Add([PSCustomObject]@{
                        GroupName = $GroupName
                        Domain    = $GroupDomain
                        Server    = $remoteComputer
                        SID       = $member.SID.value
                        Error     = $_.Exception.Message                                    
                    })
                }
            }

            # Export once at end
            if ($localResults -and $localResults.Count -gt 0) {
                # Ensure consistent CSV schema by inserting a schema primer
                if ($localResults.Count -eq 0) {
                    Write-ChunkLog $targetDomain $remoteComputer "Inserting CSV schema primer to force consistent headers" $chunkLogPath $EnableConsoleOutput $EnableVerboseMode
                    $localResults.Add((Convert-ToSchemaCompliantObject -SchemaOnly))
                }

                # Filter nulls and blank entries first
                $validResults = $localResults | Where-Object {
                    $_ -and ($_.PSObject.Properties.Value | Where-Object { $_ -ne $null -and $_ -ne "" }).Count -gt 0
                }

                foreach ($r in $validResults) {
                    $propCount = $r.PSObject.Properties.Count
                    Write-ChunkLog $targetDomain $remoteComputer $reportName "DEBUG" "Result object with $propCount properties: $($r | Format-List | Out-String)" $chunkLogPath $EnableConsoleOutput $EnableVerboseMode
                }

                try {
                    if ($validResults.Count -gt 0) {
                        Write-ChunkLog $targetDomain $remoteComputer $reportName "DEBUG" "Sample output: $($validResults[0] | Format-List | Out-String)" $chunkLogPath $EnableConsoleOutput $EnableVerboseMode
                        $validResults | Export-Csv -Path $csvPath -Encoding UTF8 -NoTypeInformation -Force
                        Write-ChunkLog $targetDomain $remoteComputer $reportName "SUCCESS" "Exported $($validResults.Count) members for group chunk to $csvPath" $chunkLogPath $EnableConsoleOutput $EnableVerboseMode
                        $hasExportedAnyResults = $true
                    } else {
                        Write-ChunkLog $targetDomain $remoteComputer $reportName "WARNING" "No valid objects to export for this group chunk" $chunkLogPath $EnableConsoleOutput $EnableVerboseMode
                    }
                } catch {
                    Write-ChunkLog $targetDomain $remoteComputer $reportName "ERROR" "Unable to export for this group chunk! Error: $_" $chunkLogPath $EnableConsoleOutput $EnableVerboseMode
                }
            }

            if (-not $hasExportedAnyResults) {
                Write-ChunkLog $targetDomain $remoteComputer $reportName "INFO" "No members were resolved from input chunk — no output file generated" $chunkLogPath $EnableConsoleOutput $EnableVerboseMode
                Write-ChunkLog $targetDomain $remoteComputer $reportName "INFO" "Creating group only entry." $chunkLogPath $EnableConsoleOutput $EnableVerboseMode
                try {
                    $groupObject = Convert-ToSchemaCompliantObject -InputObject $entry -AdditionalProperties @{
                        Forest        = $forestRoot
                        ObjectClass   = 'group'
                        GroupName     = $entry.GroupName
                        GroupDomain   = $entry.GroupDomain
                        GroupScope    = $entry.GroupScope
                        GroupCategory = $entry.GroupCategory
                        NestedTrail   = '<EmptyGroup>'
                        UserDomain    = ($entry.DistinguishedName -split ',' | Where-Object { $_ -like 'DC=*' }) -replace '^DC=', '' -join '.'
                    }

                    $localResults.Add($groupObject)
                    Write-ChunkLog $targetDomain $remoteComputer $reportName "INFO" "Created group only entry successfully for $($entry.DistinguishedName)." $chunkLogPath $EnableConsoleOutput $EnableVerboseMode
                } catch {
                    Write-ChunkLog $targetDomain $remoteComputer $reportName "ERROR" "Unable to create group only entry for $($entry.DistinguishedName)." $chunkLogPath $EnableConsoleOutput $EnableVerboseMode
                }
            }

            if ($groupFailures.Count -gt 0) {
                $failCsvPath = $csvPath -replace '\.csv$', '-failures.csv'
                $groupFailures | Export-Csv -Path $failCsvPath -Encoding UTF8 -NoTypeInformation -Force
                Write-ChunkLog $targetDomain $remoteComputer $reportName "WARNING" "Exported $($groupFailures.Count) group failures to $failCsvPath" $chunkLogPath $EnableConsoleOutput $EnableVerboseMode
            }


            Write-ChunkLog "<Debug>" $hostname $reportName "INFO" "inputArray type: $($inputArray.GetType().FullName), count: $($inputArray.Count)" $chunkLogPath $EnableConsoleOutput $EnableVerboseMode
            # return @{ Logs = $jobLog; Results = $localResults } # Use for Start-Threadjob
            Write-Output "LOGBLOCK_START"
            $jobLog | ForEach-Object { Write-Output "LOG:$_" }

            Write-Output "RESULTBLOCK_START"
            $localResults | ConvertTo-Json -Compress
        }

        # Lightweight NTLM/Kerberos detection
        try {
            $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
            $authMethod = $identity.AuthenticationType
            $user = $identity.Name

            if ($authMethod -eq "NTLM") {
                Log-Activity -DomainName $DomainName -RemoteComputer $hostname -ScriptName "AuthCheck" -ActionType "WARNING" -Message "Using NTLM authentication for $user — Kerberos likely failed or unavailable."
            } else {
                Log-Activity -DomainName $DomainName -RemoteComputer $hostname -ScriptName "AuthCheck" -ActionType "INFO" -Message "Using $authMethod authentication for $user."
            }
        } catch {
            Log-Activity -DomainName $DomainName -RemoteComputer $hostname -ScriptName "AuthCheck" -ActionType "WARNING" -Message "Could not determine authentication method: $($_.Exception.Message)"
        }
        # Define the domain and create the domain-specific subfolder for the reports
        $domainName = $trust.Name
        $domainFolder = Join-Path $dailyFolder $domainName
        if (-not (Test-Path $domainFolder)) {
            New-Item -ItemType Directory -Path $domainFolder -Force | Out-Null
        }

        $dcStartTime = Get-Date
        $dcResult = Resolve-TrustedDomainDC -DomainName $domainName
        $remoteComputer = [string]$dcResult.Computer

        # If a SID is returned, add it to the DomainSIDMap
        if ($dcResult.SID) {
            $DomainSidMap[$domainName.ToLower()] = $dcResult.SID
        }

        # Catch if there's a null value or no DC was reachable and stop processing this loop
        if (-not $remoteComputer) {
            Log-Activity $domainName "<None>" "DC-Select" "ERROR" "No reachable DC found for $domainName"
            # return @{ Logs = $jobLog; Results = $null } # Use for start-threadJob
            Write-Output "LOGBLOCK_START"
            $jobLog | ForEach-Object { Write-Output "LOG:$_" }

            Write-Output "RESULTBLOCK_START"
            $null | ConvertTo-Json -Compress
        }

        # Test to make sure AD cmdlets work talking to the remote DC, no point in running the reports otherwise
        if (-not (Test-DomainAuth -DomainName $domainName -RemoteComputer $remoteComputer)) {
            return @{ Logs = $jobLog; Results = $null }
        }

        $dcDuration = (Get-Date) - $dcStartTime
        $dcTime = "{0:F3}" -f $dcDuration.TotalSeconds
        Log-Activity $domainName $hostname "DC-Select" "RUNTIME" "DC selection took $dcTime seconds"

        # Here we define the reports themselves
        $reportScripts = @(
            @{ Name = "AD_User_Export"; Script = {
                param([string]$Server)
                # Retrieve AD users with required schema-aligned properties
                Get-ADUser -Server $Server -Filter * -Properties 'AccountExpirationDate','accountExpires','AccountLockoutTime','AccountNotDelegated','AllowReversiblePasswordEncryption','AuthenticationPolicy','AuthenticationPolicySilo','BadLogonCount','badPasswordTime','badPwdCount','CannotChangePassword','CanonicalName','Certificates','City','CN','co','codePage','comment','Company','CompoundIdentitySupported','Country','countryCode','Created','createTimeStamp','Deleted','Department','Description','DisplayName','DistinguishedName','Division','DoesNotRequirePreAuth','EmailAddress','EmployeeID','EmployeeNumber','employeeType','Enabled','Fax','GivenName','HomeDirectory','HomedirRequired','HomeDrive','HomePage','HomePhone','info','Initials','instanceType','isDeleted','KerberosEncryptionType','l','LastBadPasswordAttempt','LastKnownParent','LastLogonDate','LockedOut','LogonWorkstations','mail','Manager','MemberOf','MNSLogonAccount','MobilePhone','Modified','modifyTimeStamp','msDS-User-Account-Control-Computed','Name','ObjectCategory','ObjectClass','ObjectGUID','objectSid','Office','OfficePhone','Organization','OtherName','PasswordExpired','PasswordLastSet','PasswordNeverExpires','PasswordNotRequired','POBox','PostalCode','PrimaryGroup','primaryGroupID','PrincipalsAllowedToDelegateToAccount','ProfilePath','ProtectedFromAccidentalDeletion','pwdLastSet','SamAccountName','sAMAccountType','ScriptPath','sDRightsEffective','ServicePrincipalNames','SID','SmartcardLogonRequired','sn','State','StreetAddress','Surname','thumbnailPhoto','Title','TrustedForDelegation','TrustedToAuthForDelegation','UseDESKeyOnly','userAccountControl','userCertificate','UserPrincipalName','whenChanged','whenCreated'
            }},
            @{ Name = "AdminCount"; Script = {
                param([string]$Server)
                Get-ADUser -Server $Server -Filter 'adminCount -eq 1' -Properties adminCount, Name, SamAccountName, UserPrincipalName |
                Select-Object Name, SamAccountName, UserPrincipalName, adminCount
            }},
            @{ Name = "DomainTrusts"; Script = {
                param([string]$Server)
                Get-ADTrust -Server $Server -Filter * -Properties 'CanonicalName','CN','Created','createTimeStamp','Deleted','Description','Direction','DisallowTransivity','DisplayName','DistinguishedName','flatName','ForestTransitive','instanceType','IntraForest','isCriticalSystemObject','isDeleted','IsTreeParent','IsTreeRoot','LastKnownParent','Modified','modifyTimeStamp','msDS-SupportedEncryptionTypes','msDS-TrustForestTrustInfo','Name','ObjectCategory','ObjectClass','ObjectGUID','ProtectedFromAccidentalDeletion','sDRightsEffective','securityIdentifier','SelectiveAuthentication','showInAdvancedViewOnly','SIDFilteringForestAware','SIDFilteringQuarantined','Source','Target','TGTDelegation','TrustAttributes','trustDirection','TrustedPolicy','TrustingPolicy','trustPartner','trustPosixOffset','TrustType','UplevelOnly','UsesAESKeys','UsesRC4Encryption','whenChanged','whenCreated'
            }}
        )

        # If the domain name is null or the input array is empty or null, don't run group processing
        if (-not $domainName) {
            Log-Activity "<Init>" $hostname "GroupDiscovery" "WARNING" "Target domainName is null or empty — GroupMembership will be skipped."
        } elseif (-not $EnableAllGroupsQuery -and (-not $GroupInputArray -or $GroupInputArray.Count -eq 0)) {
            Log-Activity "<Init>" $hostname "GroupDiscovery" "WARNING" "Group input array is empty — Domain-specific GroupMembership report will be skipped."
        } else {
            $domainGroupEntries = @()
            # Filter for matching domain entries only (or the script will take days to run)
            if ($EnableAllGroupsQuery) {
                try {
                    Log-Activity $domainName $remoteComputer "GroupDiscovery" "INFO" "Pulling all groups from $remoteComputer via Get-ADGroup"
                    $rawGroups = Get-ADGroup -Server $remoteComputer -Filter * -Properties *
                    # Export list of groups with all their data
                    $csvPath = Join-Path $domainFolder "$domainName-GroupList-$Date.csv"
                    $rawGroups | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8 -Force
                        # | Select-Object `
                        # @{Name='Domain'; Expression={ $domainName }},
                        # @{Name='GroupName'; Expression={ $_.Name }},
                        # 'CanonicalName','CN','Created','createTimeStamp','Deleted','Description','DisplayName','DistinguishedName','Domain','GroupCategory','GroupName','GroupScope','groupType','HomePage','instanceType','isCriticalSystemObject','isDeleted','LastKnownParent','ManagedBy','Modified','modifyTimeStamp','Name','ObjectCategory','ObjectClass','ObjectGUID','objectSid','ProtectedFromAccidentalDeletion','SamAccountName','sAMAccountType','sDRightsEffective','SID','whenChanged','whenCreated' `
                        

                    # Use reduced version in memory
                    $rawGroups = $rawGroups | Select-Object DistinguishedName, Name, Members

                    $domainGroupEntries = foreach ($g in $rawGroups) {
                        Log-Activity $domainName $remoteComputer "GroupDiscovery" "DEBUG" "Processing $($g.DistinguishedName)"
                        # Validate and coerce
                        try {
                            $groupName = "$($g.Name)"
                            if (-not $groupName) { continue }
                        } catch {
                            Log-Activity $domainName $remoteComputer "GroupDiscovery" "WARNING" "Group name could not be coerced to string — skipping group with DN $($g.DistinguishedName)"
                            continue
                        }

                        try {
                            $groupDN = "$($g.DistinguishedName)"
                            if (-not $groupDN) { continue }
                        } catch {
                            Log-Activity $domainName $remoteComputer "GroupDiscovery" "WARNING" "Group DN could not be coerced to string — skipping group $groupName"
                            continue
                        }

                        # Validate that Name is scalar string
                        if ($g.Name -isnot [string]) {
                            Log-Activity $domainName $remoteComputer "GroupDiscovery" "WARNING" "Group object with DN $($g.DistinguishedName) has invalid Name type: $($g.Name.GetType().Name) — skipping"
                            continue
                        }

                        # Ensure DistinguishedName is also string
                        if ($g.DistinguishedName -isnot [string]) {
                            Log-Activity $domainName $remoteComputer "GroupDiscovery" "WARNING" "Group '$($g.Name)' has invalid DN type — skipping"
                            continue
                        }

                        # Normalize and sanitize members
                        $members = switch ($g.Members) {
                            $null { @() }
                            { $_ -is [string] } { @($_) }
                            { $_ -is [array] }  { $_ }
                            default { @($_.ToString()) }
                        }

                        $groupName = "$($g.Name)"               # ensures flattening to string
                        $groupDN   = "$($g.DistinguishedName)"  # same for DN

                        # Now build object using known-good strings
                        [PSCustomObject]@{
                            Domain            = $domainName
                            GroupName         = $groupName
                            Name              = $groupName
                            DistinguishedName = $groupDN
                            Member            = $members
                        }
                        Log-Activity $domainName $remoteComputer "GroupDiscovery" "DEBUG" "Completed processing $($g.DistinguishedName)"
                    }

                    Log-Activity $domainName $remoteComputer $reportName "INFO" "Retrieved $($domainGroupEntries.Count) groups"
                }
                catch {
                    Log-Activity $domainName $remoteComputer $reportName "ERROR" "Failed to retrieve groups for ${domainName}: $_"
                    $domainGroupEntries = @()  # fail-safe
                }
            } else {
                    $rawGroups = $GroupInputArray | Where-Object { $_.Domain -eq $domainName }
                    $domainGroupEntries = @()

                    foreach ($g in $rawGroups) {
                        try {
                            $resolved = Get-ADGroup -Server $remoteComputer -Filter { Name -eq $($g.GroupName) } -Properties *

                            if ($null -eq $resolved) {
                                Log-Activity $domainName $remoteComputer $reportName "WARNING" "Group '$($g.GroupName)' in domain '$domainName' returned null — skipping."
                                continue
                            }

                            $domainGroupEntries += [PSCustomObject]@{
                                Domain            = $g.Domain
                                GroupName         = $g.GroupName
                                Name              = $resolved.Name
                                DistinguishedName = $resolved.DistinguishedName
                                Member            = $resolved.Member
                            }
                        } catch {
                            Log-Activity $domainName $remoteComputer $reportName "ERROR" "Could not resolve group '$($g.GroupName)' in domain '$domainName': $($_.Exception.Message)"
                            continue
                        }
                    }
                }
            Log-Activity $domainName "<Debug>" "DomainDebug" "INFO" "Filtering group entries for $domainName"
            
            # Pre-check: Can we resolve Domain Admins in this domain?
            $domainAdminCheck = $null
            try {
                $domainAdminCheck = Get-ADGroup -Server $remoteComputer -Identity "Domain Admins" -ErrorAction Stop
                Log-Activity $domainName $remoteComputer $reportName "INFO" "Verified Domain Admins group exists: $($domainAdminCheck.DistinguishedName)"
            } catch {
                Log-Activity $domainName $remoteComputer $reportName "ERROR" "Cannot resolve Domain Admins group — skipping group membership lookups for this domain"
                $domainGroupEntries = @()
            }

            # Add the group membership script block to the reports array
            if ($domainGroupEntries.Count -gt 0) {
                Log-Activity $domainName $hostname $reportName "INFO" "Calling GroupMembership script with $($domainGroupEntries.Count) entries"
                # Split into blocks if too many groups
                $groupChunks = Split-Array -InputArray $domainGroupEntries -ChunkSize $GroupsPerJob
                Log-Activity $domainName $hostname $reportName "INFO" "Splitting $($domainGroupEntries.Count) groups into $($groupChunks.Count) jobs of max $GroupsPerJob groups each"
                $chunkIndex = 1
                $failedGroups = @()

                foreach ($chunk in $groupChunks) {
                    $csvPath = Join-Path $domainFolder "$domainName-GroupMembership-Block$chunkIndex-$Date.csv"
                    $chunkLogPath = Join-Path $domainFolder "GroupMembership-Block$chunkIndex-$Date.log"
                    New-Item -Path (Split-Path $logFilePath) -ItemType Directory -Force | Out-Null


                    $reportScripts += @{
                        Name      = "GroupMembership-Block$chunkIndex"
                        Script    = $groupMembershipScript
                            Arguments = @(
                                $(if ($EnableAllGroupsQuery) { $chunk } else { $GroupInputArray }),
                                $domainName,
                                $remoteComputer,
                                $EnableCrossDomainMemberLookups,
                                $UseFastLDAPLookups,
                                $GroupProcessingTimeThresholdSec,
                                $MaxGroupRecursionDepth,
                                $csvPath,
                                $chunkLogPath,
                                $EnableConsoleOutput,
                                $EnableVerboseMode
                            )
                    }
                    Log-Activity "<Debug>" $hostname $reportName "DEBUG" "InputArray count: $($inputArray.Count)"

                    $chunkIndex++

                Log-Activity "<Init>" $hostname $reportName "INFO" "Found $($domainGroupEntries.Count) group entries for $domainName"
                } else {
                    Log-Activity "<Init>" $hostname $reportName "WARNING" "No matching group entries found for $domainName — skipping"
                }
            } else {
                Log-Activity $domainName $remoteComputer $reportName "ERROR" "There are $($domainGroupEntries.Count) entires in the domainGroupEntries array!"
            }
        }

        # Process the reports defined earlier
        foreach ($script in $reportScripts) {
            $reportName = $script.Name
            $csvPath = Join-Path $domainFolder "$domainName-$reportName-$Date.csv"
            $memBefore = [GC]::GetTotalMemory($false)
            $scriptStart = Get-Date

            Log-Activity $domainName "<Debug>" "DomainDebug" "INFO" "Starting script $reportName in $domainName"

            try {
                if ($null -eq $script.Script) {
                    Log-Activity $domainName $remoteComputer $reportName "ERROR" "Script block is null for $reportName — skipping."
                    continue
                }

                if ($script.Script -isnot [scriptblock]) {
                    Log-Activity $domainName $remoteComputer $reportName "ERROR" "Script is not a scriptblock. Got type: $($script.Script.GetType().FullName)"
                    continue
                }

                # Handle argument-bound scripts
                if ($script.ContainsKey("Arguments")) {
                    Log-Activity $domainName $remoteComputer $reportName "DEBUG" "Invoking script block with arguments"
                    $argSet = $script.Arguments
                    $result = & $script.Script @argSet
                } else {
                    Log-Activity $domainName $remoteComputer $reportName "DEBUG" "Invoking script block with remoteComputer: $remoteComputer"
                    $result = & $script.Script $remoteComputer
                }

                # Consolidate group membership files and export other reports
                if ($reportName -like "GroupMembership*") {
                    if ($null -eq $result) {
                        Log-Activity $domainName $remoteComputer $reportName "ERROR" "GroupMembership script returned null — possible failure."
                        continue
                    }
                Log-Activity $domainName $remoteComputer $reportName "DEBUG" "GroupMembership job completed. Output handled inside the job script."
                if ($failedGroups.Count -gt 0) {
                        $timestamp = Get-Date -Format "HHmm_MM-yyyy-MM-dd"
                        $failedFile = Join-Path $domainFolder "$domainName-$reportName-Block$chunkIndex-$timestamp-FailedGroups.csv"
                        $failedGroups | Export-Csv -Path $failedFile -NoTypeInformation -Encoding UTF8
                        Log-Activity $domainName $domainController $reportName "WARNING" "Exported $($failedGroups.Count) failed groups to $failedFile"
                    }
                }
                else {
                    # Handle other reports (simple array output)
                    if ($null -eq $result) {
                        Log-Activity $domainName $remoteComputer $reportName "DEBUG" "Script result was null."
                        continue
                    } else {
                        try {
                            $result | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8 -Force
                            Log-Activity $domainName $remoteComputer $reportName "SUCCESS" "Exported $($result.Count) non-group records to $csvPath"
                        } catch {
                            Log-Activity $domainName $remoteComputer $reportName "ERROR" "Failed to export result: $($_.Exception.Message)"
                        }
                    }
                }
            } catch {
                Log-Activity $domainName $remoteComputer $reportName "ERROR" "Exception while running script ${name}: $($_.Exception.Message)"
                continue
            } finally {
                $memAfter = [GC]::GetTotalMemory($false)
                $memDelta = $memAfter - $memBefore
                $memUsedMB = "{0:N2}" -f ($memDelta / 1MB)
                $scriptDuration = (Get-Date) - $scriptStart
                $scriptTime = "{0:F3}" -f $scriptDuration.TotalSeconds

                Log-Activity $domainName $remoteComputer $reportName "RUNTIME" "$reportName execution took $scriptTime seconds"
                Log-Activity $domainName $remoteComputer $reportName "RUNTIME" "$reportName memory delta: $memUsedMB MB"
            }
        }
    return @{ Logs = $jobLog }
    } `
    -ArgumentList @(
        $domainName,
        $trust,
        $OutputRoot,
        $Date,
        $EnableAllGroupsQuery,
        $EnableCrossDomainMemberLookups,
        $EnableConsoleOutput,
        $GroupInputArray,
        $ActivityLogPath,
        $DailyFolder,
        $UseFastLDAPLookups,
        $GroupProcessingTimeThresholdSec,
        $EnableVerboseMode,
        $global:logQueue,
        $MaxGroupRecursionDepth,
        $GroupsPerJob
    ) 

    if ($job) {
        # Increment total jobs and running jobs counters
        $totalJobs++
        $jobsRunning++

        # Safety check to keep $domainJobs as an array
        if (-not ($domainJobs -is [System.Collections.IList])) {
            $domainJobs = @()
        }
        $domainJobs += $job
        Log-Activity "$domainName" $hostname "DomainJobs" "DEBUG" "Start-DomainJobs returning $($domainJobs.Count) job(s)"
        Log-Activity "<Tracker>" "<SCRIPT>" "JobStatus" "INFO" "Running: $jobsRunning, Done: $jobsDone, Total: $totalJobs"
    } else {
        Log-Activity "<Parallel>" $domainName "JobLaunch" "ERROR" "Failed to start job for $domainName"
    }
}

Log-Activity "<Init>" $hostname "DomainJobs" "DEBUG" "[DEBUG] All jobs dispatched. Final job count: $($domainJobs.Count)"

$domainJobs | ForEach-Object {
    $jobTime = if ($_.CreationTime) { $_.CreationTime.ToString("HH:mm:ss") } else { "<unknown>" }
    $location = if ($_.ChildJobs[0].JobStateInfo.Location) { $_.ChildJobs[0].JobStateInfo.Location } else { "<n/a>" }
    Write-Host "[DEBUG] Job ID: $($_.Id) | Start: $($jobTime) | State: $($_.State) | Name: $($_.Name) | Location: $location"
}

# Wait for any remaining jobs to finish
$domainJobs = $domainJobs | Where-Object { $_ -ne $null }

if ($domainJobs.Count -eq 0) {
    Log-Activity "<Parallel>" $hostname "JobMonitor" "WARNING" "No valid jobs were found to complete. All may have failed to launch."
}

foreach ($j in $domainJobs) {
    $jobScript = "SCRIPT"
    $jobId = $j.Id

    try {
        # Wait for the job to finish (unbounded)
        Wait-Job -Job $j | Out-Null

        # Safely update counters:
        $jobsDone++
        $jobsRunning--

        # Try receiving the job result
        $result = $null
        try {
            # $result = Receive-Job -Job $j -ErrorAction SilentlyContinue # Use with Start-ThreadJob
            $output = Receive-Job -Job $j -ErrorAction SilentlyContinue
            $logLines = $output | Where-Object { $_ -like 'LOG:*' } | ForEach-Object { $_ -replace '^LOG:', '' }

            # This assumes only one result block is emitted per job, and it’s valid JSON
            $jsonBlock = $output | Where-Object { $_ -match '^\{.*\}$' } | Select-Object -First 1
            if ($jsonBlock) {
                $result = $jsonBlock | ConvertFrom-Json
            } else {
                $result = $null
            }

            foreach ($line in $logLines) {
                Log-Activity $jobScript "<SCRIPT>" "JobReceive" "DEBUG" "Job ${$jobId}: $line"
            }
        } catch {
            Log-Activity $jobScript "<SCRIPT>" "JobReceive" "ERROR" "Exception while receiving job $jobId output: $_"
        }

        if ($result -and $result.Status -and $result.Domain) {
            if (-not $script:domainStatusTable) {
                $script:domainStatusTable = @{}
            }
            $script:domainStatusTable[$result.Domain] = $result.Status
        }

        if ($result -and $result.DomainStatus) {
            if (-not $global:DomainStatusTable) {
                $global:DomainStatusTable = @()
            }
            $global:DomainStatusTable += $result.DomainStatus
        }

        # Extract job domain for logging (if possible)
        if ($j.ChildJobs.Count -gt 0 -and $j.ChildJobs[0].JobStateInfo.Location) {
            $jobScript = $j.ChildJobs[0].JobStateInfo.Location
        }

        # Log if failed
        if ($j.State -eq 'Failed' -or ($j.ChildJobs.Count -gt 0 -and $j.ChildJobs[0].State -eq 'Failed')) {
            $reason = $j.ChildJobs[0].JobStateInfo.Reason.Exception.Message
            Log-Activity $jobScript "<SCRIPT>" "JobFailure" "ERROR" "Background job $jobId failed: $reason"
        } else {
            Log-Activity $jobScript "<SCRIPT>" "JobFinalize" "INFO" "Job $jobId finished with state: $($j.State)"
        }
        Log-Activity "<Tracker>" "<SCRIPT>" "JobStatus" "INFO" "Running: $jobsRunning, Done: $jobsDone, Total: $totalJobs"
    } catch {
        Log-Activity $jobScript "<SCRIPT>" "JobFinalize" "ERROR" "Error during job $jobId finalization: $_"
    }

    # Remove the job from memory
    try {
        Remove-Job -Job $j -Force
        Log-Activity $jobScript "<SCRIPT>" "JobCleanup" "INFO" "Removed job $jobId"
    } catch {
        Log-Activity $jobScript "<SCRIPT>" "JobCleanup" "ERROR" "Could not remove job ${jobId}: $_"
    }
}

# Streamed summary logging — no need to re-import full log from disk
try {
    $successes = $domainStatusTable.GetEnumerator() | Where-Object { $_.Value -eq "SUCCESS" } | ForEach-Object { $_.Key }
    $warnings  = $domainStatusTable.GetEnumerator() | Where-Object { $_.Value -eq "WARNING" } | ForEach-Object { $_.Key }
    $errors    = $domainStatusTable.GetEnumerator() | Where-Object { $_.Value -eq "ERROR" }   | ForEach-Object { $_.Key }

    if ($successes.Count -gt 0) {
        Log-Activity "<Summary>" $hostname "Summary" "INFO" ("Domains with SUCCESS : " + ($successes -join ", "))
    }
    if ($warnings.Count -gt 0) {
        Log-Activity "<Summary>" $hostname "Summary" "INFO" ("Domains with WARNINGS: " + ($warnings -join ", "))
    }
    if ($errors.Count -gt 0) {
        Log-Activity "<Summary>" $hostname "Summary" "INFO" ("Domains with ERRORS  : " + ($errors -join ", "))
    }
} catch {
    Log-Activity "<Summary>" $hostname "Summary" "ERROR" "Failed to summarize domain results: $_"
}

# Export the domain status table to CSV and strip any " marks from the output
try {
    $domainStatusCsv = $domainStatusTable.GetEnumerator() | ForEach-Object {
        [PSCustomObject]@{
            DomainName = $_.Key
            Status     = $_.Value
        }
    }

    $domainStatusCsv | Sort-Object DomainName | Export-Csv -Path $domainStatusPath -NoTypeInformation -Force

    Log-Activity "<Summary>" $hostname "DomainStatus" "INFO" "Exported domain status table to $domainStatusPath"
} catch {
    Log-Activity "<Summary>" $hostname "DomainStatus" "ERROR" "Failed to export domain status table: $($_.Exception.Message)"
}

# Send the report via email if the $sendEmail variable is $true
if ($sendEmail) { Send-EmailReport -Date $Date }
 else {
    Log-Activity "<AllDomains>" $hostname "EmailReport" "INFO" "Email sending is DISABLED. No report was sent."
}

# Compress and clean domain result folders
Compress-DomainResults

# Run function to clean old reports, activity logs, and so on.
Clean-OldReports -ReportRoot $outputRoot -RetentionDays $RetentionDays

$scriptDuration = (Get-Date) - $scriptStartTime
$scriptTimeMin = "{0:F3}" -f $scriptDuration.TotalMinutes
Log-Activity "<Summary>" $hostname "Script" "RUNTIME" "Total script execution time: $scriptTimeMin minutes"
Log-Activity "<Summary>" $hostname "Script" "INFO" "Successfully completed script at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"

Stop-LogFlusher -LogFilePath $activityLogPath -LogQueue $global:logQueue