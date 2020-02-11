[CmdletBinding()]
Param(
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()] $scanSettingsType,
    [Parameter(Mandatory=$false)] $projectName,
    [Parameter(Mandatory=$false)] $jsonSettings,
    [Parameter(Mandatory=$false)] $jsonPolicy,
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()] $failIfAstUnstable
)
if (-not $Env:BUILD_SOURCESDIRECTORY) {
	Write-Host "You must set the following environment variables"
	Write-Host "to test this script interactively."
	Write-Host '$Env:BUILD_SOURCESDIRECTORY - For example, enter something like:'
	Write-Host '$Env:BUILD_SOURCESDIRECTORY = "C:\code\app01"'
	exit 1
}
$sourceLocation = ([String]$env:BUILD_SOURCESDIRECTORY).trim()
$aicExePathTemplate = ":\Program Files (x86)\Positive Technologies\Application Inspector Agent\aic.exe"
$aicExePath = $null
foreach ($ch in 65 .. (65 + 25)) {
    $drive = $([char]$ch).ToString().Trim()
    if (Test-Path -Path $drive$aicExePathTemplate) {
        $aicExePath = $drive + $aicExePathTemplate
        break
    }
}
if ($null -eq $aicExePath) {
    Write-Error "Couldn't find aic.exe, exiting"
    Exit
}

[System.Reflection.Assembly]::LoadFile("$PSScriptRoot/JsonSubTypes.dll") | out-null
[System.Reflection.Assembly]::LoadFile("$PSScriptRoot/Newtonsoft.Json.dll") | out-null
[System.Reflection.Assembly]::LoadFile("$PSScriptRoot/RestSharp.dll") | out-null
[System.Reflection.Assembly]::LoadFile("$PSScriptRoot/AI.Enterprise.Integration.RestApi.dll") | out-null
[System.Reflection.Assembly]::LoadFile("$PSScriptRoot/AI.Generic.Client.dll") | out-null

if ("json" -eq $scanSettingsType) {
    # Write the script to disk.
    $tempDirectory = ([String]$env:AGENT_TEMPDIRECTORY).trim()
    if ($jsonSettings -And $jsonSettings.trim()) {
        $filePath = [System.IO.Path]::Combine($tempDirectory, "$([System.Guid]::NewGuid()).json")
        [System.IO.File]::WriteAllText(
            $filePath,
            $jsonSettings,
            ([System.Text.Encoding]::UTF8)) | out-null
        $params += " --project-settings-file `"$filePath`""
    }
    if ($jsonPolicy -And $jsonPolicy.trim()) {
        $filePath = [System.IO.Path]::Combine($tempDirectory, "$([System.Guid]::NewGuid()).json")
        [System.IO.File]::WriteAllText(
            $filePath,
            $jsonPolicy,
            ([System.Text.Encoding]::UTF8)) | out-null
        $params += " --policies-path `"$filePath`""
    }
} elseif ("ui" -eq $scanSettingsType) {
    $params += " --project-name `"$projectName`""
}
$reportsFolder = ([String]$env:BUILD_ARTIFACTSTAGINGDIRECTORY).trim() + '\.ptai'
$params += " --scan-target `"$sourceLocation`" --reports `"JSON|HTML`" --reports-folder `"$reportsFolder`" --sync"
$aic = New-Object "AI.Generic.Client.ExeWrapper" ($aicExePath, $params)
$code = $aic.Execute()

switch ($code) {
    0        { $status = "SUCCESS::AST policy assessment OK" }
    -1       { $status = "ERROR::Application already started" }
    -2       { $status = "ERROR::Child process start failed" }
    2        { $status = "ERROR::Scan folder not found" }
    3        { $status = "ERROR::License error" }
    4        { $status = "ERROR::Project not found" }
    5        { $status = "ERROR::Project settings error" }
    6        { $status = "UNSTABLE::Minor error messages during scan" }
    7        { $status = "UNSTABLE::Mail sending failed" }
    8        { $status = "ERROR::Bad scan settings file path" }
    9        { $status = "UNSTABLE::Bad report folder path" }
    10       { $status = "FAILED::AST policy assessment failed" }
    11       { $status = "UNSTABLE::Bad report settings" }
    12       { $status = "ERROR::No client certificate found" }
    13       { $status = "ERROR::Scan was deleted" }
    14       { $status = "UNSTABLE::Autocheck authorization failed" }
    15       { $status = "UNSTABLE::Incorrect proxy settings" }
    16       { $status = "UNSTABLE::Incorrect host for check" }
    17       { $status = "UNSTABLE::AST policy error" }
    18       { $status = "ERROR::Scan kernel critical error" }
    19       { $status = "ERROR::Scan kernel not found" }
    20       { $status = "ERROR::Sources download failed" }
    21       { $status = "ERROR::Scan agent heartbeat timeout" }
    22       { $status = "ERROR::Update process failed" }
    23       { $status = "ERROR::Bad client certificate password" }
    24       { $status = "ERROR::Server certificate not found" }
    100      { $status = "ERROR::Scan was terminated" }
    1000     { $status = "ERROR::Unknown error" }
    default  { $status = "ERROR::Unknown error" }
}

if ($code -in @(0, 6, 7, 10)) {
    Write-Host "##vso[artifact.upload containerfolder=ptai.reports;artifactname=ptai.reports.zip;]$reportsFolder\report.json"
    Write-Host "##vso[artifact.upload containerfolder=ptai.reports;artifactname=ptai.reports.zip;]$reportsFolder\report.html"
}

$state = $status.Substring(0, $status.IndexOf("::"))
$message = $status.Substring($status.IndexOf("::") + "::".Length);

if (("ERROR" -eq $state) -Or ("FAILED" -eq $state)) {
    Write-Host "##vso[task.logissue type=error]$message"
    Write-Host "##vso[task.complete result=Failed;]"
} elseif (("true" -eq $failIfAstUnstable) -And ("UNSTABLE" -eq $state)) {
    Write-Host "##vso[task.logissue type=error]$message"
    Write-Host "##vso[task.complete result=Failed;]"
} elseif (("false" -eq $failIfAstUnstable) -And ("UNSTABLE" -eq $state)) {
    Write-Host "##vso[task.logissue type=warning]$message"
    Write-Host "##vso[task.complete result=SucceededWithIssues;]"
} else {
    Write-Host "$message"
    Write-Host "##vso[task.complete result=Succeeded;]"
}
