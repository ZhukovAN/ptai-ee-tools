<#
[CmdletBinding()]
Param(
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()] $useRemotePtaiService,
    [Parameter(Mandatory=$false)][ValidateNotNullOrEmpty()] $remotePtaiService,
    [Parameter(Mandatory=$false)][ValidateNotNullOrEmpty()] $ptaiAgent,
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()] $scanSettingsType,
    [Parameter(Mandatory=$false)] $projectName,
    [Parameter(Mandatory=$false)] $jsonSettings,
    [Parameter(Mandatory=$false)] $jsonPolicy,
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()] $failIfAstUnstable,
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()] $includeFiles,
    [Parameter(Mandatory=$false)] $excludeFiles,
    [Parameter(Mandatory=$false)] $removePrefix,
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()] $usePredefinedExcludes,
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()] $flattenFiles
)
if (-not $Env:BUILD_SOURCESDIRECTORY) {
	Write-Host "You must set the following environment variables"
	Write-Host "to test this script interactively."
	Write-Host '$Env:BUILD_SOURCESDIRECTORY - For example, enter something like:'
	Write-Host '$Env:BUILD_SOURCESDIRECTORY = "C:\code\app01"'
	exit 1
}
$sourceLocation = ([String]$env:BUILD_SOURCESDIRECTORY).trim()
#>
[System.Reflection.Assembly]::LoadFile("$PSScriptRoot/JsonSubTypes.dll") | out-null
[System.Reflection.Assembly]::LoadFile("$PSScriptRoot/Newtonsoft.Json.dll") | out-null
[System.Reflection.Assembly]::LoadFile("$PSScriptRoot/RestSharp.dll") | out-null
[System.Reflection.Assembly]::LoadFile("$PSScriptRoot/AI.Enterprise.Integration.RestApi.dll") | out-null
[System.Reflection.Assembly]::LoadFile("$PSScriptRoot/AI.Generic.Client.dll") | out-null

$useRemotePtaiServices = "false"
$includes = "**/*"
$excludes = "**/target/**, **/*.json, **/*.xml"
$removePrefix = ""
$usePredefinedExcludes = "true"
$flatten = "false"
$projectName = "DEVEL.TEST.JAVA"
$jsonSettings = ""
$jsonPolicy = ""
$sourceFolder = "D:\TEMP\20200217\SRC"
$tempFolder = "D:\TEMP\20200217\TEMP" 
$stagingFolder = "D:\TEMP\20200217\STAGING"

$plugin = New-Object -TypeName AI.Generic.Client.Plugin -ArgumentList $useRemotePtaiServices,
    "url", "login", "password", "ca", "agent", $includes, $excludes, $removePrefix, 
    $usePredefinedExcludes, $flatten, 
    $projectName, $jsonSettings, $jsonPolicy, $sourceFolder, $tempFolder, $stagingFolder
$res = $plugin.scan()
"Result is "
$res