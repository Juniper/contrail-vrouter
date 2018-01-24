# all_tests_run.ps1
#
# Copyright (c) 2018, Juniper Networks, Inc.
# All rights reserved

Param ([Parameter(Mandatory = $true)] [string] $VMSwitchName,
       [Parameter(Mandatory = $true)] [string] $TestsFolder,
       [Parameter(Mandatory = $false)] [string] $VtestPath = "vtest.exe",
       [Parameter(Mandatory = $false)] [string] $ExtensionName = "vRouter forwarding extension")

function Restart-Extension {
    Disable-VMSwitchExtension -Name $ExtensionName -VMSwitchName $VMSwitchName -ErrorVariable Err | Out-Null
    If ($Err) {
        throw "Error while disabling the extension"
    }
    Enable-VMSwitchExtension -Name $ExtensionName -VMSwitchName $VMSwitchName -ErrorVariable Err | Out-Null
    If ($Err) {
        throw "Error while enabling the extension"
    }
}

$Tests = Get-ChildItem -Path $TestsFolder -Filter *.xml -Recurse
foreach ($Test in $Tests) {
    $OutFile = "$Env:Temp/vtest-stdout.log"
    $ErrFile = "$Env:Temp/vtest-stderr.log"

    Restart-Extension

    Write-Host $Test.FullName
    $Ret = Start-Process -File $VTestPath -RedirectStandardOutput $OutFile -RedirectStandardError $ErrFile `
        -Wait -PassThru -WindowStyle Hidden -ArgumentList $Test.FullName
    Get-Content $OutFile | Write-Host
    Remove-Item $OutFile
    Get-Content $ErrFile | Write-Warning
    Remove-Item $ErrFile

    If ($Ret.ExitCode -ne 0) {
        throw "Test failed: $($Test.Name)"
    }
    Write-Host ""
}

Restart-Extension
Write-Host "vtest: all($(($Tests | Measure-Object).Count)) tests passed"
