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
    Restart-Extension

    Write-Host $Test.FullName
    $Ret = Start-Process -File $VTestPath -RedirectStandardOutput "stdout.log" -RedirectStandardError "stderr.log" -Wait -PassThru -ArgumentList $Test.FullName
    Get-Content "stdout.log" | Write-Host
    Get-Content "stderr.log" | Write-Warning
    If ($Ret.ExitCode -ne 0) {
        throw "Test failed: $($Test.Name)"
    }
    Write-Host ""
}

Restart-Extension
Write-Host "vtest: all($(($Tests | Measure-Object).Count)) tests passed"
