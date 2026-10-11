#Requires -RunAsAdministrator
[CmdletBinding()]
param([switch]$LabVm,[Parameter(Mandatory)][string]$DriverPath,[Parameter(Mandatory)][string]$AgentPath,[Parameter(Mandatory)][string]$RulesPath)
$ErrorActionPreference='Stop'
if (!$LabVm) { throw 'Use -LabVm only inside a disposable, configured test VM.' }
$driver=(Resolve-Path -LiteralPath $DriverPath).Path
$agent=(Resolve-Path -LiteralPath $AgentPath).Path
$rules=(Resolve-Path -LiteralPath $RulesPath).Path
if ((Get-AuthenticodeSignature -LiteralPath $driver).Status -ne 'Valid') { throw 'A valid, trusted driver signature is required. Configure VM signing first.' }
foreach($name in @('RudySensor','RudySentinel')) { if (Get-Service -Name $name -ErrorAction SilentlyContinue) { throw "Service $name already exists; inspect the old installation first." } }
$destination=Join-Path $env:ProgramFiles 'RudySentinelLab'
if(Test-Path -LiteralPath $destination) { throw 'The lab folder already exists; inspect it before reinstalling.' }
New-Item -ItemType Directory -Path $destination | Out-Null
Copy-Item -LiteralPath $driver -Destination (Join-Path $destination 'RudySensor.sys')
Copy-Item -LiteralPath $agent -Destination (Join-Path $destination 'rudy-sentinel.exe')
Copy-Item -LiteralPath $rules -Destination (Join-Path $destination 'rules.json')
$sessions=Join-Path $env:ProgramData 'RudySentinel\sessions'
New-Item -ItemType Directory -Path $sessions -Force | Out-Null
& icacls.exe $sessions /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
if($LASTEXITCODE -ne 0) { throw 'Could not restrict the session directory.' }
$sensorBinary='"{0}"' -f (Join-Path $destination 'RudySensor.sys')
& sc.exe create RudySensor type= kernel start= demand binPath= $sensorBinary
if($LASTEXITCODE -ne 0) { throw 'Driver registration failed.' }
$agentBinary='"{0}" --live --service --rules "{1}" --out "{2}"' -f (Join-Path $destination 'rudy-sentinel.exe'),(Join-Path $destination 'rules.json'),$sessions
& sc.exe create RudySentinel type= own start= demand binPath= $agentBinary DisplayName= 'Rudy Sentinel Research Agent'
if($LASTEXITCODE -ne 0) { & sc.exe delete RudySensor | Out-Null; throw 'Agent registration failed; driver service entry was removed.' }
Write-Output 'Registered demand-start lab services. Start RudySensor, then RudySentinel. No service was started by this script.'
