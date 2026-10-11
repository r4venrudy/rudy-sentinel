# Kernel lab

Use a disposable Windows 11 x64 VM with a snapshot and recovery path. Builds and automated tests never install or load the driver.

1. Build with the pinned SDK/WDK and inspect diagnostics.
2. Configure appropriate test signing **inside the VM** using [Microsoft's guidance](https://learn.microsoft.com/windows-hardware/drivers/install/test-signing). Keep private keys out of this repository. Production signing is separate.
3. Verify the driver signature. Do not weaken host protections to run the preview.
4. The optional elevated installation script requires `-LabVm`, valid signing, and explicit build paths. It creates demand-start services and restricts session folders to SYSTEM/administrators.
5. Start the driver and foreground agent. Launch benign programs such as Notepad and verify lifecycle events. Replay fixtures for suspicious signals; fixture commands are never executed.
6. Test repeated load/unload, stop/start, queue overflow and failure paths. Use [Driver Verifier](https://learn.microsoft.com/windows-hardware/drivers/devtest/driver-verifier) in the VM and retain any crash dumps.
7. Measure CPU, memory, queue loss and latency under representative workloads. Test supported Windows versions and signing/security configurations before distribution.

```powershell
./scripts/Install-Lab.ps1 -LabVm -DriverPath ./artifacts/sensor/Release/RudySensor.sys -AgentPath ./build/native/Release/rudy-sentinel.exe -RulesPath ./rules/default.json
sc.exe start RudySensor
sc.exe start RudySentinel
```

The service creates a session under `%ProgramData%\RudySentinel\sessions`. Open that session in the console using an account with access to those logs.

Supported removal:

```powershell
sc.exe stop RudySentinel
sc.exe stop RudySensor
sc.exe delete RudySentinel
sc.exe delete RudySensor
```

Preserve relevant sessions before cleanup. No signing certificate is included; the project has not passed HLK or production certification. Existing service entries are never silently overwritten by the installation script.

References: [WDK NuGet](https://learn.microsoft.com/windows-hardware/drivers/install-the-wdk-using-nuget), [process callbacks](https://learn.microsoft.com/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutineex), [object callbacks](https://learn.microsoft.com/windows-hardware/drivers/ddi/wdm/nf-wdm-obregistercallbacks), [device SDDL](https://learn.microsoft.com/windows-hardware/drivers/kernel/sddl-for-device-objects).
