# Validation status

Automated checks cover compilation, portable C queue semantics, C++ behavioral rules and process state, C# investigation data handling, synthetic replay, and WPF rendering. Consult the GitHub Actions run for each job's actual result.

Kernel runtime loading, callback behavior under real workloads, unload races, Driver Verifier, signing compatibility, HLK certification, adversarial testing, false-positive calibration, and performance benchmarking have not been completed. WDK compilation does not establish these properties. There is no guarantee of millions of events per second or instant malware detection.

Tests use synthetic data and never execute fixture command lines. No driver is loaded on the development machine or hosted CI.
