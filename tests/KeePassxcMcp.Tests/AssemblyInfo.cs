using Xunit.Sdk;

// e2e suites share a built exe + real keepassxc-cli processes; run serially.
[assembly: Xunit.v3.Parallelization(Mode = ParallelMode.None)]
