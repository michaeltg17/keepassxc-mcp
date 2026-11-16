using Xunit;

// e2e suites share a built exe + real keepassxc-cli processes; run serially.
[assembly: CollectionBehavior(DisableTestParallelization = true)]
