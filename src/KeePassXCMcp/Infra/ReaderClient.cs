namespace KeePassXCMcp.Infra;

/// <summary>Server-side half of the reader protocol: write a command file, poll for the
/// matching result file. One request in flight at a time (the reader is a single human
/// session, and this matches one-at-a-time tool calls).</summary>
public static class ReaderClient
{
    private static readonly SemaphoreSlim Gate = new(1, 1);
    private const int PollMs = 150;

    public static async Task<ReaderResult> SendAsync(ConfigPaths paths, string op, string arg,
        TimeSpan? timeout = null, CancellationToken ct = default)
    {
        if (!ReaderProtocol.TryGetLiveSession(paths, out _))
            return new ReaderResult { Ok = false, Error = "No reader session is open. Ask the user to run `keepassxc-mcp reader`, or (with their agreement) open the window with vault_reader_open." };

        var id = Guid.NewGuid().ToString("N");
        var deadline = DateTime.UtcNow + (timeout ?? TimeSpan.FromSeconds(120));
        await Gate.WaitAsync(ct);
        try
        {
            if (File.Exists(paths.ReaderResultFile)) File.Delete(paths.ReaderResultFile); // drop any stale answer
            ReaderProtocol.WriteAtomic(paths.ReaderCommandFile, new ReaderCommand { Id = id, Op = op, Arg = arg });

            while (DateTime.UtcNow < deadline)
            {
                await Task.Delay(PollMs, ct);
                var res = ReaderProtocol.TryReadAtomic<ReaderResult>(paths.ReaderResultFile);
                if (res is null)
                {
                    if (!ReaderProtocol.TryGetLiveSession(paths, out _))
                        break; // reader died mid-request (idle timeout / closed window)
                    continue;
                }
                File.Delete(paths.ReaderResultFile!);
                if (res.Id == id) return res;
                // A result for a different id is stale by definition — discard and keep waiting.
            }
            return new ReaderResult
            {
                Id = id,
                Ok = false,
                Error = "The reader did not answer (it may have hit its idle timeout, been closed, or the password attempt failed in the window). Re-open it with vault_reader_open and retry.",
            };
        }
        finally
        {
            Gate.Release();
        }
    }
}
