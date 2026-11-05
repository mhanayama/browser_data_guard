using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

namespace Bdg.Tray;

internal sealed record AccessEvent(DateTimeOffset Time, long Sequence, long Pid, string Process, string Image,
    string Target, string Browser, string Category, string Decision, bool Demo = false, long Reason = 0, long Flags = 0,
    string Operation = "", long Count = 1);

internal sealed class Telemetry
{
    public DateTimeOffset? Heartbeat { get; private set; }
    public int ServicePid { get; private set; }
    public long ServiceStart { get; private set; }
    public bool Armed { get; private set; }
    public bool Observing { get; private set; }
    public string Mode { get; private set; } = "";
    public long RuleCount { get; private set; }
    public long EventsReceived { get; private set; }
    public long EventsMatched { get; private set; }
    public long Unmapped { get; private set; }
    public long DecodeErrors { get; private set; }
    public ulong Lost { get; private set; }
    public int Invalid { get; private set; }
    public string IdentityStatus { get; private set; } = "pending";
    private Task<(int Pid, long Start, DateTimeOffset Checked, bool Alive, string Reason)>? processCheck;
    public void Disconnect() { Heartbeat = null; Armed = false; Observing = false; Mode = ""; }
    private static string Str(JsonElement root, string name, int limit = 32768) =>
        root.TryGetProperty(name, out var field) && field.ValueKind == JsonValueKind.String && field.GetString() is { } s && s.Length <= limit ? s : "";
    private static long Num(JsonElement root, string name) =>
        root.TryGetProperty(name, out var field) && field.TryGetInt64(out long value) ? value : 0;

    public AccessEvent? Accept(string line)
    {
        try
        {
            using var doc = JsonDocument.Parse(line);
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object) throw new JsonException();
            string type = Str(root, "type", 32);
            if (type == "heartbeat")
            {
                if (!DateTimeOffset.TryParse(Str(root, "timestamp"), CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var time) ||
                    Str(root, "mode") is not ("synthetic" or "observe-etw") || Num(root, "servicePid") is <= 0 or > int.MaxValue || Num(root, "serviceStart") <= 0)
                    throw new JsonException();
                Heartbeat = time; ServicePid = (int)Num(root, "servicePid"); ServiceStart = Num(root, "serviceStart");
                Armed = root.TryGetProperty("armed", out var armed) && armed.ValueKind == JsonValueKind.True;
                Mode = Str(root, "mode");
                Observing = Mode == "observe-etw" && root.TryGetProperty("observing", out var observing) && observing.ValueKind == JsonValueKind.True;
                if (Mode == "observe-etw") Armed = false; // Observation can never advertise a deny boundary.
                RuleCount = Num(root, "ruleCount"); EventsReceived = Num(root, "eventsReceived"); EventsMatched = Num(root, "eventsMatched");
                Unmapped = Num(root, "unmappedReadsWrites"); DecodeErrors = Num(root, "decodeErrors");
                long loss = Num(root, "lostEvents"); if (loss > 0) Lost = Math.Max(Lost, (ulong)loss);
            }
            else if (type == "stopped") Disconnect();
            else if (type == "audit_loss")
            {
                if (!root.TryGetProperty("lostEvents", out var lost) || !lost.TryGetUInt64(out ulong value)) throw new JsonException();
                Lost = Math.Max(Lost, value);
            }
            else if (type == "access")
            {
                string decision = Str(root, "decision", 8);
                long reason = Num(root, "reason");
                string target = Str(root, "target");
                if (decision is not ("deny" or "allow" or "observe") ||
                    (decision == "observe" && Str(root, "source") != "etw") ||
                    !DateTimeOffset.TryParse(Str(root, "timestamp"), CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var time) ||
                    (target.Length == 0 && reason != 2)) throw new JsonException();
                return new(time, Num(root, "sequence"), Num(root, "pid"), Str(root, "processName", 1024),
                    Str(root, "executablePath"), target.Length == 0 ? "名前取得失敗・対象パス不明" : target,
                    Str(root, "browser", 256), Str(root, "category", 256), decision, false, reason, Num(root, "flags"),
                    Str(root, "operation", 32), Math.Max(1, Num(root, "count")));
            }
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException or FormatException or OverflowException)
        { Invalid++; }
        return null;
    }

    public bool Fresh(DateTimeOffset now) => (Armed || Observing) && Heartbeat is { } time && now - time >= TimeSpan.FromSeconds(-2) && now - time < TimeSpan.FromSeconds(8);
    public bool ServiceAlive(DateTimeOffset now)
    {
        if (!Fresh(now)) return false;
        // SYSTEM services can grant QUERY_LIMITED_INFORMATION without SYNCHRONIZE.
        // Process.HasExited requests the latter and wrongly made a live service look offline.
        using var process = OpenProcess(0x1000, false, ServicePid);
        if (!process.IsInvalid && GetProcessTimes(process, out long creation, out _, out _, out _) &&
            creation == ServiceStart && GetExitCodeProcess(process, out uint exitCode) && exitCode == 259) { IdentityStatus = "verified-native"; return true; }
        // The WMI broker can expose creation metadata for SYSTEM processes whose DACL
        // denies even limited native queries. Keep COM work off the UI thread, and
        // compare the birth time (not just PID) before accepting the result.
        bool verified = false;
        if (processCheck is { IsCompletedSuccessfully: true })
        {
            var check = processCheck.Result;
            IdentityStatus = check.Reason;
            verified = check.Pid == ServicePid && check.Start == ServiceStart && check.Alive && now - check.Checked < TimeSpan.FromSeconds(4);
            if (now - check.Checked < TimeSpan.FromSeconds(2) && check.Pid == ServicePid && check.Start == ServiceStart) return verified;
        }
        if (processCheck == null || processCheck.IsCompleted)
        {
            int pid = ServicePid; long start = ServiceStart;
            processCheck = Task.Run(() => { bool alive = WmiBirthMatches(pid, start, out string reason); return (pid, start, DateTimeOffset.UtcNow, alive, reason); });
        }
        return verified;
    }
    private static bool WmiBirthMatches(int pid, long expected, out string reason)
    {
        reason = "process metadata unavailable";
        object? locator = null, connection = null, results = null;
        static void Release(object? value) { if (value != null && Marshal.IsComObject(value)) Marshal.ReleaseComObject(value); }
        try
        {
            var type = Type.GetTypeFromProgID("WbemScripting.SWbemLocator");
            if (type == null) return false;
            locator = Activator.CreateInstance(type);
            connection = ((dynamic)locator!).ConnectServer(".", @"root\cimv2");
            ((dynamic)connection).Security_.ImpersonationLevel = 3;
            results = ((dynamic)connection).Get("Win32_Process.Handle=\"" + pid + "\"");
            {
                    string raw = (string)((dynamic)results).Properties_.Item("CreationDate", 0).Value;
                    if (raw.Length != 25 || raw[14] != '.' || raw[21] is not ('+' or '-')) return false;
                    var date = DateTime.ParseExact(raw[..14], "yyyyMMddHHmmss", CultureInfo.InvariantCulture, DateTimeStyles.None)
                        .AddTicks(long.Parse(raw.Substring(15, 6), CultureInfo.InvariantCulture) * 10);
                    int offset = int.Parse(raw[22..], CultureInfo.InvariantCulture) * (raw[21] == '-' ? -1 : 1);
                    long actual = new DateTimeOffset(date, TimeSpan.FromMinutes(offset)).ToFileTime();
                    bool matches = expected >= actual && expected - actual < 10;
                    reason = matches ? "verified-WMI" : "process birth mismatch";
                    return matches; // WMI stores microseconds; FILETIME has 100ns precision.
            }
        }
        catch (Exception ex) when (ex is COMException or Microsoft.CSharp.RuntimeBinder.RuntimeBinderException or FormatException or ArgumentException or InvalidCastException)
        { reason = ex.GetType().Name + ": " + ex.Message; }
        finally { Release(results); Release(connection); Release(locator); }
        return false;
    }
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern SafeProcessHandle OpenProcess(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, int pid);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetProcessTimes(SafeProcessHandle process, out long created, out long exited, out long kernel, out long user);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetExitCodeProcess(SafeProcessHandle process, out uint exitCode);
}

// Read only appended records, not a historical replay of alerts. Bounded work per tick and record.
internal sealed class JsonTail(string path)
{
    public static List<AccessEvent> Recent(string path)
    {
        var events = new List<AccessEvent>();
        foreach (string source in new[] { path + ".1", path })
        {
            try
            {
                using var stream = new FileStream(source, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                long start = Math.Max(0, stream.Length - 1024 * 1024);
                stream.Position = start;
                byte[] bytes = new byte[(int)(stream.Length - start)];
                stream.ReadExactly(bytes);
                int first = start > 0 ? Array.IndexOf(bytes, (byte)'\n') + 1 : 0;
                int last = Array.LastIndexOf(bytes, (byte)'\n');
                if (last <= first) continue;
                var parser = new Telemetry();
                foreach (string line in Utf8.GetString(bytes, first, last - first).Split('\n'))
                    if (parser.Accept(line) is { } item) events.Add(item);
                if (events.Count > 200) events.RemoveRange(0, events.Count - 200);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or DecoderFallbackException) { }
        }
        return events;
    }
    private long position;
    private string? identity;
    private bool first = true, discard;
    private readonly List<byte> pending = [];
    public string? Error { get; private set; }
    public int Oversize { get; private set; }
    public bool Reset { get; private set; }
    private static readonly UTF8Encoding Utf8 = new(false, true);

    [StructLayout(LayoutKind.Sequential)]
    private struct FileInfo
    {
        public uint Attributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME Creation, Access, Write;
        public uint Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
    }
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out FileInfo info);

    public List<string> Poll()
    {
        var lines = new List<string>(); Reset = false; Error = null;
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            if (!GetFileInformationByHandle(stream.SafeFileHandle, out var info)) throw new IOException("ログの識別に失敗しました");
            string current = $"{info.Volume}:{info.IndexHigh}:{info.IndexLow}:{info.Creation.dwHighDateTime}:{info.Creation.dwLowDateTime}";
            if (first)
            {
                first = false; identity = current; position = stream.Length;
                if (position > 0) { stream.Position = position - 1; discard = stream.ReadByte() != '\n'; }
                return lines;
            }
            if (identity != current || stream.Length < position)
            { identity = current; position = 0; pending.Clear(); discard = false; Reset = true; }
            stream.Position = position;
            byte[] buffer = new byte[128 * 1024];
            int count = stream.Read(buffer, 0, buffer.Length);
            position += count;
            for (int i = 0; i < count; i++)
            {
                byte value = buffer[i];
                if (value == '\n')
                {
                    if (!discard && pending.Count > 0)
                    {
                        try { lines.Add(Utf8.GetString(pending.ToArray()).TrimEnd('\r')); }
                        catch (DecoderFallbackException) { Error = "ログに不正な UTF-8 レコードがあります"; }
                    }
                    discard = false; pending.Clear();
                }
                else if (!discard)
                {
                    pending.Add(value);
                    if (pending.Count > 64 * 1024) { pending.Clear(); discard = true; Oversize++; }
                }
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Error = "イベントログ未接続 / 読み取り不可";
            Reset = true;
            // Resume the same identity after transient errors; never replay old alerts.
        }
        return lines;
    }
}
