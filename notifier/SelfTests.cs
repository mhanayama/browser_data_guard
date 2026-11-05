using System.Diagnostics;
using System.Text;
using System.Text.Json;

namespace Bdg.Tray;

internal static class SelfTests
{
    public static int Run()
    {
        int checks = 0;
        void Check(bool condition, string label)
        { if (!condition) throw new InvalidOperationException(label); checks++; }
        string scratch = Path.Combine(Path.GetTempPath(), "BDG-TrayTests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(scratch);
        string Put(string relative, string text = "fixture")
        {
            string path = Path.Combine(scratch, relative); Directory.CreateDirectory(Path.GetDirectoryName(path)!); File.WriteAllText(path, text); return path;
        }
        try
        {
            var telemetry = new Telemetry();
            string access = JsonSerializer.Serialize(new { type = "access", timestamp = DateTimeOffset.UtcNow, sequence = 7, pid = 42,
                processName = "probe.exe", executablePath = @"C:\lab\probe.exe", target = @"C:\lab\日本語\Cookie", browser = "Synthetic", category = "TestData", decision = "deny" });
            var item = telemetry.Accept(access);
            Check(item is { Decision: "deny", Pid: 42, Sequence: 7 } && item.Target.Contains("日本語"), "deny record + UTF-8");
            Check(telemetry.Accept(access.Replace("deny", "allow"))?.Decision == "allow", "allow record");
            string nameFailure = JsonSerializer.Serialize(new { type = "access", timestamp = DateTimeOffset.UtcNow, decision = "deny", target = "", reason = 2, flags = 1 });
            Check(telemetry.Accept(nameFailure) is { Reason: 2, Flags: 1, Target: "名前取得失敗・対象パス不明" }, "name-query failures still alert");
            Check(telemetry.Accept(access.Replace("deny", "unknown")) == null, "reject unknown decision");
            foreach (string bad in new[] { "{", "[]", "null", "{\"type\":\"access\",\"pid\":{}}", access.Replace("\"pid\":42", "\"pid\":\"bad\"") }) telemetry.Accept(bad);
            Check(telemetry.Invalid == 6, "malformed records isolated");
            DateTimeOffset now = DateTimeOffset.UtcNow;
            using var process = Process.GetCurrentProcess();
            string Heartbeat(DateTimeOffset time, long start) => JsonSerializer.Serialize(new { type = "heartbeat", timestamp = time,
                mode = "synthetic", armed = true, servicePid = process.Id, serviceStart = start });
            long birth = process.StartTime.ToUniversalTime().ToFileTimeUtc();
            telemetry.Accept(Heartbeat(now, birth));
            Check(telemetry.Fresh(now) && telemetry.ServiceAlive(now), "fresh heartbeat bound to live process");
            Check(!telemetry.Fresh(now.AddSeconds(9)), "heartbeat expiry");
            Check(!telemetry.Fresh(now.AddSeconds(-3)), "future heartbeat rejected");
            telemetry.Accept(Heartbeat(now, birth - 1));
            Check(!telemetry.ServiceAlive(now), "PID reuse / start mismatch");
            telemetry.Accept("{\"type\":\"stopped\"}"); Check(!telemetry.Fresh(now), "clean stop clears health");
            telemetry.Accept("{\"type\":\"status\",\"armed\":true}"); Check(!telemetry.Fresh(now), "old status cannot show healthy");
            telemetry.Accept("{\"type\":\"audit_loss\",\"lostEvents\":33}");
            telemetry.Accept("{\"type\":\"audit_loss\",\"lostEvents\":1}"); Check(telemetry.Lost == 33, "loss stays visible");
            string observeHeartbeat = Heartbeat(now, birth).Replace("synthetic", "observe-etw").TrimEnd('}') + ",\"observing\":true,\"ruleCount\":140,\"eventsReceived\":100,\"eventsMatched\":5}";
            telemetry.Accept(observeHeartbeat);
            Check(telemetry.Fresh(now) && !telemetry.Armed && telemetry.Observing && telemetry.RuleCount == 140, "ETW monitoring never implies enforcement");
            Check(telemetry.EventsReceived == 100 && telemetry.EventsMatched == 5, "ETW counters");
            string observeAccess = access.Replace("\"decision\":\"deny\"", "\"decision\":\"observe\",\"source\":\"etw\",\"operation\":\"read\",\"count\":7");
            Check(telemetry.Accept(observeAccess) is { Decision: "observe", Operation: "read", Count: 7 }, "observation distinguished from deny");
            Check(telemetry.Accept(access.Replace("deny", "observe")) == null, "observation requires explicit source");
            telemetry.Disconnect(); Check(!telemetry.Fresh(now) && !telemetry.Observing, "observation disconnect");
            string exported = HistoryLog.Format([item! with { Target = "path\nforged entry" }, item! with { Demo = true }], now);
            var exportLines = exported.Split(Environment.NewLine, StringSplitOptions.RemoveEmptyEntries);
            Check(exportLines.Length == 3, "export metadata cannot inject extra records");
            using (var exportEntry = JsonDocument.Parse(exportLines[1])) Check(exportEntry.RootElement.GetProperty("target").GetString() == "path\nforged entry", "export path round trip");
            using (var exportEntry = JsonDocument.Parse(exportLines[2])) Check(exportEntry.RootElement.GetProperty("decision").GetString() == "display-test", "export labels demo separately");

            string log = Put("telemetry.jsonl", access + "\n");
            Check(JsonTail.Recent(log).Single() is { Decision: "deny", Sequence: 7 }, "persisted history available without live alert replay");
            var tail = new JsonTail(log); Check(tail.Poll().Count == 0, "no historical alerts");
            File.AppendAllText(log, access[..20]); Check(tail.Poll().Count == 0, "partial line waits");
            File.AppendAllText(log, access[20..] + "\n"); Check(tail.Poll().Single() == access, "partial record reconstructed");
            byte[] utf8 = Encoding.UTF8.GetBytes("日本語\n");
            using (var stream = new FileStream(log, FileMode.Append)) stream.Write(utf8, 0, 1);
            Check(tail.Poll().Count == 0, "partial UTF-8 waits");
            using (var stream = new FileStream(log, FileMode.Append)) stream.Write(utf8, 1, utf8.Length - 1);
            Check(tail.Poll().Single() == "日本語", "split UTF-8 reconstructed");
            File.AppendAllText(log, new string('x', 65537) + "\n" + access + "\n");
            Check(tail.Poll().Single() == access && tail.Oversize == 1, "oversize record dropped and recovery");
            File.WriteAllText(log, "new\n"); Check(tail.Poll().Single() == "new" && tail.Reset, "truncation resets health");
            File.Move(log, log + ".old"); File.WriteAllText(log, "rotated\n");
            Check(tail.Poll().Single() == "rotated" && tail.Reset, "replacement file identity");
            File.Delete(log); Check(tail.Poll().Count == 0 && tail.Error != null && tail.Reset, "missing log disconnects");
            string startupPartial = Put("partial.jsonl", "old partial");
            var partial = new JsonTail(startupPartial); partial.Poll();
            File.AppendAllText(startupPartial, " rest\nnew\n"); Check(partial.Poll().Single() == "new", "startup partial not replayed");

            string home = Path.Combine(scratch, "home"), local = Path.Combine(home, @"AppData\Local"), roaming = Path.Combine(home, @"AppData\Roaming");
            string prefix = Path.GetRelativePath(scratch, home);
            string localState = Put(Path.Combine(prefix, @"AppData\Local\Google\Chrome\User Data\Local State"), "contents must not be read");
            string cookie = Put(Path.Combine(prefix, @"AppData\Local\Google\Chrome\User Data\Work\Network\Cookies"));
            string customProfile = Put(Path.Combine(prefix, @"AppData\Local\Google\Chrome\User Data\Other\Preferences"));
            Put(Path.Combine(prefix, @"AppData\Roaming\Mozilla\Firefox\profiles.ini"), "[Profile0]\nPath=Profiles/test\nIsRelative=1\n[Profile1]\nPath=../../escape\nIsRelative=1");
            Put(Path.Combine(prefix, @"AppData\Roaming\Mozilla\Firefox\Profiles\test\cookies.sqlite"));
            Directory.CreateDirectory(Path.Combine(roaming, @"Mozilla\Firefox\Profiles\test\storage\default\https+++example.test\ls"));
            Directory.CreateDirectory(Path.Combine(roaming, @"Mozilla\Firefox\Profiles\test\storage\default\https+++example.test\idb"));
            string auth = Put(Path.Combine(prefix, @".codex\auth.json"), "not JSON, contents must not be parsed");
            string key = Put(Path.Combine(prefix, @".ssh\id_ed25519"), "not a key, contents must not be read");
            Put(Path.Combine(prefix, @".ssh\id_ed25519.pub"));
            Put(Path.Combine(prefix, @".ssh\known_hosts"));
            Put(Path.Combine(prefix, @".aws\credentials"));
            Put(Path.Combine(prefix, @"AppData\Roaming\ChatGPT\Partitions\account\Network\Cookies"));
            Put(Path.Combine(prefix, @"AppData\Local\Packages\OpenAI.Codex_test\LocalCache\Roaming\Codex\Local Storage\leveldb\CURRENT"));
            // FileShare.None makes any accidental attempt to read a secret fail.
            using var lockedAuth = new FileStream(auth, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
            using var lockedKey = new FileStream(key, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
            using var lockedCookie = new FileStream(cookie, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
            using var lockedLocalState = new FileStream(localState, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
            var inventory = new Discovery(new(home, local, roaming)).Scan([new("Custom", "API", Path.Combine(home, "secrets.env"), false, false), new("Custom", "duplicate", cookie, false, true)]);
            var list = inventory.Targets;
            Check(list.Any(x => x.Path == cookie), "locked cookie discovered without read");
            Check(list.Any(x => x.Path == cookie + "-wal" && !x.Exists), "future SQLite companions included");
            Check(list.Any(x => x.Path.StartsWith(Path.GetDirectoryName(customProfile)!) && x.Category == "Local Storage"), "non-default Chromium profile");
            Check(!list.Any(x => x.Path.Contains("escape")), "manifest path traversal ignored");
            Check(list.Any(x => x.Application == "Firefox" && x.Path.EndsWith("cookies.sqlite")), "Firefox relative manifest");
            Check(list.Any(x => x.Application == "Firefox" && x.Path.EndsWith(@"example.test\ls") && x.Subtree), "Firefox local storage scoped");
            Check(!list.Any(x => x.Path.EndsWith(@"example.test\idb")), "Firefox IDB not mislabelled local storage");
            Check(list.Any(x => x.Path == auth && x.Exists), "Codex auth metadata only");
            Check(list.Any(x => x.Path == localState && x.Exists) && inventory.Diagnostics.All(x => !x.Contains("一覧を読めません")), "Chromium key material never read");
            Check(list.Any(x => x.Path == key) && !list.Any(x => x.Path.EndsWith(".pub") || x.Path.EndsWith("known_hosts")), "SSH key filename candidates only");
            Check(list.Any(x => x.Application == "AWS"), "API credential path");
            Check(list.Any(x => x.Application.StartsWith("ChatGPT") && x.Path.EndsWith(@"Network\Cookies")), "Electron partition discovery");
            Check(list.Any(x => x.Application.StartsWith("Codex (") && x.Category == "Local Storage"), "packaged embedded browser discovery");
            Check(list.Any(x => x.Application == "Custom" && !x.Exists), "custom future target");
            Check(list.Single(x => x.Application == "Custom" && !x.Exists).Manual && !list.Single(x => x.Path == cookie).Manual, "standard target cannot become removable through duplicate manual registration");
            Check(list.Select(x => x.Path).Distinct(StringComparer.OrdinalIgnoreCase).Count() == list.Count, "deduplicated targets");
            try { Discovery.LocalPath(@"\\server\share\secret"); Check(false, "UNC accepted"); } catch (IOException) { Check(true, "UNC rejected"); }
            try { Discovery.LocalPath(@"C:\secret:stream"); Check(false, "ADS accepted"); } catch (IOException) { Check(true, "ADS rejected"); }
            Console.WriteLine($"BDG notifier: {checks} checks passed.");
            return 0;
        }
        catch (Exception ex) { Console.Error.WriteLine($"BDG notifier test failed after {checks} checks: {ex}"); return 1; }
        finally
        {
            string absolute = Path.GetFullPath(scratch);
            if (absolute.StartsWith(Path.GetFullPath(Path.GetTempPath()), StringComparison.OrdinalIgnoreCase) && Path.GetFileName(absolute).StartsWith("BDG-TrayTests-", StringComparison.Ordinal))
                Directory.Delete(absolute, true);
        }
    }
}
