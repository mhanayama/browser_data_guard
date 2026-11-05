using System.Text.Json;

namespace Bdg.Tray;

internal static class Program
{
    internal static string? StartupLog { get; private set; }
    internal static void Stage(string message)
    {
        if (StartupLog == null) return;
        try { File.WriteAllText(StartupLog, DateTimeOffset.Now.ToString("O") + " " + message); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
    }
    [STAThread]
    private static int Main(string[] args)
    {
        bool background = args.Contains("--background");
        try
        {
            if (args.Contains("--self-test")) return SelfTests.Run();
            string state = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "BrowserDataGuard");
            string? log = null, inventory = null, policy = null;
            bool test = false, quiet = false;
            int runSeconds = 0;
            for (int i = 0; i < args.Length; i++)
            {
                string Value() => ++i < args.Length ? args[i] : throw new ArgumentException("引数が不足しています");
                switch (args[i])
                {
                    case "--state-dir": state = Discovery.LocalPath(Value()); break;
                    case "--log": log = Discovery.LocalPath(Value()); break;
                    case "--inventory": inventory = Discovery.LocalPath(Value()); break;
                    case "--export-monitor-policy": policy = Discovery.LocalPath(Value()); break;
                    case "--background": background = true; break;
                    case "--no-popups": quiet = true; break;
                    case "--run-seconds":
                        if (!int.TryParse(Value(), out runSeconds) || runSeconds is < 1 or > 86400) throw new ArgumentException("実行時間は 1〜86400 秒で指定してください");
                        break;
                    case "--test-alert": test = true; break;
                    default: throw new ArgumentException("不明な引数: " + args[i]);
                }
            }
            if (quiet && test) throw new ArgumentException("--no-popups と --test-alert は同時に指定できません");
            if (policy != null)
            {
                List<Target>? custom = null;
                string customFile = Path.Combine(state, "custom-targets.json");
                if (File.Exists(customFile))
                {
                    if (new FileInfo(customFile).Length > 1024 * 1024) throw new IOException("登録一覧が大きすぎます");
                    custom = JsonSerializer.Deserialize<List<Target>>(File.ReadAllText(customFile));
                }
                var found = new Discovery(Locations.Current).Scan(custom);
                var rows = found.Targets.Select(t => string.Join('\t', t.Subtree ? "tree" : "file", t.Application, t.Category, t.Path));
                if (found.Targets.Any(t => (t.Application + t.Category + t.Path).IndexOfAny(['\t','\r','\n']) >= 0))
                    throw new IOException("監視ルールにタブまたは改行を含む保存場所があります");
                File.WriteAllText(policy, "BDG-OBSERVE-1\n" + string.Join('\n', rows) + "\n", new System.Text.UTF8Encoding(false));
                return 0;
            }
            if (inventory != null)
            {
                File.WriteAllText(inventory, JsonSerializer.Serialize(new Discovery(Locations.Current).Scan(), new JsonSerializerOptions { WriteIndented = true }));
                return 0;
            }
            using var mutex = new Mutex(true, @"Local\BrowserDataGuard.Tray." + Environment.UserName, out bool created);
            if (!created)
            {
                if (!background) MessageBox.Show("BDG は既に通知領域で実行中です。アイコンをダブルクリックしてください。", "Browser Data Guard");
                return 0;
            }
            Directory.CreateDirectory(state);
            StartupLog = Path.Combine(state, "startup.txt");
            Stage("Initializing desktop application");
            ApplicationConfiguration.Initialize();
            Stage("Creating notification window");
            using var context = new TrayContext(log ?? Path.Combine(state, "events.jsonl"), state, background, test, quiet, runSeconds);
            Stage("Running notification loop");
            Application.Run(context);
            return 0;
        }
        catch (Exception ex)
        {
            Stage("Startup failed: " + ex.GetType().Name + ": " + ex.Message);
            if (background) Console.Error.WriteLine("BDG: " + ex.Message);
            else MessageBox.Show(ex.Message, "BDG を開始できません", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return 1;
        }
    }
}
