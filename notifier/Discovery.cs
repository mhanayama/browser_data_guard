namespace Bdg.Tray;

internal sealed record Target(string Application, string Category, string Path, bool Subtree, bool Exists,
    string Note = "保存場所の候補・未保護", bool Manual = false);
internal sealed record Inventory(List<Target> Targets, List<string> Diagnostics);
internal sealed record Locations(string Home, string Local, string Roaming, string? Codex = null)
{
    public static Locations Current => new(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), Environment.GetEnvironmentVariable("CODEX_HOME"));
}

// Metadata only. Secret files, databases, key files, .env and application settings are NEVER opened.
// The only content reads in this class are bounded Firefox profile-location INI manifests.
// Chromium Local State can contain encryption material: register its path but do not read it.
internal sealed class Discovery(Locations locations)
{
    private readonly List<Target> targets = [];
    private readonly List<string> diagnostics = [];
    private readonly HashSet<string> seen = new(StringComparer.OrdinalIgnoreCase);
    private static readonly string[] SqlSuffixes = ["", "-wal", "-shm", "-journal"];

    public Inventory Scan(IEnumerable<Target>? custom = null)
    {
        Chromium("Chrome", Path.Combine(locations.Local, @"Google\Chrome\User Data"));
        Chromium("Edge", Path.Combine(locations.Local, @"Microsoft\Edge\User Data"));
        Firefox(Path.Combine(locations.Roaming, @"Mozilla\Firefox"));
        var codex = locations.Codex ?? Path.Combine(locations.Home, ".codex");
        Add("Codex", "認証ファイル", Path.Combine(codex, "auth.json"), false,
            "ファイル方式の認証キャッシュ候補。OS 資格情報ストアは対象外");
        foreach (var file in new[] { ".credentials.json", "mcp-auth.json" })
            Existing("Codex", "追加の認証ファイル候補", Path.Combine(codex, file));
        Ssh(Path.Combine(locations.Home, ".ssh"));
        foreach (var item in new[] {
            ("AWS", @".aws\credentials"), ("AWS", @".aws\sso\cache"), ("AWS", @".aws\cli\cache"),
            ("Azure", @".azure\accessTokens.json"), ("Azure", @".azure\msal_token_cache.bin"),
            ("Azure", @".azure\msal_token_cache.json"), ("Google Cloud", @"AppData\Roaming\gcloud\application_default_credentials.json"),
            ("npm", ".npmrc"), ("Python", ".pypirc"), ("Docker", @".docker\config.json"),
            ("Git", ".git-credentials") })
            Existing(item.Item1, "API / 認証ファイル候補", Path.Combine(locations.Home, item.Item2));
        foreach (var variable in new[] { "AWS_SHARED_CREDENTIALS_FILE", "GOOGLE_APPLICATION_CREDENTIALS" })
        {
            var configured = Environment.GetEnvironmentVariable(variable);
            if (!string.IsNullOrWhiteSpace(configured)) Existing(variable, "指定された認証ファイル候補", configured);
        }
        bool KnownApp(string path) => AppName(Path.GetFileName(path)) != null;
        foreach (var root in Children(locations.Roaming, KnownApp).Concat(Children(locations.Local, KnownApp)))
            if (AppName(Path.GetFileName(root)) is { } name) Embedded(name, root);
        foreach (var root in Children(Path.Combine(locations.Local, "Packages"), KnownApp))
            if (AppName(Path.GetFileName(root)) is { } name) Embedded(name, root);
        if (custom != null) foreach (var target in custom.Take(200))
            Add(target.Application, target.Category, target.Path, target.Subtree, "手動登録した候補・未保護", true);
        return new(targets.OrderBy(x => x.Application).ThenBy(x => x.Path).ToList(), diagnostics);
    }

    private static string? AppName(string name)
    {
        if (name.Contains("ChatGPT", StringComparison.OrdinalIgnoreCase)) return "ChatGPT (内蔵ブラウザー)";
        if (name.Contains("Codex", StringComparison.OrdinalIgnoreCase)) return "Codex (内蔵ブラウザー)";
        return null;
    }

    internal static string LocalPath(string input)
    {
        if (!Path.IsPathFullyQualified(input) || input.StartsWith(@"\\", StringComparison.Ordinal) || input.Length > 30000)
            throw new IOException("ローカル絶対パスが必要です");
        var result = Path.GetFullPath(input);
        if (result.AsSpan(3).Contains(':')) throw new IOException("代替ストリームは登録できません");
        return Path.TrimEndingDirectorySeparator(result);
    }

    private bool Safe(string path)
    {
        try
        {
            for (string? current = LocalPath(path); current != null; current = Path.GetDirectoryName(current))
                if (File.Exists(current) || Directory.Exists(current))
                    if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                    { diagnostics.Add($"リンク先は未確認: {path}"); return false; }
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        { diagnostics.Add($"保存場所を確認できません: {path}"); return false; }
    }

    private void Add(string app, string category, string path, bool subtree = false, string note = "保存場所の候補・未保護", bool manual = false)
    {
        if (!Safe(path)) return;
        path = LocalPath(path);
        if (seen.Add(path)) targets.Add(new(app, category, path, subtree, File.Exists(path) || Directory.Exists(path), note, manual));
    }
    private void Existing(string app, string category, string path)
    {
        if (File.Exists(path) || Directory.Exists(path)) Add(app, category, path, Directory.Exists(path));
    }
    private string[] Children(string root, Func<string, bool>? include = null)
    {
        if (!Directory.Exists(root) || !Safe(root)) return [];
        try
        {
            var entries = Directory.EnumerateDirectories(root).Take(513).ToArray();
            if (entries.Length > 512) diagnostics.Add($"フォルダー列挙の上限に達しました: {root}");
            return entries.Take(512).Where(p => include == null || include(p)).Where(Safe).ToArray();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        { diagnostics.Add($"フォルダーを列挙できません: {root}"); return []; }
    }
    private string? Manifest(string path)
    {
        if (!File.Exists(path) || !Safe(path)) return null;
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            if (stream.Length > 4 * 1024 * 1024) throw new IOException("manifest too large");
            using var reader = new StreamReader(stream, detectEncodingFromByteOrderMarks: true);
            var buffer = new char[2 * 1024 * 1024 + 1];
            int length = reader.ReadBlock(buffer, 0, buffer.Length);
            if (length == buffer.Length) throw new IOException("manifest too large");
            return new string(buffer, 0, length);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        { diagnostics.Add($"プロファイル一覧を読めません: {path}"); return null; }
    }
    private void Sql(string app, string category, string path)
    { foreach (string suffix in SqlSuffixes) Add(app, category, path + suffix); }

    private bool ChromiumEvidence(string path) => File.Exists(Path.Combine(path, "Preferences")) ||
        File.Exists(Path.Combine(path, @"Network\Cookies")) || File.Exists(Path.Combine(path, "Cookies")) ||
        Directory.Exists(Path.Combine(path, @"Local Storage\leveldb"));

    private void ChromiumProfile(string app, string profile)
    {
        if (!Directory.Exists(profile) || !Safe(profile)) return;
        Sql(app, "Cookie", Path.Combine(profile, @"Network\Cookies"));
        Sql(app, "Cookie (旧配置)", Path.Combine(profile, "Cookies"));
        Add(app, "Local Storage", Path.Combine(profile, @"Local Storage\leveldb"), true);
    }
    private void Chromium(string app, string root)
    {
        if (!Directory.Exists(root) || !Safe(root)) return;
        Add(app, "プロファイル設定 / 暗号鍵の保存候補", Path.Combine(root, "Local State"));
        foreach (string profile in Children(root).Where(ChromiumEvidence)) ChromiumProfile(app, profile);
    }

    private void Firefox(string root)
    {
        if (!Directory.Exists(root) || !Safe(root)) return;
        var profiles = new HashSet<string>(Children(Path.Combine(root, "Profiles")), StringComparer.OrdinalIgnoreCase);
        foreach (string name in new[] { "profiles.ini", "installs.ini" })
        {
            var manifest = Manifest(Path.Combine(root, name));
            if (manifest == null) continue;
            var section = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            void Flush()
            {
                string? candidate = section.GetValueOrDefault("Path") ?? section.GetValueOrDefault("Default");
                if (!string.IsNullOrWhiteSpace(candidate) && candidate != "0" && candidate != "1")
                {
                    try
                    {
                        string full = Path.GetFullPath(candidate, root);
                        bool relative = section.GetValueOrDefault("IsRelative") != "0" && !Path.IsPathFullyQualified(candidate);
                        if (!relative || full.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) profiles.Add(full);
                        else diagnostics.Add("Firefox の相対パスが保存先外を指しています");
                    }
                    catch (ArgumentException) { diagnostics.Add("Firefox のプロファイルパスが不正です"); }
                }
                section.Clear();
            }
            foreach (var line in manifest.Split('\n').Select(x => x.Trim()))
            {
                if (line.StartsWith('[')) { Flush(); continue; }
                if (line.StartsWith(';') || line.StartsWith('#')) continue;
                int equal = line.IndexOf('=');
                if (equal > 0) section[line[..equal].Trim()] = line[(equal + 1)..].Trim();
            }
            Flush();
        }
        foreach (string profile in profiles.Where(p => Directory.Exists(p) && Safe(p)))
        {
            Sql("Firefox", "Cookie", Path.Combine(profile, "cookies.sqlite"));
            Sql("Firefox", "Local Storage (旧配置)", Path.Combine(profile, "webappsstore.sqlite"));
            Sql("Firefox", "Local Storage", Path.Combine(profile, @"storage\ls-archive.sqlite"));
            foreach (string origin in Children(Path.Combine(profile, @"storage\default")))
                if (Directory.Exists(Path.Combine(origin, "ls"))) Add("Firefox", "Local Storage", Path.Combine(origin, "ls"), true);
        }
    }

    private void Ssh(string root)
    {
        if (!Directory.Exists(root) || !Safe(root)) return;
        try
        {
            foreach (string file in Directory.EnumerateFiles(root).Take(512))
            {
                var name = Path.GetFileName(file);
                if (name.EndsWith(".pub", StringComparison.OrdinalIgnoreCase) || name.EndsWith("-cert.pub", StringComparison.OrdinalIgnoreCase)) continue;
                if (name.StartsWith("id_", StringComparison.OrdinalIgnoreCase) || name.EndsWith(".pem", StringComparison.OrdinalIgnoreCase) ||
                    name.EndsWith(".ppk", StringComparison.OrdinalIgnoreCase))
                    Add("SSH", "秘密鍵のファイル名候補", file, false, "内容未確認。独自名の鍵は手動登録してください");
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { diagnostics.Add("SSH の保存先を列挙できません"); }
    }

    private void Embedded(string app, string root)
    {
        int visited = 0;
        var queue = new Queue<(string Path, int Depth)>();
        queue.Enqueue((root, 0));
        while (queue.Count > 0 && visited++ < 2048)
        {
            var (path, depth) = queue.Dequeue();
            if (ChromiumEvidence(path)) ChromiumProfile(app, path);
            Existing(app, "プロファイル設定 / 暗号鍵の保存候補", Path.Combine(path, "Local State"));
            if (depth >= 8) continue;
            foreach (string child in Children(path, p => !new[] { "Cache", "Code Cache", "GPUCache", "node_modules", "logs", "sessions", "plugins", "attachments", "IndexedDB", "Local Storage", "Network" }
                .Contains(Path.GetFileName(p), StringComparer.OrdinalIgnoreCase)))
            {
                queue.Enqueue((child, depth + 1));
            }
        }
        if (queue.Count > 0) diagnostics.Add($"探索上限に達しました。独自の保存先は手動登録してください: {root}");
        if (!targets.Any(t => t.Application == app)) diagnostics.Add($"既知の内蔵ブラウザー配置は未確認: {app}");
    }
}
