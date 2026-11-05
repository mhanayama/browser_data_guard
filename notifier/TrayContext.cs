using System.Text.Json;

namespace Bdg.Tray;

internal sealed class TrayContext : ApplicationContext
{
    private readonly NotifyIcon icon;
    private readonly Form dashboard;
    private readonly Label service, summary;
    private readonly DataGridView targets, history;
    private readonly TextBox diagnostics;
    private readonly System.Windows.Forms.Timer timer = new() { Interval = 500 };
    private readonly Telemetry telemetry = new();
    private readonly JsonTail tail;
    private readonly List<Target> custom = [];
    private readonly string customPath;
    private bool scanning, quitting, hideTip, popups = true;
    private DateTimeOffset nextScan;
    private AlertForm? alert;
    private int denied;
    private long observed;
    private string inventoryNotes = "";
    private readonly string runtimePath;
    private readonly long started = Environment.TickCount64;
    private readonly int runSeconds;
    private long nextReport;
    private int ticks;
    private static readonly Color Navy = Color.FromArgb(21, 35, 56);
    private static readonly Color Amber = Color.FromArgb(255, 219, 139);

    public TrayContext(string logPath, string state, bool background, bool test, bool quiet, int runSeconds)
    {
        popups = !quiet; this.runSeconds = runSeconds;
        runtimePath = Path.Combine(state, "runtime.json");
        tail = new(logPath); customPath = Path.Combine(state, "custom-targets.json");
        try
        {
            if (File.Exists(customPath))
            {
                if (new FileInfo(customPath).Length > 1024 * 1024) throw new IOException("登録一覧が大きすぎます");
                custom.AddRange(JsonSerializer.Deserialize<List<Target>>(File.ReadAllText(customPath))?.Take(200) ?? []);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        { inventoryNotes = "手動登録の一覧を読めません。設定ファイルを確認してください。\r\n"; }

        dashboard = new Form { Text = "Browser Data Guard", Size = new(1080, 760), MinimumSize = new(850, 620),
            StartPosition = FormStartPosition.CenterScreen, BackColor = Color.FromArgb(245, 247, 250),
            Font = new Font("Yu Gothic UI", 10), Icon = SystemIcons.Shield };
        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 6, Padding = new(20) };
        layout.RowStyles.Add(new(SizeType.Absolute, 74)); layout.RowStyles.Add(new(SizeType.Absolute, 65));
        layout.RowStyles.Add(new(SizeType.Absolute, 46)); layout.RowStyles.Add(new(SizeType.Absolute, 50));
        layout.RowStyles.Add(new(SizeType.Percent, 100)); layout.RowStyles.Add(new(SizeType.Absolute, 64));
        dashboard.Controls.Add(layout);
        Program.Stage("Creating dashboard controls");
        var heading = new Panel { Dock = DockStyle.Fill, BackColor = Navy, Padding = new(14, 8, 14, 8) };
        heading.Controls.Add(new Label { Text = "BROWSER DATA GUARD\n認証情報の保存場所とアクセス通知", ForeColor = Color.White,
            Font = new Font("Yu Gothic UI", 14, FontStyle.Bold), Dock = DockStyle.Fill });
        layout.Controls.Add(heading, 0, 0);
        service = new Label { Dock = DockStyle.Fill, BackColor = Amber, Padding = new(12, 6, 8, 4), AutoEllipsis = true };
        layout.Controls.Add(service, 0, 1);
        var pages = new Panel { Dock = DockStyle.Fill };
        var pageList = new List<Panel>();
        var navigationButtons = new List<Button>();
        void ShowPage(int index)
        {
            for (int i = 0; i < pageList.Count; i++)
            {
                pageList[i].Visible = i == index;
                navigationButtons[i].BackColor = i == index ? Navy : Color.White;
                navigationButtons[i].ForeColor = i == index ? Color.White : Navy;
            }
            pageList[index].BringToFront();
        }
        var navigation = new FlowLayoutPanel { Dock = DockStyle.Fill, WrapContents = false, Padding = new(0, 6, 0, 0) };
        foreach (var entry in new[] { (Text: "対象一覧", Index: 0), (Text: "履歴一覧", Index: 1), (Text: "状態", Index: 2) })
        {
            var button = new Button { Text = entry.Text, Width = 130, Height = 34, FlatStyle = FlatStyle.Flat,
                UseVisualStyleBackColor = false, Font = new Font("Yu Gothic UI", 11, FontStyle.Bold) };
            button.Click += (_, _) => ShowPage(entry.Index);
            navigationButtons.Add(button);
            navigation.Controls.Add(button);
        }
        layout.Controls.Add(navigation, 0, 2);
        var commands = new FlowLayoutPanel { Dock = DockStyle.Fill, WrapContents = false, AutoScroll = true, Padding = new(0, 7, 0, 0) };
        Button Action(string text, Action action)
        {
            var button = new Button { Text = text, AutoSize = true, Height = 32, FlatStyle = FlatStyle.Flat, BackColor = Color.White };
            button.Click += (_, _) => action(); commands.Controls.Add(button); return button;
        }
        Action("再スキャン", () => _ = Scan());
        Action("ファイルを追加", AddFile);
        Action("フォルダーを追加", AddFolder);
        Action("手動登録を解除", RemoveCustom);
        Action("履歴を .log に保存", ExportHistory);
        Action("通知表示テスト", Demo);
        Action("通知領域へ", () => dashboard.Hide());
        layout.Controls.Add(commands, 0, 3);
        var targetTab = new Panel { Dock = DockStyle.Fill, AccessibleName = "対象一覧" };
        targets = Grid([("Application", "アプリ", 150), ("Category", "種類", 200), ("Exists", "存在確認", 85), ("Path", "保存場所", 460), ("Note", "補足", 340)]);
        targetTab.Controls.Add(targets); pages.Controls.Add(targetTab); pageList.Add(targetTab);
        var historyTab = new Panel { Dock = DockStyle.Fill, AccessibleName = "履歴一覧" };
        history = Grid([("Time", "時刻", 150), ("Decision", "結果", 110), ("Process", "プロセス", 150), ("Browser", "対象アプリ", 150), ("Category", "種類", 160), ("Target", "対象パス", 400)]);
        history.AccessibleName = "アクセス履歴（直近200件・ダブルクリックで詳細）";
        historyTab.Controls.Add(history); pages.Controls.Add(historyTab); pageList.Add(historyTab);
        history.CellDoubleClick += (_, e) => { if (e.RowIndex >= 0 && history.Rows[e.RowIndex].Tag is AccessEvent item) ShowEvent(item); };
        var diagnosticsTab = new Panel { Dock = DockStyle.Fill, AccessibleName = "状態" };
        diagnostics = new TextBox { Dock = DockStyle.Fill, Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Both,
            BackColor = Color.White, WordWrap = false };
        diagnosticsTab.Controls.Add(diagnostics); pages.Controls.Add(diagnosticsTab); pageList.Add(diagnosticsTab);
        layout.Controls.Add(pages, 0, 4);
        ShowPage(1);
        summary = new Label { Dock = DockStyle.Fill, Padding = new(0, 6, 0, 0), ForeColor = Navy };
        layout.Controls.Add(summary, 0, 5);
        Program.Stage("Creating tray icon");
        var menu = new ContextMenuStrip();
        menu.Items.Add("状態・履歴を開く", null, (_, _) => ShowDashboard());
        menu.Items.Add("通知表示テスト", null, (_, _) => Demo());
        menu.Items.Add("履歴を .log に保存", null, (_, _) => ExportHistory());
        var toggle = new ToolStripMenuItem("拒否時にアラート画面を表示") { Checked = popups, CheckOnClick = true };
        toggle.CheckedChanged += (_, _) => popups = toggle.Checked; menu.Items.Add(toggle);
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("BDG 通知を終了", null, (_, _) => ExitThread());
        icon = new NotifyIcon { Icon = SystemIcons.Shield, Text = "BDG: 対象候補は未保護", Visible = true, ContextMenuStrip = menu };
        icon.DoubleClick += (_, _) => ShowDashboard();
        dashboard.FormClosing += (_, e) =>
        {
            if (quitting || e.CloseReason != CloseReason.UserClosing) return;
            e.Cancel = true; dashboard.Hide();
            if (!hideTip) { hideTip = true; icon.ShowBalloonTip(3000, "Browser Data Guard", "通知領域に常駐しています。アイコンをダブルクリックすると状態画面を開きます。", ToolTipIcon.Info); }
        };
        timer.Tick += (_, _) => Tick();
        tail.Poll(); // Establish the live cursor before reading a bounded historical snapshot.
        foreach (var item in JsonTail.Recent(logPath)) Receive(item, true);
        timer.Start();
        Program.Stage("Starting telemetry reader");
        Tick();
        Program.Stage("Showing dashboard");
        if (!background) dashboard.Show();
        Program.Stage("Starting discovery");
        _ = Scan();
        if (test) Demo();
    }

    private static DataGridView Grid((string Name, string Title, int Width)[] columns)
    {
        var grid = new DataGridView { Dock = DockStyle.Fill, ReadOnly = true, AllowUserToAddRows = false, AllowUserToDeleteRows = false,
            MultiSelect = false, SelectionMode = DataGridViewSelectionMode.FullRowSelect, RowHeadersVisible = false,
            BackgroundColor = Color.White, BorderStyle = BorderStyle.None, AutoGenerateColumns = false, AllowUserToResizeRows = false };
        grid.ColumnHeadersHeight = 34; grid.RowTemplate.Height = 28;
        grid.DefaultCellStyle.SelectionBackColor = Color.FromArgb(218, 232, 244);
        grid.DefaultCellStyle.SelectionForeColor = Color.Black;
        grid.AlternatingRowsDefaultCellStyle.BackColor = Color.FromArgb(247, 249, 252);
        foreach (var c in columns) grid.Columns.Add(new DataGridViewTextBoxColumn { Name = c.Name, HeaderText = c.Title, Width = c.Width, SortMode = DataGridViewColumnSortMode.NotSortable });
        return grid;
    }

    private async Task Scan()
    {
        if (scanning || quitting) return;
        scanning = true; summary.Text = "保存場所を確認中です。秘密の値は読み取りません。";
        var snapshot = custom.ToArray();
        try
        {
            var inventory = await Task.Run(() => new Discovery(Locations.Current).Scan(snapshot));
            if (quitting) return;
            targets.Rows.Clear();
            foreach (var target in inventory.Targets)
            {
                int row = targets.Rows.Add(target.Application, target.Category, target.Exists ? "あり" : "未確認", target.Path,
                    (target.Subtree ? "フォルダー配下 / " : "ファイル / ") + target.Note);
                targets.Rows[row].Tag = target;
            }
            diagnostics.Text = inventoryNotes + string.Join("\r\n", inventory.Diagnostics) +
                "\r\n\r\n・一覧は保存場所の候補です。認証情報の有無や形式は検証していません。" +
                "\r\n・OS 資格情報ストア、SSH Agent、環境変数の値、プロセスメモリ、WSL 内部は対象外です。" +
                "\r\n・独自名の SSH 鍵や .env はファイルを追加してください。" +
                "\r\n・内蔵ブラウザーは ChatGPT / Codex の既知のフォルダーのみを探索します。他のアプリは手動登録してください。" +
                "\r\n・この版のドライバーはラボ領域専用です。ETW 監視はファイル I/O の観測のみで遮断しません。" +
                "\r\n・ETW のプロセス識別は最善努力です。成功/失敗、既存マッピングの利用、すべての別名は確認できません。" +
                "\r\n・監視対象はサービス登録時のスナップショットです。候補の追加だけでは監視ルールを更新しません。" +
                "\r\n・履歴は起動後に追記されたイベントのみ。ログは通知用であり、保護を証明する経路ではありません。";
            summary.Text = $"保存場所の候補 {inventory.Targets.Count} 件（存在する場所 {inventory.Targets.Count(x => x.Exists)} 件）  /  全件未保護\r\n" +
                "× で閉じると通知領域へ常駐します。終了はアイコンの右クリックから。";
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        { summary.Text = "保存場所の確認に失敗しました。再スキャンしてください。"; diagnostics.Text = ex.Message; }
        finally { scanning = false; nextScan = DateTimeOffset.UtcNow.AddSeconds(60); }
    }

    private void Tick()
    {
        ticks++;
        var lines = tail.Poll();
        if (tail.Reset) telemetry.Disconnect();
        foreach (var line in lines)
            if (telemetry.Accept(line) is { } item) Receive(item);
        bool alive = telemetry.ServiceAlive(DateTimeOffset.UtcNow);
        bool observing = alive && telemetry.Observing;
        bool receiving = telemetry.Fresh(DateTimeOffset.UtcNow) && telemetry.Observing;
        service.Text = (receiving ? $"{(observing ? "ETW 監視中" : "ETW ログ受信中（生存確認保留）")}・遮断なし  |  監視ルール {telemetry.RuleCount} 件" :
            "対象のブラウザー・認証情報は未保護  |  " + (alive ? "ラボ用サービスの状態通知あり" : "サービス未接続 / 状態確認不可")) +
            $"\n観測 {observed} 回 / 拒否 {denied} 件 / 監査欠落 {telemetry.Lost} / 不正レコード {telemetry.Invalid + tail.Oversize} / 未照合 I/O（対象外含む）{telemetry.Unmapped}" +
            (tail.Error == null ? "" : "  /  " + tail.Error);
        icon.Text = receiving ? "BDG: ETW ログ受信中・遮断なし" : alive ? "BDG: ラボ通知稼働・実データ未保護" : "BDG: サービス未接続・実データ未保護";
        if (!scanning && DateTimeOffset.UtcNow >= nextScan) _ = Scan();
        if (Environment.TickCount64 >= nextReport)
        {
            try
            {
                File.WriteAllText(runtimePath + ".tmp", JsonSerializer.Serialize(new { timestamp = DateTimeOffset.UtcNow,
                    pid = Environment.ProcessId, realDataProtected = false, labServiceAlive = alive && !telemetry.Observing,
                    monitorServiceAlive = observing, monitorRules = telemetry.RuleCount, etwEvents = telemetry.EventsReceived,
                    monitorLogReceiving = receiving, serviceIdentityStatus = telemetry.IdentityStatus,
                    etwMatched = telemetry.EventsMatched, etwUnmapped = telemetry.Unmapped, etwDecodeErrors = telemetry.DecodeErrors, observed, popups,
                    ticks, scanning, candidates = targets.Rows.Count, history = history.Rows.Count, denied,
                    lostEvents = telemetry.Lost, invalidRecords = telemetry.Invalid + tail.Oversize, logError = tail.Error }));
                File.Move(runtimePath + ".tmp", runtimePath, true);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
            nextReport = Environment.TickCount64 + 2000;
        }
        if (runSeconds > 0 && Environment.TickCount64 - started >= runSeconds * 1000L) ExitThread();
    }

    private void Receive(AccessEvent item, bool historical = false)
    {
        if (history.Rows.Cast<DataGridViewRow>().Any(r => r.Tag is AccessEvent previous &&
            previous.Sequence == item.Sequence && previous.Time == item.Time && previous.Pid == item.Pid &&
            previous.Target == item.Target && previous.Decision == item.Decision)) return;
        history.Rows.Insert(0, item.Time.ToLocalTime().ToString("MM/dd HH:mm:ss"), item.Demo ? "表示テスト" : item.Decision == "deny" ? "拒否" : item.Decision == "observe" ? $"観測 {item.Operation} ×{item.Count}" : "許可",
            item.Process, item.Browser, item.Category, item.Target);
        history.Rows[0].Tag = item;
        while (history.Rows.Count > 200) history.Rows.RemoveAt(history.Rows.Count - 1);
        if (historical) return; // Never replay alerts for historical denials.
        if (item.Decision == "observe") observed += item.Count;
        if (item.Decision != "deny") return;
        if (!item.Demo) denied++;
        if (!popups && !item.Demo) return;
        if (alert is null || alert.IsDisposed) alert = new AlertForm();
        alert.Present(item);
        if (!item.Demo) icon.ShowBalloonTip(4000, "BDG: アクセス拒否イベント", $"{item.Process} / {item.Browser} / {item.Category}", ToolTipIcon.Warning);
    }

    private void Demo() => Receive(new(DateTimeOffset.UtcNow, 0, 0, "表示テスト用プロセス", "実際のプロセスではありません",
        @"C:\BDG-Lab\Protected\demo.txt", "ラボ / 表示テスト", "通知の動作確認", "deny", true));
    private void ShowDashboard() { dashboard.Show(); dashboard.WindowState = FormWindowState.Normal; dashboard.Activate(); }
    private void AddFile()
    {
        using var picker = new OpenFileDialog { Title = "保存場所の候補へ追加（内容は読みません）", CheckFileExists = true, Multiselect = false };
        if (picker.ShowDialog(dashboard) == DialogResult.OK) AddCustom(picker.FileName, false);
    }
    private void AddFolder()
    {
        using var picker = new FolderBrowserDialog { Description = "保存場所の候補へフォルダーを追加（配下全体・未保護）", UseDescriptionForTitle = true };
        if (picker.ShowDialog(dashboard) == DialogResult.OK) AddCustom(picker.SelectedPath, true);
    }
    private void AddCustom(string path, bool subtree)
    {
        try
        {
            path = Discovery.LocalPath(path);
            if (!custom.Any(x => x.Path.Equals(path, StringComparison.OrdinalIgnoreCase)))
            {
                if (custom.Count >= 200) throw new IOException("手動登録は 200 件までです");
                custom.Add(new("手動登録", "認証情報 / 内蔵ブラウザー", path, subtree, true));
                SaveCustom();
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        { MessageBox.Show(dashboard, ex.Message, "保存場所を登録できません"); }
    }
    private void RemoveCustom()
    {
        if (targets.CurrentRow?.Tag is not Target target)
        { MessageBox.Show(dashboard, "項目を選択してください。", "手動登録の解除", MessageBoxButtons.OK, MessageBoxIcon.Information); return; }
        if (!target.Manual)
        { MessageBox.Show(dashboard, "標準項目は削除できません", "手動登録の解除", MessageBoxButtons.OK, MessageBoxIcon.Information); return; }
        if (MessageBox.Show(dashboard, "この項目の手動登録を解除しますか？\n\n" + target.Path +
            "\n\n実ファイルは削除しません。現在の監視ルールには即時反映されません。", "手動登録の解除", MessageBoxButtons.YesNo,
            MessageBoxIcon.Question, MessageBoxDefaultButton.Button2) != DialogResult.Yes) return;
        var previous = custom.ToArray();
        custom.RemoveAll(x => x.Path.Equals(target.Path, StringComparison.OrdinalIgnoreCase));
        try { SaveCustom(); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        { custom.Clear(); custom.AddRange(previous); MessageBox.Show(dashboard, ex.Message, "登録一覧を保存できません"); }
    }
    private void ExportHistory()
    {
        using var picker = new SaveFileDialog { Title = "アクセス履歴を保存（直近200件まで）", Filter = "ログファイル (*.log)|*.log",
            DefaultExt = "log", AddExtension = true, OverwritePrompt = true, FileName = $"BDG-access-{DateTime.Now:yyyyMMdd-HHmmss}.log" };
        if (picker.ShowDialog(dashboard.Visible ? dashboard : null) != DialogResult.OK) return;
        try
        {
            var rows = history.Rows.Cast<DataGridViewRow>().Select(r => (AccessEvent)r.Tag!).Reverse().ToArray();
            File.WriteAllText(picker.FileName, HistoryLog.Format(rows, DateTimeOffset.Now), new System.Text.UTF8Encoding(false));
            MessageBox.Show(dashboard.Visible ? dashboard : null, $"{rows.Length} 件の履歴を書き出しました。", "アクセス履歴の保存", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        { MessageBox.Show(dashboard.Visible ? dashboard : null, ex.Message, "履歴を保存できません", MessageBoxButtons.OK, MessageBoxIcon.Error); }
    }
    private void ShowEvent(AccessEvent item)
    {
        using var detail = new Form { Text = "アクセス履歴の詳細", Size = new(740, 480), StartPosition = FormStartPosition.CenterParent,
            Font = dashboard.Font, MinimizeBox = false, MaximizeBox = false };
        var text = new TextBox { Dock = DockStyle.Fill, Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Both, WordWrap = false,
            Text = $"日時: {item.Time.ToLocalTime():yyyy/MM/dd HH:mm:ss.fff}\r\n結果: {(item.Demo ? "表示テスト" : item.Decision)}\r\n" +
                $"操作: {item.Operation} / 回数: {item.Count}\r\nプロセス: {item.Process} / PID: {item.Pid}\r\n実行ファイル: {item.Image}\r\n" +
                $"対象アプリ: {item.Browser}\r\n種類: {item.Category}\r\n対象パス: {item.Target}\r\n理由: {item.Reason} / フラグ: {item.Flags}\r\n\r\n" +
                (item.Decision == "observe" ? "ETW によるアクセス要求の観測です。遮断・成功失敗の判定は行っていません。プロセス識別は最善努力です。" : item.Demo ? "表示テストです。実際のアクセス検出ではありません。" : "BDG ポリシーの記録です。") };
        detail.Controls.Add(text); detail.ShowDialog(dashboard);
    }
    private void SaveCustom()
    {
        File.WriteAllText(customPath + ".tmp", JsonSerializer.Serialize(custom, new JsonSerializerOptions { WriteIndented = true }));
        File.Move(customPath + ".tmp", customPath, true);
        _ = Scan();
    }
    protected override void ExitThreadCore()
    {
        quitting = true; timer.Stop(); icon.Visible = false; alert?.Close(); dashboard.Close(); base.ExitThreadCore();
    }
    protected override void Dispose(bool disposing)
    {
        if (disposing) { quitting = true; timer.Dispose(); icon.Dispose(); alert?.Dispose(); dashboard.Dispose(); }
        base.Dispose(disposing);
    }
}

internal sealed class AlertForm : Form
{
    private readonly Label heading, count;
    private readonly TextBox detail;
    private int received;
    public AlertForm()
    {
        Text = "BDG アクセス通知"; Size = new(700, 470); MinimumSize = new(550, 400);
        StartPosition = FormStartPosition.CenterScreen; TopMost = true; Icon = SystemIcons.Shield;
        BackColor = Color.White; Font = new("Yu Gothic UI", 10);
        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, RowCount = 4, ColumnCount = 1, Padding = new(18) };
        layout.RowStyles.Add(new(SizeType.Absolute, 78)); layout.RowStyles.Add(new(SizeType.Absolute, 34));
        layout.RowStyles.Add(new(SizeType.Percent, 100)); layout.RowStyles.Add(new(SizeType.Absolute, 42));
        heading = new Label { Dock = DockStyle.Fill, Padding = new(10), Font = new("Yu Gothic UI", 13, FontStyle.Bold) };
        count = new Label { Dock = DockStyle.Fill, Padding = new(0, 6, 0, 0) };
        detail = new TextBox { Dock = DockStyle.Fill, Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical, BackColor = Color.White, BorderStyle = BorderStyle.None };
        var close = new Button { Text = "確認して閉じる", AutoSize = true, Dock = DockStyle.Right, FlatStyle = FlatStyle.Flat };
        close.Click += (_, _) => Close();
        layout.Controls.Add(heading, 0, 0); layout.Controls.Add(count, 0, 1); layout.Controls.Add(detail, 0, 2); layout.Controls.Add(close, 0, 3);
        Controls.Add(layout); AcceptButton = close;
    }
    public void Present(AccessEvent item)
    {
        received++;
        heading.BackColor = item.Demo ? Color.FromArgb(255, 225, 162) : Color.FromArgb(255, 218, 213);
        heading.Text = item.Demo ? "通知表示テスト\n実際のアクセス検出ではありません" : "アクセス拒否イベントを受信\n" + (item.Browser == "Synthetic" ? "ラボ領域に対する検出です" : "イベントの詳細を確認してください");
        count.Text = $"この画面で受信した通知 {received} 件 / 最新のイベントを表示";
        detail.Text = $"時刻: {item.Time.ToLocalTime():yyyy/MM/dd HH:mm:ss}\r\nプロセス: {item.Process} (PID {item.Pid})\r\n" +
            $"実行ファイル: {item.Image}\r\n\r\n対象アプリ: {item.Browser}\r\n種類: {item.Category}\r\n対象: {item.Target}\r\n\r\n" +
            (item.Demo ? "通知画面のみのテストです。実データの保護を有効化するものではありません。" : "通知ログの記録を表示しています。対象一覧の保護状態はメイン画面で確認してください。");
        if (item.Reason == 2) detail.Text += "\r\n名前取得に失敗したための拒否です。保護対象外のパスでも発生します。";
        if (item.Flags != 0) detail.Text += $"\r\nイベントの補足フラグ: {item.Flags}（パス省略などの可能性があります）";
        if (!Visible) Show();
    }
}
