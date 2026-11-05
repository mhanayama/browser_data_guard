using System.Text.Encodings.Web;
using System.Text.Json;

namespace Bdg.Tray;

internal static class HistoryLog
{
    // JSON Lines keeps control characters in path/process metadata from forging log entries.
    public static string Format(IEnumerable<AccessEvent> events, DateTimeOffset exported)
    {
        var options = new JsonSerializerOptions { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping };
        var rows = events.ToArray();
        var lines = new List<string> { JsonSerializer.Serialize(new { type = "bdg-history-export", exported,
            entries = rows.Length, scope = "通知アプリで保持している直近200件まで", enforcement = false,
            note = "ETWはアクセス要求の観測です。成功/失敗を判定せず、アクセスを遮断しません。表示テストは実検出ではありません。" }, options) };
        lines.AddRange(rows.Select(e => JsonSerializer.Serialize(new { type = "access", timestamp = e.Time,
            decision = e.Demo ? "display-test" : e.Decision, operation = e.Operation, count = e.Count,
            sequence = e.Sequence, pid = e.Pid, processName = e.Process, executablePath = e.Image,
            target = e.Target, application = e.Browser, category = e.Category, reason = e.Reason, flags = e.Flags }, options)));
        return string.Join(Environment.NewLine, lines) + Environment.NewLine;
    }
}
