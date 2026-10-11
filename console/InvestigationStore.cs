using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
namespace RudySentinel;
public sealed record ProcessInfo(
    [property: JsonPropertyName("id")] string Id,
    [property: JsonPropertyName("pid")] uint Pid,
    [property: JsonPropertyName("parent_id")] string ParentId,
    [property: JsonPropertyName("image")] string Image,
    [property: JsonPropertyName("command")] string Command,
    [property: JsonPropertyName("active")] bool Active,
    [property: JsonPropertyName("risk")] int Risk)
{
    public string Label => $"{Image.Split('\\','/').Last()}  ·  PID {Pid}  ·  risk {Risk}" + (Active ? "" : "  ·  exited");
}
public sealed record AlertInfo(string Id,string Severity,string Title,string RuleId,uint Pid,int Risk,ulong TimeMs,string Image,string Raw)
{
    public string Time => TimeMs>253402300799999UL ? "Invalid timestamp" : DateTimeOffset.FromUnixTimeMilliseconds((long)TimeMs).ToLocalTime().ToString("HH:mm:ss");
}
public sealed class ProcessNode(ProcessInfo process)
{
    public ProcessInfo Process { get; } = process;
    public string Label => Process.Label;
    public List<ProcessNode> Children { get; } = [];
}
public sealed class InvestigationStore
{
    public string Mode { get; private set; } = "disconnected";
    public ulong Events { get; private set; }
    public ulong Dropped { get; private set; }
    public ulong AllocationFailures { get; private set; }
    public ulong Evictions { get; private set; }
    public ulong TotalAlerts { get; private set; }
    public ulong UpdatedMs { get; private set; }
    public int MalformedLines { get; private set; }
    public List<ProcessInfo> Processes { get; private set; } = [];
    public List<AlertInfo> Alerts { get; private set; } = [];
    public string StateRaw { get; private set; } = "{}";
    private static FileStream SharedRead(string path) => new(path,FileMode.Open,FileAccess.Read,FileShare.ReadWrite|FileShare.Delete);
    private static ulong Number(JsonElement e,string key) => e.TryGetProperty(key,out var p) && p.TryGetUInt64(out var value) ? value : 0;
    private static string Text(JsonElement e,string key,string fallback="") => e.TryGetProperty(key,out var p) && p.ValueKind==JsonValueKind.String ? p.GetString()??fallback : fallback;
    public void Load(string directory)
    {
        string state=Path.Combine(directory,"state.json");
        using var file=SharedRead(state);
        if (file.Length>64*1024*1024) throw new InvalidDataException("State exceeds the 64 MiB limit");
        using var doc=JsonDocument.Parse(file);
        var root=doc.RootElement;
        if (Number(root,"version")!=1) throw new InvalidDataException("Unsupported session format");
        var processes=JsonSerializer.Deserialize<List<ProcessInfo>>(root.GetProperty("processes").GetRawText())??[];
        if (processes.Count>100000 || processes.Any(p=>string.IsNullOrEmpty(p.Id) || p.ParentId is null || p.Image is null)) throw new InvalidDataException("Invalid process state");
        var alerts=new List<AlertInfo>(); int malformed=0;
        foreach(var name in new[]{"alerts.ndjson.1","alerts.ndjson"})
        {
            string path=Path.Combine(directory,name); if (!File.Exists(path)) continue;
            using var stream=SharedRead(path);
            bool partial=stream.Length>4*1024*1024;
            if (partial) stream.Seek(-4*1024*1024,SeekOrigin.End);
            using var reader=new StreamReader(stream);
            if (partial) reader.ReadLine();
            string? line;
            while ((line=reader.ReadLine())!=null)
            {
                if (line.Length==0) continue;
                try
                {
                    using var item=JsonDocument.Parse(line); var v=item.RootElement;
                    if (Text(v,"kind")=="health")
                    {
                        var time=Number(v,"time_ms");
                        alerts.Add(new($"health:{time}","high",Text(v,"title"),"SENSOR",0,0,time,"Sensor",line)); continue;
                    }
                    alerts.Add(new(Text(v,"id"),Text(v,"severity"),Text(v,"title"),Text(v,"rule_id"),
                        checked((uint)Number(v,"pid")),checked((int)Number(v,"risk")),Number(v,"time_ms"),Text(v,"image"),line));
                }
                catch (Exception ex) when (ex is JsonException or OverflowException or InvalidOperationException) { malformed++; }
            }
        }
        // Commit only after a complete state read, preserving the previous view during atomic replacement.
        Processes=processes; Alerts=alerts.TakeLast(1000).Reverse().ToList(); MalformedLines=malformed;
        Mode=Text(root,"mode","unknown"); Events=Number(root,"events"); Dropped=Number(root,"sensor_dropped");
        AllocationFailures=Number(root,"sensor_allocation_failures"); Evictions=Number(root,"evictions");
        TotalAlerts=Number(root,"alert_count"); UpdatedMs=Number(root,"updated_ms"); StateRaw=root.GetRawText();
    }
    public List<ProcessNode> Tree()
    {
        var nodes=Processes.ToDictionary(p=>p.Id,p=>new ProcessNode(p)); var roots=new List<ProcessNode>();
        foreach (var p in Processes)
        {
            bool cycle=false; string parent=p.ParentId; var seen=new HashSet<string>{p.Id};
            while (nodes.TryGetValue(parent,out var ancestor))
            {
                if (!seen.Add(parent) || seen.Count>128) { cycle=true; break; }
                parent=ancestor.Process.ParentId;
            }
            if (!cycle && nodes.TryGetValue(p.ParentId,out var node)) node.Children.Add(nodes[p.Id]);
            else roots.Add(nodes[p.Id]);
        }
        return roots;
    }
    public static void Export(string path,AlertInfo alert,IReadOnlyList<ProcessInfo> processes)
    {
        using var evidence=JsonDocument.Parse(alert.Raw);
        var payload=new { format="rudy-sentinel-case-v1", exported_utc=DateTimeOffset.UtcNow, alert=evidence.RootElement, processes };
        File.WriteAllText(path,JsonSerializer.Serialize(payload,new JsonSerializerOptions{WriteIndented=true}));
    }
}
