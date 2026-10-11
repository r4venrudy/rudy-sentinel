using System.IO;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using Microsoft.Win32;
namespace RudySentinel;
public partial class MainWindow : Window
{
    private readonly InvestigationStore store=new();
    private readonly DispatcherTimer timer=new() { Interval=TimeSpan.FromSeconds(3) };
    private string directory;
    private bool ready;
    public MainWindow(string path)
    {
        InitializeComponent(); directory=path; ready=true; Refresh();
        timer.Tick+=(_,_)=>Refresh(); timer.Start(); Closed+=(_,_)=>timer.Stop();
    }
    private void Refresh()
    {
        try
        {
            store.Load(directory);
            EventCount.Text=store.Events.ToString("N0"); ProcessCount.Text=store.Processes.Count.ToString("N0");
            AlertCount.Text=store.TotalAlerts.ToString("N0"); LossCount.Text=(store.Dropped+store.AllocationFailures).ToString("N0");
            SessionLabel.Text=store.Mode=="replay"?"RECORDED-EVENT REPLAY":"LIVE SENSOR SESSION";
            Filter(); ProcessesTree.ItemsSource=store.Tree();
            HealthText.Text=$"Mode: {store.Mode}\n\nQueue overflow: {store.Dropped:N0}\nAllocation failures: {store.AllocationFailures:N0}\nProcess history evictions: {store.Evictions:N0}\nMalformed alert lines: {store.MalformedLines:N0}\n\nThe sensor records process lifecycle, image loads, and selected handle requests. A requested handle is not proof of successful access.\n\nMonitoring is observational. This preview does not block or quarantine processes. Administrators retain control of the service and driver.";
            var age=DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()-(long)Math.Min(store.UpdatedMs,(ulong)long.MaxValue);
            Status.Text=$"Session: {Path.GetFileName(directory)}  ·  {(store.Mode=="live" && age>10000?"Stale session: agent may have stopped":"Session loaded")}  ·  Showing up to 1,000 recent alerts. Behavioral signals require investigation.";
            if(Evidence.Text.Length==0 && AlertsGrid.Items.Count>0) AlertsGrid.SelectedIndex=0;
        }
        catch(Exception ex) when(ex is IOException or UnauthorizedAccessException or JsonException or ArgumentException)
        { Status.Text=$"Waiting for a readable session: {ex.Message}"; }
    }
    private void Filter()
    {
        if(!ready) return;
        string severity=(Severity.SelectedItem as ComboBoxItem)?.Content?.ToString()??"All severities";
        string search=Search.Text;
        string? selected=(AlertsGrid.SelectedItem as AlertInfo)?.Id;
        var rows=store.Alerts.Where(a=>(severity=="All severities"||a.Severity==severity) &&
            ($"{a.Title} {a.Image} {a.RuleId} {a.Pid}").Contains(search,StringComparison.OrdinalIgnoreCase)).ToList();
        AlertsGrid.ItemsSource=rows; AlertsGrid.SelectedItem=rows.Find(a=>a.Id==selected);
    }
    private void FilterChanged(object sender,SelectionChangedEventArgs e)=>Filter();
    private void SearchChanged(object sender,TextChangedEventArgs e)=>Filter();
    private void AlertSelected(object sender,SelectionChangedEventArgs e)
    { if(AlertsGrid.SelectedItem is AlertInfo alert) { using var d=JsonDocument.Parse(alert.Raw); Evidence.Text=JsonSerializer.Serialize(d.RootElement,new JsonSerializerOptions{WriteIndented=true}); } }
    private void ProcessSelected(object sender,RoutedPropertyChangedEventArgs<object> e)
    { if(e.NewValue is ProcessNode node) Evidence.Text=JsonSerializer.Serialize(node.Process,new JsonSerializerOptions{WriteIndented=true}); }
    private void OpenSession(object sender,RoutedEventArgs e)
    { var picker=new OpenFolderDialog{Title="Open a Rudy Sentinel session"}; if(picker.ShowDialog(this)==true) { directory=picker.FolderName; Evidence.Clear(); Refresh(); } }
    private void ExportCase(object sender,RoutedEventArgs e)
    {
        if(AlertsGrid.SelectedItem is not AlertInfo alert) { MessageBox.Show(this,"Select an alert first."); return; }
        var picker=new SaveFileDialog{Title="Export investigation",Filter="JSON case|*.json",FileName=$"sentinel-case-{alert.Pid}.json"};
        if(picker.ShowDialog(this)!=true) return;
        try { InvestigationStore.Export(picker.FileName,alert,store.Processes); Status.Text="Investigation exported locally."; }
        catch(Exception ex) when(ex is IOException or UnauthorizedAccessException) { MessageBox.Show(this,ex.Message,"Export failed"); }
    }
}
