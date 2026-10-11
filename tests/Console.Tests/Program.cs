using System.Text.Json;
using RudySentinel;
int checks=0;
void Check(bool value,string message) { checks++; if(!value) throw new Exception(message); }
string folder=Path.Combine(Path.GetTempPath(),"sentinel-tests-"+Guid.NewGuid()); Directory.CreateDirectory(folder);
try
{
    var processes=new[]{new ProcessInfo("10:1",10,"","parent.exe","",true,0),new ProcessInfo("11:2",11,"10:1","child.exe","",false,70)};
    var state=new{version=1,mode="replay",events=9,alert_count=1,processes,sensor_dropped=2,sensor_allocation_failures=3,evictions=0,updated_ms=1000};
    File.WriteAllText(Path.Combine(folder,"state.json"),JsonSerializer.Serialize(state));
    var alert=new{kind="alert",id="one",severity="high",title="Test behavior",rule_id="RS-001",pid=11,risk=70,time_ms=1000,image="child.exe"};
    File.WriteAllText(Path.Combine(folder,"alerts.ndjson"),JsonSerializer.Serialize(alert)+"\n{invalid}\n");
    var store=new InvestigationStore(); store.Load(folder);
    Check(store.Events==9&&store.Mode=="replay","state counters");
    Check(store.Dropped==2&&store.AllocationFailures==3,"health counts");
    Check(store.Alerts.Count==1&&store.MalformedLines==1,"malformed line isolation");
    Check(store.Tree().Count==1&&store.Tree()[0].Children.Count==1,"process tree");
    string export=Path.Combine(folder,"case.json"); InvestigationStore.Export(export,store.Alerts[0],store.Processes);
    using(var doc=JsonDocument.Parse(File.ReadAllText(export))) Check(doc.RootElement.GetProperty("processes").GetArrayLength()==2,"export process evidence");
    var cycle=new[]{new ProcessInfo("1",1,"2","a","",true,0),new ProcessInfo("2",2,"1","b","",true,0)};
    File.WriteAllText(Path.Combine(folder,"state.json"),JsonSerializer.Serialize(new{version=1,processes=cycle})); store.Load(folder);
    Check(store.Tree().Count==2,"cycle isolation");
    File.WriteAllText(Path.Combine(folder,"state.json"),"{\"version\":99,\"processes\":[]}");
    bool rejected=false; try{store.Load(folder);}catch(InvalidDataException){rejected=true;} Check(rejected,"version rejection");
    Check(store.Processes.Count==2,"previous view preserved on read failure");
    System.Console.WriteLine($"{checks} C# investigation checks passed");
}
finally{Directory.Delete(folder,true);}
