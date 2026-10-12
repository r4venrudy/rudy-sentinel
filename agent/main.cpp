#include "collector.hpp"
#ifdef RS_EVIDENCE
#include "evidence.hpp"
#endif
#include <chrono>
#include <csignal>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <stdexcept>
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <shellapi.h>
#endif
namespace fs = std::filesystem;
static std::atomic_bool stopped{false};
static void stop_signal(int) { stopped.store(true); }
static std::uint64_t now_ms() { return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count()); }
static void atomic_json(const fs::path& path, const rs::Json& value) {
    auto temp=path; temp += ".tmp";
    { std::ofstream out(temp,std::ios::binary|std::ios::trunc); out << value.dump(2); out.close(); if (!out) throw std::runtime_error("Cannot write " + temp.string()); }
#ifdef _WIN32
    if (!MoveFileExW(temp.c_str(),path.c_str(),MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH)) throw std::runtime_error("Cannot replace snapshot");
#else
    fs::rename(temp,path);
#endif
}
class Log {
    fs::path path_; std::ofstream stream_;
public:
    explicit Log(fs::path path):path_(std::move(path)) { open(); }
    void open() { stream_.open(path_,std::ios::binary|std::ios::app); if (!stream_) throw std::runtime_error("Cannot open log " + path_.string()); }
    void write(const rs::Json& value) {
        if (stream_.tellp() > 64*1024*1024) {
            stream_.close(); auto previous=path_; previous += ".1";
            std::error_code ec; fs::remove(previous,ec); fs::rename(path_,previous); open();
        }
        stream_ << value.dump(-1,' ',false,rs::Json::error_handler_t::replace) << '\n'; stream_.flush();
        if (!stream_) throw std::runtime_error("Log write failed");
    }
};
struct Options { fs::path rules="rules/default.json", out="run", replay, evidence_file; std::string scope; bool live{}, service{}; };
static int run(const Options& o) {
    std::ifstream input(o.rules); if (!input) throw std::runtime_error("Cannot open rules");
    rs::Json rules; input >> rules; rs::Engine engine(std::move(rules));
    fs::create_directories(o.out);
    /* A new session must never mix old process identities and alert logs. */
    for (const char* name : {"events.ndjson","alerts.ndjson","events.ndjson.1","alerts.ndjson.1"}) {
        if (fs::exists(o.out/name)) throw std::runtime_error("Output contains a previous session; choose a new --out directory");
    }
    Log events(o.out/"events.ndjson"), alerts(o.out/"alerts.ndjson");
    std::uint64_t count=0, alert_count=0, snapshot_time=0;
    auto save=[&] { auto state=engine.snapshot(); state["mode"]=o.live?"live":"replay"; state["updated_ms"]=now_ms(); state["alert_count"]=alert_count; atomic_json(o.out/"state.json",state); };
    auto sink=[&](const rs::Event& e) {
        events.write(rs::event_json(e)); ++count;
        for (auto& alert : engine.consume(e)) { alerts.write(alert); ++alert_count; std::cout << alert["severity"].get<std::string>() << " " << alert["title"].get<std::string>() << " (PID " << e.pid << ")\n"; }
        auto time=now_ms(); if (time-snapshot_time>=1000) { save(); snapshot_time=time; }
    };
    save();
    try {
        if (o.live) rs::collect(stopped,sink,[&](std::uint64_t dropped,std::uint64_t allocations) {
            auto health=engine.health(dropped,allocations,now_ms()); if (!health.is_null()) alerts.write(health);
            auto time=now_ms(); if(time-snapshot_time>=1000) { save(); snapshot_time=time; }
        });
        else {
            std::ifstream replay(o.replay,std::ios::binary); if(!replay) throw std::runtime_error("Cannot open replay file");
            std::string line; std::size_t line_number=0;
            while (!stopped.load() && std::getline(replay,line)) {
                ++line_number; if (line.size()>65536) throw std::runtime_error("Replay line too long"); if (line.empty()) continue;
                try { sink(rs::parse_event(rs::Json::parse(line))); }
                catch(const std::exception& e) { throw std::runtime_error("Replay line " + std::to_string(line_number) + ": " + e.what()); }
            }
            if (replay.bad()) throw std::runtime_error("Replay read failed");
        }
    } catch (...) { save(); throw; }
    save(); std::cout << "Processed " << count << " events, " << alert_count << " alerts.\n"; return 0;
}
#ifdef _WIN32
static SERVICE_STATUS_HANDLE service_handle{};
static SERVICE_STATUS service_status{};
static Options service_options;
static void service_state(DWORD state, DWORD error=NO_ERROR) {
    service_status.dwServiceType=SERVICE_WIN32_OWN_PROCESS; service_status.dwCurrentState=state;
    service_status.dwControlsAccepted=state==SERVICE_RUNNING?SERVICE_ACCEPT_STOP|SERVICE_ACCEPT_SHUTDOWN:0;
    service_status.dwWin32ExitCode=error; service_status.dwWaitHint=state==SERVICE_STOP_PENDING?10000:0;
    service_status.dwServiceSpecificExitCode=error==ERROR_SERVICE_SPECIFIC_ERROR?1:0;
    SetServiceStatus(service_handle,&service_status);
}
static DWORD WINAPI control(DWORD code,DWORD,LPVOID,LPVOID) {
    if(code==SERVICE_CONTROL_STOP || code==SERVICE_CONTROL_SHUTDOWN) { service_state(SERVICE_STOP_PENDING); stopped.store(true); }
    return NO_ERROR;
}
static void WINAPI service_main(DWORD,LPWSTR*) {
    service_handle=RegisterServiceCtrlHandlerExW(L"RudySentinel",control,nullptr); if(!service_handle) return;
    service_state(SERVICE_START_PENDING); service_state(SERVICE_RUNNING);
    try { service_options.out /= "session-" + std::to_string(now_ms()); run(service_options); service_state(SERVICE_STOPPED); }
    catch(const std::exception& e) {
        try { atomic_json(service_options.out/"error.json",{{"error",e.what()},{"time_ms",now_ms()}}); } catch(...) {}
        service_state(SERVICE_STOPPED,ERROR_SERVICE_SPECIFIC_ERROR);
    }
}
#endif
int main(int argc,char** argv) {
    try {
#ifdef _WIN32
        int wide_count=0;
        auto wide=CommandLineToArgvW(GetCommandLineW(),&wide_count);
        if(!wide) throw std::runtime_error("Cannot parse Windows command line");
        std::vector<std::string> arguments;
        for(int i=0;i<wide_count;++i) {
            int bytes=WideCharToMultiByte(CP_UTF8,0,wide[i],-1,nullptr,0,nullptr,nullptr);
            if(!bytes) { LocalFree(wide); throw std::runtime_error("Invalid command line text"); }
            std::string text(static_cast<std::size_t>(bytes),'\0');
            WideCharToMultiByte(CP_UTF8,0,wide[i],-1,text.data(),bytes,nullptr,nullptr);
            text.pop_back(); arguments.push_back(std::move(text));
        }
        LocalFree(wide);
        std::vector<char*> pointers; for(auto& arg:arguments) pointers.push_back(arg.data());
        argc=wide_count; argv=pointers.data();
#endif
        Options o;
        for(int i=1;i<argc;++i) {
            std::string a=argv[i];
            if(a=="--help") { std::cout << "Rudy Sentinel 0.1.0\n--replay FILE | --live [--service] --rules FILE --out NEW_DIRECTORY\n--export-evidence ALERTS_NDJSON --scope HOST_SESSION_ID (requires RS_EVIDENCE build)\n"; return 0; }
            if(a=="--live") o.live=true;
            else if(a=="--service") o.service=true;
            else if(a=="--scope" && i+1<argc) o.scope=argv[++i];
            else if(a=="--export-evidence" && i+1<argc) o.evidence_file=fs::path(std::u8string(reinterpret_cast<const char8_t*>(argv[++i])));
            else if((a=="--rules" || a=="--out" || a=="--replay") && i+1<argc) { fs::path p(std::u8string(reinterpret_cast<const char8_t*>(argv[++i]))); if(a=="--rules") o.rules=p; else if(a=="--out") o.out=p; else o.replay=p; }
            else throw std::runtime_error("Unknown or incomplete argument: " + a);
        }
        if(!o.evidence_file.empty()) {
            if(o.live || o.service || !o.replay.empty()) throw std::runtime_error("Evidence export is an offline operation; choose it separately from collection/replay");
#ifdef RS_EVIDENCE
            std::cout << export_evidence(o.evidence_file,o.scope) << '\n'; return std::cout ? 0 : 1;
#else
            throw std::runtime_error("Rebuild with -DRS_EVIDENCE=ON and an installed Rudy Evidence SDK");
#endif
        }
        if(!o.scope.empty()) throw std::runtime_error("--scope requires --export-evidence");
        if(o.live==!o.replay.empty() || (o.service&&!o.live)) throw std::runtime_error("Choose --live or --replay FILE; --service requires --live");
        std::signal(SIGINT,stop_signal); std::signal(SIGTERM,stop_signal);
#ifdef _WIN32
        if(o.service) {
            o.rules=fs::absolute(o.rules); o.out=fs::absolute(o.out); service_options=o;
            SERVICE_TABLE_ENTRYW table[]{{const_cast<LPWSTR>(L"RudySentinel"),service_main},{nullptr,nullptr}};
            if(!StartServiceCtrlDispatcherW(table)) throw std::runtime_error("Service dispatcher failed; start the registered service via SCM");
            return 0;
        }
#endif
        return run(o);
    } catch(const std::exception& e) { std::cerr << "Rudy Sentinel: " << e.what() << '\n'; return 1; }
}
