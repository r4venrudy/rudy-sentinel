#include "collector.hpp"
#include "protocol.h"
#include <cstring>
#include <stdexcept>
#include <thread>
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#endif
namespace rs {
#ifdef _WIN32
static_assert(sizeof(RS_EVENT) == 1592 && sizeof(RS_BATCH) == 48 && sizeof(RS_REQUEST) == 16);
class Handle {
public:
    HANDLE value;
    explicit Handle(HANDLE h) : value(h) {}
    ~Handle() { if (value != INVALID_HANDLE_VALUE && value != nullptr) CloseHandle(value); }
    Handle(const Handle&) = delete; Handle& operator=(const Handle&) = delete;
};
static std::string utf8(const std::uint16_t* value, std::size_t capacity) {
    std::string output;
    for (std::size_t i=0; i<capacity && value[i]; ++i) {
        std::uint32_t cp = value[i];
        if (cp >= 0xD800 && cp <= 0xDBFF) {
            if (i+1<capacity && value[i+1]>=0xDC00 && value[i+1]<=0xDFFF) { cp = 0x10000 + ((cp-0xD800)<<10) + value[++i]-0xDC00; }
            else cp = 0xFFFD;
        } else if (cp>=0xDC00 && cp<=0xDFFF) cp=0xFFFD;
        if (cp<0x80) output += static_cast<char>(cp);
        else if (cp<0x800) { output += static_cast<char>(0xC0|(cp>>6)); output += static_cast<char>(0x80|(cp&0x3F)); }
        else if (cp<0x10000) { output += static_cast<char>(0xE0|(cp>>12)); output += static_cast<char>(0x80|((cp>>6)&0x3F)); output += static_cast<char>(0x80|(cp&0x3F)); }
        else { output += static_cast<char>(0xF0|(cp>>18)); output += static_cast<char>(0x80|((cp>>12)&0x3F)); output += static_cast<char>(0x80|((cp>>6)&0x3F)); output += static_cast<char>(0x80|(cp&0x3F)); }
    }
    return output;
}
static std::string process_path(std::uint32_t pid) {
    Handle handle(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,pid));
    if (!handle.value) return {};
    WCHAR buffer[32768]; DWORD chars = 32768;
    if (!QueryFullProcessImageNameW(handle.value,0,buffer,&chars)) return {};
    return utf8(reinterpret_cast<const std::uint16_t*>(buffer),chars);
}
void collect(std::atomic_bool& stop, const EventSink& sink, const HealthSink& health) {
    Handle device(CreateFileW(L"\\\\.\\RudySentinel",GENERIC_READ,0,nullptr,OPEN_EXISTING,0,nullptr));
    if (device.value == INVALID_HANDLE_VALUE) throw std::runtime_error("Cannot open RudySensor (error " + std::to_string(GetLastError()) + "). Load the signed driver in a test VM and run elevated.");
    std::vector<unsigned char> buffer(sizeof(RS_BATCH)+RS_BATCH_MAX*sizeof(RS_EVENT));
    std::unordered_map<std::uint32_t,std::string> paths;
    const auto path = [&](std::uint32_t pid) -> std::string {
        if (auto it = paths.find(pid); it != paths.end()) return it->second;
        auto result = process_path(pid);
        if (paths.size() >= 20000) paths.clear();
        if (!result.empty()) paths[pid] = result;
        return result;
    };
    while (!stop.load()) {
        RS_REQUEST request{sizeof(RS_REQUEST),RS_VERSION,RS_BATCH_MAX,0}; DWORD bytes{};
        if (!DeviceIoControl(device.value,RS_IOCTL_DRAIN,&request,sizeof(request),buffer.data(),static_cast<DWORD>(buffer.size()),&bytes,nullptr))
            throw std::runtime_error("Sensor read failed: " + std::to_string(GetLastError()));
        RS_BATCH batch{};
        if (bytes<sizeof(batch)) throw std::runtime_error("Sensor returned a short batch");
        std::memcpy(&batch,buffer.data(),sizeof(batch));
        if (batch.Size!=sizeof(batch) || batch.Version!=RS_VERSION || batch.Count>RS_BATCH_MAX ||
            bytes != sizeof(batch)+batch.Count*sizeof(RS_EVENT)) throw std::runtime_error("Sensor ABI mismatch");
        health(batch.Dropped,batch.AllocationFailures);
        for (std::uint32_t i=0; i<batch.Count; ++i) {
            RS_EVENT raw{}; std::memcpy(&raw,buffer.data()+sizeof(batch)+i*sizeof(raw),sizeof(raw));
            if (raw.Size!=sizeof(raw) || raw.Version!=RS_VERSION || raw.Type<1 || raw.Type>4) throw std::runtime_error("Invalid sensor event");
            static const char* names[]{"","process_start","process_exit","image_load","handle_request"};
            Event e;
            e.type=names[raw.Type]; e.sequence=raw.Sequence;
            constexpr std::uint64_t epoch=116444736000000000ULL;
            e.time_ms=raw.Time100ns>=epoch ? (raw.Time100ns-epoch)/10000 : 0;
            e.pid=raw.ProcessId; e.parent=raw.ParentId; e.target=raw.TargetId; e.access=raw.AccessMask; e.flags=raw.Flags;
            e.image=utf8(raw.Image,RS_PATH_CHARS); e.command=utf8(raw.Command,RS_COMMAND_CHARS);
            if (e.type=="process_start") paths[e.pid]=e.image;
            e.process_image=path(e.pid);
            if (e.type=="handle_request") e.target_image=path(e.target);
            sink(e);
            if (e.type=="process_exit") paths.erase(e.pid);
        }
        if (!batch.Count) std::this_thread::sleep_for(std::chrono::milliseconds(25));
    }
}
#else
void collect(std::atomic_bool&, const EventSink&, const HealthSink&) { throw std::runtime_error("Live kernel collection requires Windows"); }
#endif
}
