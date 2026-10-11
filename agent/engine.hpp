#pragma once
#include <cstdint>
#include <deque>
#include <string>
#include <unordered_map>
#include <vector>
#include <nlohmann/json.hpp>
namespace rs {
using Json = nlohmann::json;
struct Event {
    std::uint64_t sequence{}, time_ms{};
    std::uint32_t pid{}, parent{}, target{}, access{}, flags{};
    std::string type, image, command, process_image, target_image;
};
Event parse_event(const Json& value);
Json event_json(const Event& event);
struct Process {
    std::string id, parent_id, image, command;
    std::uint32_t pid{}, parent{};
    std::uint64_t started{}, exited{};
    bool active{true};
};
class Engine {
public:
    explicit Engine(Json config, std::size_t capacity = 20000);
    std::vector<Json> consume(const Event& event);
    Json snapshot() const;
    Json health(std::uint64_t dropped, std::uint64_t allocations, std::uint64_t time_ms);
private:
    struct Hit { std::string rule; std::uint64_t time, sequence; int score; };
    Json config_;
    std::size_t capacity_;
    std::unordered_map<std::string, Process> processes_;
    std::unordered_map<std::uint32_t, std::string> active_;
    std::unordered_map<std::string, std::deque<Hit>> hits_;
    std::deque<std::string> order_;
    std::uint64_t last_sequence_{}, last_time_{}, events_{}, evictions_{}, dropped_{}, allocations_{};
    bool matches(const Json& rule, const Event& e, const Process& p) const;
    Json alert(const Json& rule, const Event& e, const Process& p, const std::vector<std::uint64_t>& evidence);
    int risk(const std::string& id) const;
    Process& ensure(const Event& event);
};
std::string lower(std::string value);
std::string basename(std::string value);
}
