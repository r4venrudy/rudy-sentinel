#include "engine.hpp"
#include <algorithm>
#include <cctype>
#include <set>
#include <stdexcept>
namespace rs {
std::string lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
}
std::string basename(std::string value) {
    auto position = value.find_last_of("\\/");
    return lower(position == std::string::npos ? value : value.substr(position + 1));
}
static std::uint64_t number(const Json& j, const char* key, std::uint64_t fallback = 0) {
    if (!j.contains(key)) return fallback;
    if (!j[key].is_number_unsigned() && !(j[key].is_number_integer() && j[key].get<std::int64_t>() >= 0))
        throw std::runtime_error(std::string("invalid nonnegative integer: ") + key);
    return j[key].get<std::uint64_t>();
}
static std::uint32_t pid_number(const Json& j, const char* key) {
    auto value = number(j, key);
    if (value > UINT32_MAX) throw std::runtime_error(std::string("integer out of range: ") + key);
    return static_cast<std::uint32_t>(value);
}
Event parse_event(const Json& j) {
    if (!j.is_object() || number(j, "version") != 1) throw std::runtime_error("unsupported event version");
    Event e;
    e.sequence = number(j, "sequence"); e.time_ms = number(j, "time_ms");
    e.pid = pid_number(j, "pid"); e.parent = pid_number(j, "parent_pid");
    e.target = pid_number(j, "target_pid"); e.access = pid_number(j, "access_mask"); e.flags = pid_number(j, "flags");
    e.type = j.at("type").get<std::string>(); e.image = j.value("image", ""); e.command = j.value("command", "");
    e.process_image = j.value("process_image", ""); e.target_image = j.value("target_image", "");
    static const std::set<std::string> types{"process_start", "process_exit", "image_load", "handle_request"};
    if (!e.sequence || !types.contains(e.type) || e.image.size() > 16384 || e.command.size() > 16384 || e.process_image.size() > 16384 || e.target_image.size() > 16384)
        throw std::runtime_error("invalid event sequence, type, or text length");
    return e;
}
Json event_json(const Event& e) {
    return {{"version",1},{"sequence",e.sequence},{"time_ms",e.time_ms},{"type",e.type},
        {"pid",e.pid},{"parent_pid",e.parent},{"target_pid",e.target},{"access_mask",e.access},
        {"flags",e.flags},{"image",e.image},{"command",e.command},{"process_image",e.process_image},{"target_image",e.target_image}};
}
Engine::Engine(Json config, std::size_t capacity) : config_(std::move(config)), capacity_(capacity) {
    if (!capacity_ || capacity_ > 100000 || config_.value("version",0) != 1 || !config_.contains("rules") ||
        !config_["rules"].is_array() || config_["rules"].size() > 256) throw std::runtime_error("invalid ruleset or state capacity");
    auto window = number(config_, "window_ms", 120000);
    if (!window || window > 86400000) throw std::runtime_error("window_ms must be between 1 and 86400000");
    std::set<std::string> ids;
    const std::set<std::string> fields{"id","title","severity","score","mitre","event","image_names","parent_names","command_any","command_all","switch_any","path_any","target_names","access_all","sequence"};
    const std::set<std::string> events{"process_start","process_exit","image_load","handle_request"};
    for (const auto& rule : config_["rules"]) {
        auto id = rule.at("id").get<std::string>();
        if (id.empty() || !ids.insert(id).second || !rule.at("title").is_string() ||
            !rule.at("mitre").is_string() || !rule.at("severity").is_string()) throw std::runtime_error("invalid or duplicate rule id");
        int score = rule.at("score").get<int>();
        if (score < 1 || score > 100) throw std::runtime_error("invalid rule score");
        for (auto it = rule.begin(); it != rule.end(); ++it) if (!fields.contains(it.key())) throw std::runtime_error("unknown rule field: " + it.key());
        if (rule.contains("sequence")) {
            if (!rule["sequence"].is_array() || rule["sequence"].size() != 2) throw std::runtime_error("sequence requires exactly two stages");
            for (const auto& stage : rule["sequence"]) if (!stage.is_string() || !ids.contains(stage.get<std::string>()) || stage == id) throw std::runtime_error("sequence must refer to earlier rules");
            continue;
        }
        if (!events.contains(rule.at("event").get<std::string>())) throw std::runtime_error("invalid rule event");
        for (const char* field : {"image_names","parent_names","command_any","command_all","switch_any","path_any","target_names"}) {
            if (!rule.contains(field)) continue;
            if (!rule[field].is_array() || rule[field].empty()) throw std::runtime_error("rule condition requires a nonempty array");
            for (const auto& term : rule[field]) if (!term.is_string() || term.get<std::string>().empty()) throw std::runtime_error("rule term must be nonempty text");
        }
        if (rule.contains("access_all") && number(rule,"access_all") > UINT32_MAX) throw std::runtime_error("access mask out of range");
    }
}
Process& Engine::ensure(const Event& e) {
    if (e.type == "process_start" || !active_.contains(e.pid)) {
        if (active_.contains(e.pid)) {
            auto old = active_.at(e.pid); processes_.at(old).active = false; processes_.at(old).exited = e.time_ms;
        }
        while (processes_.size() >= capacity_) {
            auto old = order_.front(); order_.pop_front(); auto it = processes_.find(old);
            if (it != processes_.end()) {
                auto a = active_.find(it->second.pid);
                if (a != active_.end() && a->second == old) active_.erase(a);
                processes_.erase(it); hits_.erase(old); ++evictions_;
            }
        }
        Process p;
        p.id = std::to_string(e.pid) + ":" + std::to_string(e.sequence); p.pid = e.pid; p.parent = e.parent;
        p.started = e.time_ms;
        p.image = e.type == "process_start" ? e.image : (e.process_image.empty() ? "[unobserved process]" : e.process_image);
        p.command = e.type == "process_start" ? e.command : "";
        if (active_.contains(e.parent) && e.parent != e.pid) p.parent_id = active_.at(e.parent);
        active_[e.pid] = p.id; order_.push_back(p.id); processes_[p.id] = std::move(p);
    }
    return processes_.at(active_.at(e.pid));
}
static bool terms(const Json& r, const char* key, const std::string& text, bool exact = false, bool all = false) {
    if (!r.contains(key)) return true;
    auto test = [&](const Json& term) { auto t = lower(term.get<std::string>()); return exact ? text == t : text.find(t) != std::string::npos; };
    return all ? std::all_of(r[key].begin(),r[key].end(),test) : std::any_of(r[key].begin(),r[key].end(),test);
}
static std::vector<std::string> tokens(const std::string& input) {
    std::vector<std::string> result; std::string current; bool quoted = false;
    for (char c : lower(input)) {
        if (c == '"') quoted = !quoted;
        else if (!quoted && std::isspace(static_cast<unsigned char>(c))) { if (!current.empty()) { result.push_back(current); current.clear(); } }
        else current += c;
    }
    if (!current.empty()) result.push_back(current);
    return result;
}
bool Engine::matches(const Json& rule, const Event& e, const Process& p) const {
    if (rule.at("event") != e.type) return false;
    std::string parent, target;
    if (processes_.contains(p.parent_id)) parent = basename(processes_.at(p.parent_id).image);
    if (active_.contains(e.target)) target = basename(processes_.at(active_.at(e.target)).image);
    else target = basename(e.target_image);
    if (!terms(rule,"image_names",basename(p.image),true) || !terms(rule,"parent_names",parent,true) ||
        !terms(rule,"target_names",target,true) || !terms(rule,"command_any",lower(e.command)) ||
        !terms(rule,"command_all",lower(e.command),false,true) || !terms(rule,"path_any",lower(e.image))) return false;
    if (rule.contains("access_all")) { auto mask = rule["access_all"].get<std::uint32_t>(); if ((e.access & mask) != mask) return false; }
    if (rule.contains("switch_any")) {
        auto args = tokens(e.command); bool found = false;
        for (const auto& arg : args) for (const auto& term : rule["switch_any"]) if (arg == lower(term.get<std::string>())) found = true;
        if (!found) return false;
    }
    return true;
}
int Engine::risk(const std::string& id) const {
    auto it = hits_.find(id); if (it == hits_.end()) return 0;
    int total = 0; for (const auto& hit : it->second) if (last_time_ - hit.time <= number(config_,"window_ms",120000)) total += hit.score;
    return std::min(total,100);
}
Json Engine::alert(const Json& rule, const Event& e, const Process& p, const std::vector<std::uint64_t>& evidence) {
    return {{"kind","alert"},{"id",p.id + ":" + rule["id"].get<std::string>() + ":" + std::to_string(e.sequence)},
        {"rule_id",rule["id"]},{"title",rule["title"]},{"severity",rule["severity"]},{"mitre",rule["mitre"]},
        {"time_ms",e.time_ms},{"sequence",e.sequence},{"process_id",p.id},{"pid",p.pid},{"image",p.image},
        {"parent_id",p.parent_id},{"risk",risk(p.id)},{"evidence_sequences",evidence},
        {"event",event_json(e)},{"interpretation","Behavioral signal requiring investigation; not a malware verdict."}};
}
std::vector<Json> Engine::consume(const Event& e) {
    if (e.sequence <= last_sequence_) throw std::runtime_error("events must have strictly increasing sequence numbers");
    /* Kernel wall-clock timestamps may go backwards: use a monotonic watermark for correlation expiry. */
    last_time_ = std::max(last_time_,e.time_ms); last_sequence_ = e.sequence; ++events_;
    auto& p = ensure(e); auto& hits = hits_[p.id];
    const auto window = number(config_,"window_ms",120000);
    while (!hits.empty() && last_time_ - hits.front().time > window) hits.pop_front();
    std::vector<Json> output;
    for (const auto& rule : config_["rules"]) {
        auto id = rule["id"].get<std::string>();
        if (std::any_of(hits.begin(),hits.end(),[&](const Hit& h) { return h.rule == id; })) continue;
        std::vector<std::uint64_t> evidence{e.sequence}; bool matched = false;
        if (rule.contains("sequence")) {
            auto first = rule["sequence"][0].get<std::string>(), second = rule["sequence"][1].get<std::string>();
            const Hit* a = nullptr; const Hit* b = nullptr;
            for (const auto& hit : hits) { if (hit.rule == first) a = &hit; if (hit.rule == second) b = &hit; }
            matched = a && b && a->sequence <= b->sequence && b->sequence == e.sequence;
            if (matched) evidence = {a->sequence,b->sequence};
        } else matched = matches(rule,e,p);
        if (matched) {
            hits.push_back({id,last_time_,e.sequence,rule["score"].get<int>()});
            output.push_back(alert(rule,e,p,evidence));
        }
    }
    if (e.type == "process_exit") { p.active = false; p.exited = e.time_ms; active_.erase(e.pid); }
    return output;
}
Json Engine::health(std::uint64_t dropped, std::uint64_t allocations, std::uint64_t time) {
    Json result = nullptr;
    if (dropped > dropped_ || allocations > allocations_) result = {{"kind","health"},{"severity","high"},
        {"title","Sensor telemetry was lost"},{"time_ms",time},{"dropped",dropped},{"allocation_failures",allocations}};
    dropped_ = dropped; allocations_ = allocations; return result;
}
Json Engine::snapshot() const {
    Json values = Json::array();
    for (const auto& id : order_) {
        auto it = processes_.find(id); if (it == processes_.end()) continue; const auto& p = it->second;
        values.push_back({{"id",p.id},{"pid",p.pid},{"parent_pid",p.parent},{"parent_id",p.parent_id},
            {"image",p.image},{"command",p.command},{"active",p.active},{"started_ms",p.started},{"exited_ms",p.exited},{"risk",risk(p.id)}});
    }
    return {{"version",1},{"events",events_},{"processes",values},{"evictions",evictions_},
        {"sensor_dropped",dropped_},{"sensor_allocation_failures",allocations_}};
}
}
