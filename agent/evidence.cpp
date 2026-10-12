#include "evidence.hpp"
#include "engine.hpp"
#include <rudy/evidence.hpp>
#include <array>
#include <fstream>
#include <stdexcept>
std::string export_evidence(const std::filesystem::path& alerts, const std::string& scope) {
    if (scope.empty()) throw std::runtime_error("Evidence export requires --scope HOST_SESSION_ID");
    std::ifstream in(alerts, std::ios::binary);
    if (!in) throw std::runtime_error("Cannot open alert file");
    std::string raw; std::array<char, 8192> buffer{};
    while (in) {
        in.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
        auto n = static_cast<std::size_t>(in.gcount());
        if (n > rudy::evidence::max_input_bytes - raw.size()) throw std::runtime_error("Alert file exceeds SDK limit");
        raw.append(buffer.data(), n);
    }
    if (in.bad()) throw std::runtime_error("Cannot read alert file");
    return rudy::evidence::process(rs::Json{{"operation", "normalize-lines"}, {"format", "rudy-sentinel"}, {"scope", scope}, {"text", raw}}.dump());
}
