#pragma once
#include "engine.hpp"
#include <atomic>
#include <functional>
namespace rs {
using EventSink = std::function<void(const Event&)>;
using HealthSink = std::function<void(std::uint64_t,std::uint64_t)>;
void collect(std::atomic_bool& stop, const EventSink& event_sink, const HealthSink& health_sink);
}
