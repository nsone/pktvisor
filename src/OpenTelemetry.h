/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include "HttpServer.h"
#include <atomic>
#include <functional>
#include <timer.hpp>
#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#pragma GCC diagnostic ignored "-Woverflow"
#pragma GCC diagnostic ignored "-Wzero-as-null-pointer-constant"
#endif
#include "opentelemetry/proto/collector/metrics/v1/metrics_service.pb.h"
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

namespace visor {

constexpr char BIN_CONTENT_TYPE[] = "application/x-protobuf";

using namespace opentelemetry::proto;

struct OtelConfig {
    bool enable{false};
    std::string endpoint{"localhost"};
    std::string path{"/v1/metrics"};
    uint32_t port_number{4318};
    uint64_t interval_sec{60};
    std::string tls_cert;
    std::string tls_key;
};

class OpenTelemetry
{
    std::unique_ptr<httplib::Client> _client;
    // _in_flight prevents concurrent exports when a slow tick overlaps the next
    // interval fired by the thread-pool timer.  test_and_set returns false only
    // for the first caller; subsequent ticks see true and skip.
    std::atomic_flag _in_flight = ATOMIC_FLAG_INIT;
    timer _timer_thread;
    std::shared_ptr<timer::interval_handle> _timer_handle;
    std::function<bool(metrics::v1::ResourceMetrics &resource)> _callback;

public:
    OpenTelemetry(const OtelConfig &config)
        : _timer_thread{std::chrono::seconds(config.interval_sec)}
    {
        if (!config.tls_cert.empty() && !config.tls_key.empty()) {
            _client = std::make_unique<httplib::Client>(config.endpoint, config.port_number, config.tls_cert, config.tls_key);
        } else {
            _client = std::make_unique<httplib::Client>(config.endpoint, config.port_number);
        }
        auto path = config.path;
        _timer_handle = _timer_thread.set_interval(std::chrono::seconds(config.interval_sec), [path, this] {
            // Skip this tick if the previous export is still running.
            if (_in_flight.test_and_set(std::memory_order_acquire)) {
                return;
            }
            // Build a fresh request each tick so there is no shared mutable
            // protobuf state between concurrent (or sequential) callbacks.
            collector::metrics::v1::ExportMetricsServiceRequest request;
            auto *resource = request.add_resource_metrics();
            if (_callback && _callback(*resource)) {
                if (auto body_size = request.ByteSizeLong(); body_size > sizeof(request)) {
                    auto body = std::make_unique<char[]>(body_size);
                    request.SerializeToArray(body.get(), body_size);
                    _client->Post(path, body.get(), body_size, BIN_CONTENT_TYPE);
                }
            }
            _in_flight.clear(std::memory_order_release);
        });
    }

    ~OpenTelemetry()
    {
        _timer_handle->cancel();
    }

    void OnInterval(std::function<bool(metrics::v1::ResourceMetrics &resource)> callback)
    {
        _callback = callback;
    }
};
}