/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include "HttpServer.h"
#include <functional>
#include <mutex>
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
    // Serialises concurrent ticks: late tick waits up to interval/2 rather than discarding its window.
    std::timed_mutex _export_mutex;
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
        // Cap HTTP timeouts to interval/2 so a hung receiver cannot starve the bucket retention window.
        auto timeout = std::chrono::seconds(config.interval_sec / 2);
        auto timeout_sec = static_cast<time_t>(timeout.count());
        _client->set_connection_timeout(timeout_sec);
        _client->set_read_timeout(timeout_sec);
        _client->set_write_timeout(timeout_sec);
        auto path = config.path;
        _timer_handle = _timer_thread.set_interval(std::chrono::seconds(config.interval_sec), [path, timeout, this] {
            // Wait for any in-progress export; drop this tick only if the wait exceeds interval/2 (broken receiver).
            std::unique_lock<std::timed_mutex> lock(_export_mutex, timeout);
            if (!lock.owns_lock()) {
                return;
            }
            // Fresh request each tick: no shared mutable protobuf state between ticks.
            collector::metrics::v1::ExportMetricsServiceRequest request;
            auto *resource = request.add_resource_metrics();
            if (_callback && _callback(*resource)) {
                if (auto body_size = request.ByteSizeLong(); body_size > sizeof(request)) {
                    auto body = std::make_unique<char[]>(body_size);
                    request.SerializeToArray(body.get(), body_size);
                    _client->Post(path, body.get(), body_size, BIN_CONTENT_TYPE);
                }
            }
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