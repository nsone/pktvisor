/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "DnsStreamHandler.h"
#include "GeoDB.h"
#include "utils.h"
#include <Corrade/Utility/Debug.h>
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma clang diagnostic ignored "-Wc99-extensions"
#pragma GCC diagnostic ignored "-Wpedantic"
#include <IPv4Layer.h>
#include <IPv6Layer.h>
#pragma GCC diagnostic pop
#include <arpa/inet.h>
#include <sstream>

namespace visor::handler::dns {

DnsStreamHandler::DnsStreamHandler(const std::string &name, InputStream *stream, const Configurable *window_config)
    : visor::StreamMetricsHandler<DnsMetricsManager>(name, window_config)
{
    assert(stream);
    // figure out which input stream we have
    _pcap_stream = dynamic_cast<PcapInputStream *>(stream);
    _mock_stream = dynamic_cast<MockInputStream *>(stream);
    if (!_pcap_stream && !_mock_stream) {
        throw StreamHandlerException(fmt::format("NetStreamHandler: unsupported input stream {}", stream->name()));
    }
}

void DnsStreamHandler::start()
{
    if (_running) {
        return;
    }

    // Setup Filters
    if (config_exists("exclude_noerror") && config_get<bool>("exclude_noerror")) {
        _f_enabled.set(Filters::ExcludingRCode);
        _f_rcode = NoError;
    } else if (config_exists("only_rcode")) {
        auto want_code = config_get<uint64_t>("only_rcode");
        switch (want_code) {
        case NoError:
        case NXDomain:
        case SrvFail:
        case Refused:
            _f_enabled.set(Filters::OnlyRCode);
            _f_rcode = want_code;
            break;
        default:
            throw ConfigException("only_rcode contained an invalid/unsupported rcode");
        }
    }
    if (config_exists("only_qname_suffix")) {
        _f_enabled.set(Filters::OnlyQNameSuffix);
        for (const auto &qname : config_get<StringList>("only_qname_suffix")) {
            // note, this currently copies the strings, meaning there could be a big list that is duplicated
            // we can work on trying to make this a string_view instead
            // we copy it out so that we don't have to hit the config mutex
            std::string qname_ci{qname};
            std::transform(qname_ci.begin(), qname_ci.end(), qname_ci.begin(),
                [](unsigned char c) { return std::tolower(c); });
            _f_qnames.emplace_back(std::move(qname_ci));
        }
    }

    if (config_exists("recorded_stream")) {
        _metrics->set_recorded_stream();
    }

    if (_pcap_stream) {
        _pkt_udp_connection = _pcap_stream->udp_signal.connect(&DnsStreamHandler::process_udp_packet_cb, this);
        _start_tstamp_connection = _pcap_stream->start_tstamp_signal.connect(&DnsStreamHandler::set_start_tstamp, this);
        _end_tstamp_connection = _pcap_stream->end_tstamp_signal.connect(&DnsStreamHandler::set_end_tstamp, this);
        _tcp_start_connection = _pcap_stream->tcp_connection_start_signal.connect(&DnsStreamHandler::tcp_connection_start_cb, this);
        _tcp_end_connection = _pcap_stream->tcp_connection_end_signal.connect(&DnsStreamHandler::tcp_connection_end_cb, this);
        _tcp_message_connection = _pcap_stream->tcp_message_ready_signal.connect(&DnsStreamHandler::tcp_message_ready_cb, this);
    }

    _running = true;
}

void DnsStreamHandler::stop()
{
    if (!_running) {
        return;
    }

    if (_pcap_stream) {
        _pkt_udp_connection.disconnect();
        _start_tstamp_connection.disconnect();
        _end_tstamp_connection.disconnect();
        _tcp_start_connection.disconnect();
        _tcp_end_connection.disconnect();
        _tcp_message_connection.disconnect();
    }

    _running = false;
}

// callback from input module
void DnsStreamHandler::process_udp_packet_cb(pcpp::Packet &payload, PacketDirection dir, pcpp::ProtocolType l3, uint32_t flowkey, timespec stamp)
{
    pcpp::UdpLayer *udpLayer = payload.getLayerOfType<pcpp::UdpLayer>();
    assert(udpLayer);

    uint16_t metric_port{0};
    auto dst_port = ntohs(udpLayer->getUdpHeader()->portDst);
    auto src_port = ntohs(udpLayer->getUdpHeader()->portSrc);
    // note we want to capture metrics only when one of the ports is dns,
    // but metrics on the port which is _not_ the dns port
    if (DnsLayer::isDnsPort(dst_port)) {
        metric_port = src_port;
    } else if (DnsLayer::isDnsPort(src_port)) {
        metric_port = dst_port;
    }
    if (metric_port) {
        DnsLayer dnsLayer(udpLayer, &payload);
        if (!_filtering(dnsLayer, dir, l3, pcpp::UDP, metric_port, stamp)) {
            _metrics->process_dns_layer(dnsLayer, dir, l3, pcpp::UDP, flowkey, metric_port, stamp);
        }
    }
}

void TcpSessionData::receive_dns_wire_data(const uint8_t *data, size_t len)
{
    const size_t MIN_DNS_QUERY_SIZE = 17;
    const size_t MAX_DNS_QUERY_SIZE = 512;

    _buffer.append(reinterpret_cast<const char *>(data), len);

    for (;;) {
        std::uint16_t size;

        if (_buffer.size() < sizeof(size)) {
            break;
        }

        // dns packet size is in network byte order.
        size = static_cast<unsigned char>(_buffer[1]) | static_cast<unsigned char>(_buffer[0]) << 8;

        // ensure we never allocate more than max
        if (size < MIN_DNS_QUERY_SIZE || size > MAX_DNS_QUERY_SIZE) {
            break;
        }

        if (_buffer.size() >= sizeof(size) + size) {
            auto data = std::make_unique<uint8_t[]>(size);
            std::memcpy(data.get(), _buffer.data() + sizeof(size), size);
            _buffer.erase(0, sizeof(size) + size);
            _got_dns_msg(std::move(data), size);
        } else {
            // Nope, we need more data.
            break;
        }
    }
}

void DnsStreamHandler::tcp_message_ready_cb(int8_t side, const pcpp::TcpStreamData &tcpData)
{
    auto flowKey = tcpData.getConnectionData().flowKey;

    // check if this flow already appears in the connection manager. If not add it
    auto iter = _tcp_connections.find(flowKey);

    // if not tracking connection, and it's DNS, then start tracking.
    if (iter == _tcp_connections.end()) {
        // note we want to capture metrics only when one of the ports is dns,
        // but metrics on the port which is _not_ the dns port
        uint16_t metric_port{0};
        if (DnsLayer::isDnsPort(tcpData.getConnectionData().dstPort)) {
            metric_port = tcpData.getConnectionData().srcPort;
        } else if (DnsLayer::isDnsPort(tcpData.getConnectionData().srcPort)) {
            metric_port = tcpData.getConnectionData().dstPort;
        }
        if (metric_port) {
            _tcp_connections.emplace(flowKey, TcpFlowData(tcpData.getConnectionData().srcIP.getType() == pcpp::IPAddress::IPv4AddressType, metric_port));
            iter = _tcp_connections.find(tcpData.getConnectionData().flowKey);
        } else {
            // not tracking
            return;
        }
    }

    pcpp::ProtocolType l3Type{iter->second.l3Type};
    auto port{iter->second.port};
    timespec stamp{0, 0};
    // for tcp, endTime is updated by pcpp to represent the time stamp from the latest packet in the stream
    TIMEVAL_TO_TIMESPEC(&tcpData.getConnectionData().endTime, &stamp)
    auto dir = (side == 0) ? PacketDirection::fromHost : PacketDirection::toHost;

    auto got_dns_message = [this, port, dir, l3Type, flowKey, stamp](std::unique_ptr<uint8_t[]> data, size_t size) {
        // this dummy packet prevents DnsLayer from owning and trying to free the data. it is otherwise unused by the DNS layer,
        // instead using the packet meta data we pass in
        pcpp::Packet dummy_packet;
        DnsLayer dnsLayer(data.get(), size, nullptr, &dummy_packet);
        if (!_filtering(dnsLayer, dir, l3Type, pcpp::UDP, port, stamp)) {
            _metrics->process_dns_layer(dnsLayer, dir, l3Type, pcpp::TCP, flowKey, port, stamp);
        }
        // data is freed upon return
    };

    if (!iter->second.sessionData[side]) {
        iter->second.sessionData[side] = std::make_unique<TcpSessionData>(got_dns_message);
    }

    iter->second.sessionData[side]->receive_dns_wire_data(tcpData.getData(), tcpData.getDataLength());
}

void DnsStreamHandler::tcp_connection_start_cb(const pcpp::ConnectionData &connectionData)
{
    // look for the connection
    auto iter = _tcp_connections.find(connectionData.flowKey);

    // note we want to capture metrics only when one of the ports is dns,
    // but metrics on the port which is _not_ the dns port
    uint16_t metric_port{0};
    if (DnsLayer::isDnsPort(connectionData.dstPort)) {
        metric_port = connectionData.srcPort;
    } else if (DnsLayer::isDnsPort(connectionData.srcPort)) {
        metric_port = connectionData.dstPort;
    }
    if (iter == _tcp_connections.end() && metric_port) {
        // add it to the connections
        _tcp_connections.emplace(connectionData.flowKey, TcpFlowData(connectionData.srcIP.getType() == pcpp::IPAddress::IPv4AddressType, metric_port));
    }
}

void DnsStreamHandler::tcp_connection_end_cb(const pcpp::ConnectionData &connectionData, [[maybe_unused]] pcpp::TcpReassembly::ConnectionEndReason reason)
{
    // find the connection in the connections by the flow key
    auto iter = _tcp_connections.find(connectionData.flowKey);

    // connection wasn't found, we didn't track
    if (iter == _tcp_connections.end()) {
        return;
    }

    // remove the connection from the connection manager
    _tcp_connections.erase(iter);
}
void DnsStreamHandler::set_start_tstamp(timespec stamp)
{
    _metrics->set_start_tstamp(stamp);
}
void DnsStreamHandler::set_end_tstamp(timespec stamp)
{
    _metrics->set_end_tstamp(stamp);
}
void DnsStreamHandler::info_json(json &j) const
{
    common_info_json(j);
    j[schema_key()]["xact"]["open"] = _metrics->num_open_transactions();
}
static inline bool endsWith(std::string_view str, std::string_view suffix)
{
    return str.size() >= suffix.size() && 0 == str.compare(str.size() - suffix.size(), suffix.size(), suffix);
}
bool DnsStreamHandler::_filtering(DnsLayer &payload, [[maybe_unused]] PacketDirection dir, [[maybe_unused]] pcpp::ProtocolType l3, [[maybe_unused]] pcpp::ProtocolType l4, [[maybe_unused]] uint16_t port, timespec stamp)
{
    if (_f_enabled.test(Filters::ExcludingRCode) && payload.getDnsHeader()->responseCode == _f_rcode) {
        goto will_filter;
    } else if (_f_enabled.test(Filters::OnlyRCode) && payload.getDnsHeader()->responseCode != _f_rcode) {
        goto will_filter;
    }
    if (_f_enabled.test(Filters::OnlyQNameSuffix)) {
        if (!payload.parseResources(true) || payload.getFirstQuery() == nullptr) {
            goto will_filter;
        }
        // we need an all lower case version of this, we can't get away without making a copy
        std::string qname_ci{payload.getFirstQuery()->getName()};
        std::transform(qname_ci.begin(), qname_ci.end(), qname_ci.begin(),
            [](unsigned char c) { return std::tolower(c); });
        for (auto fqn : _f_qnames) {
            // if it matched, we know we are not filtering
            if (endsWith(qname_ci, fqn)) {
                goto will_not_filter;
            }
        }
        // checked the whole list and none of them matched: filter
        goto will_filter;
    }
will_not_filter:
    return false;
will_filter:
    _metrics->process_filtered(stamp);
    return true;
}

void DnsMetricsBucket::specialized_merge(const AbstractMetricsBucket &o)
{
    // static because caller guarantees only our own bucket type
    const auto &other = static_cast<const DnsMetricsBucket &>(o);

    std::shared_lock r_lock(other._mutex);
    std::unique_lock w_lock(_mutex);

    _counters.xacts_total += other._counters.xacts_total;
    _counters.xacts_in += other._counters.xacts_in;
    _counters.xacts_out += other._counters.xacts_out;
    _counters.xacts_timed_out += other._counters.xacts_timed_out;
    _counters.queries += other._counters.queries;
    _counters.replies += other._counters.replies;
    _counters.UDP += other._counters.UDP;
    _counters.TCP += other._counters.TCP;
    _counters.IPv4 += other._counters.IPv4;
    _counters.IPv6 += other._counters.IPv6;
    _counters.NX += other._counters.NX;
    _counters.REFUSED += other._counters.REFUSED;
    _counters.SRVFAIL += other._counters.SRVFAIL;
    _counters.NOERROR += other._counters.NOERROR;

    _counters.filtered += other._counters.filtered;

    _dnsXactFromTimeUs.merge(other._dnsXactFromTimeUs);
    _dnsXactToTimeUs.merge(other._dnsXactToTimeUs);

    _dns_qnameCard.merge(other._dns_qnameCard);

    _dns_topQname2.merge(other._dns_topQname2);
    _dns_topQname3.merge(other._dns_topQname3);
    _dns_topNX.merge(other._dns_topNX);
    _dns_topREFUSED.merge(other._dns_topREFUSED);
    _dns_topSRVFAIL.merge(other._dns_topSRVFAIL);
    _dns_topUDPPort.merge(other._dns_topUDPPort);
    _dns_topQType.merge(other._dns_topQType);
    _dns_topRCode.merge(other._dns_topRCode);
    _dns_topOrgID.merge(other._dns_topOrgID);
    _dns_slowXactIn.merge(other._dns_slowXactIn);
    _dns_slowXactOut.merge(other._dns_slowXactOut);
}

void DnsMetricsBucket::to_json(json &j) const
{

    bool live_rates = !read_only() && !recorded_stream();

    {
        auto [num_events, num_samples, event_rate, event_lock] = event_data_locked(); // thread safe

        event_rate->to_json(j, live_rates);
        num_events->to_json(j);
        num_samples->to_json(j);
    }

    std::shared_lock r_lock(_mutex);

    _counters.queries.to_json(j);
    _counters.replies.to_json(j);
    _counters.TCP.to_json(j);
    _counters.UDP.to_json(j);
    _counters.IPv4.to_json(j);
    _counters.IPv6.to_json(j);
    _counters.NX.to_json(j);
    _counters.REFUSED.to_json(j);
    _counters.SRVFAIL.to_json(j);
    _counters.NOERROR.to_json(j);

    _counters.filtered.to_json(j);

    _dns_qnameCard.to_json(j);
    _counters.xacts_total.to_json(j);
    _counters.xacts_timed_out.to_json(j);

    _counters.xacts_in.to_json(j);
    _dns_slowXactIn.to_json(j);

    _dnsXactFromTimeUs.to_json(j);
    _dnsXactToTimeUs.to_json(j);

    _counters.xacts_out.to_json(j);
    _dns_slowXactOut.to_json(j);

    _dns_topUDPPort.to_json(j, [](const uint16_t &val) { return std::to_string(val); });
    _dns_topQname2.to_json(j);
    _dns_topQname3.to_json(j);
    _dns_topNX.to_json(j);
    _dns_topREFUSED.to_json(j);
    _dns_topSRVFAIL.to_json(j);
    _dns_topRCode.to_json(j, [](const uint16_t &val) {
        if (RCodeNames.find(val) != RCodeNames.end()) {
            return RCodeNames[val];
        } else {
            return std::to_string(val);
        }
    });
    _dns_topOrgID.to_json(j, [](const uint64_t &val) {
        return std::to_string(val);
    });
    _dns_topQType.to_json(j, [](const uint16_t &val) {
        if (QTypeNames.find(val) != QTypeNames.end()) {
            return QTypeNames[val];
        } else {
            return std::to_string(val);
        }
    });
}

// the main bucket analysis
void DnsMetricsBucket::process_dns_layer(bool deep, DnsLayer &payload, pcpp::ProtocolType l3, pcpp::ProtocolType l4, uint16_t port)
{

    std::unique_lock lock(_mutex);

    if (l3 == pcpp::IPv6) {
        ++_counters.IPv6;
    } else {
        ++_counters.IPv4;
    }

    if (l4 == pcpp::TCP) {
        ++_counters.TCP;
    } else {
        ++_counters.UDP;
    }

    // only count response codes on responses (not queries)
    if (payload.getDnsHeader()->queryOrResponse == QR::response) {
        ++_counters.replies;
        switch (payload.getDnsHeader()->responseCode) {
        case NoError:
            ++_counters.NOERROR;
            break;
        case SrvFail:
            ++_counters.SRVFAIL;
            break;
        case NXDomain:
            ++_counters.NX;
            break;
        case Refused:
            ++_counters.REFUSED;
            break;
        }
    } else {
        ++_counters.queries;
    }

    if (!deep) {
        return;
    }

    _dns_topUDPPort.update(port);

    auto success = payload.parseResources(true);
    if (!success) {
        return;
    }

    if (payload.getDnsHeader()->queryOrResponse == response) {
        _dns_topRCode.update(payload.getDnsHeader()->responseCode);
    }

    auto query = payload.getFirstQuery();
    if (query) {

        auto name = query->getName();
        _dns_qnameCard.update(name);

        _dns_topQType.update(query->getDnsType());

        if (payload.getDnsHeader()->queryOrResponse == response) {
            switch (payload.getDnsHeader()->responseCode) {
            case SrvFail:
                _dns_topSRVFAIL.update(name);
                break;
            case NXDomain:
                _dns_topNX.update(name);
                break;
            case Refused:
                _dns_topREFUSED.update(name);
                break;
            }
        }

        auto aggDomain = aggregateDomain(name);
        _dns_topQname2.update(std::string(aggDomain.first));
        if (aggDomain.second.size()) {
            _dns_topQname3.update(std::string(aggDomain.second));
        }


//        uint64_t orgID = 0;
        _dns_topOrgID.update(1632);
    }
}

void DnsMetricsBucket::new_dns_transaction(bool deep, float to90th, float from90th, DnsLayer &dns, PacketDirection dir, DnsTransaction xact)
{

    uint64_t xactTime = ((xact.totalTS.tv_sec * 1'000'000'000L) + xact.totalTS.tv_nsec) / 1'000; // nanoseconds to microseconds

    // lock for write
    std::unique_lock lock(_mutex);

    ++_counters.xacts_total;

    if (dir == PacketDirection::toHost) {
        ++_counters.xacts_out;
        if (deep) {
            _dnsXactFromTimeUs.update(xactTime);
        }
    } else if (dir == PacketDirection::fromHost) {
        ++_counters.xacts_in;
        if (deep) {
            _dnsXactToTimeUs.update(xactTime);
        }
    }

    if (deep) {
        auto query = dns.getFirstQuery();
        if (query) {
            auto name = query->getName();
            // dir is the direction of the last packet, meaning the reply so from a transaction perspective
            // we look at it from the direction of the query, so the opposite side than we have here
            if (dir == PacketDirection::toHost && from90th > 0 && xactTime >= from90th) {
                _dns_slowXactOut.update(name);
            } else if (dir == PacketDirection::fromHost && to90th > 0 && xactTime >= to90th) {
                _dns_slowXactIn.update(name);
            }
        }
    }
}
void DnsMetricsBucket::to_prometheus(std::stringstream &out, Metric::LabelMap add_labels) const
{

    {
        auto [num_events, num_samples, event_rate, event_lock] = event_data_locked(); // thread safe

        event_rate->to_prometheus(out, add_labels);
        num_events->to_prometheus(out, add_labels);
        num_samples->to_prometheus(out, add_labels);
    }

    std::shared_lock r_lock(_mutex);

    _counters.queries.to_prometheus(out, add_labels);
    _counters.replies.to_prometheus(out, add_labels);
    _counters.TCP.to_prometheus(out, add_labels);
    _counters.UDP.to_prometheus(out, add_labels);
    _counters.IPv4.to_prometheus(out, add_labels);
    _counters.IPv6.to_prometheus(out, add_labels);
    _counters.NX.to_prometheus(out, add_labels);
    _counters.REFUSED.to_prometheus(out, add_labels);
    _counters.SRVFAIL.to_prometheus(out, add_labels);
    _counters.NOERROR.to_prometheus(out, add_labels);

    _counters.filtered.to_prometheus(out, add_labels);

    _dns_qnameCard.to_prometheus(out, add_labels);
    _counters.xacts_total.to_prometheus(out, add_labels);
    _counters.xacts_timed_out.to_prometheus(out, add_labels);

    _counters.xacts_in.to_prometheus(out, add_labels);
    _dns_slowXactIn.to_prometheus(out, add_labels);

    _dnsXactFromTimeUs.to_prometheus(out, add_labels);
    _dnsXactToTimeUs.to_prometheus(out, add_labels);

    _counters.xacts_out.to_prometheus(out, add_labels);
    _dns_slowXactOut.to_prometheus(out, add_labels);

    _dns_topUDPPort.to_prometheus(out, add_labels, [](const uint16_t &val) { return std::to_string(val); });
    _dns_topQname2.to_prometheus(out, add_labels);
    _dns_topQname3.to_prometheus(out, add_labels);
    _dns_topNX.to_prometheus(out, add_labels);
    _dns_topREFUSED.to_prometheus(out, add_labels);
    _dns_topSRVFAIL.to_prometheus(out, add_labels);
    _dns_topRCode.to_prometheus(out, add_labels, [](const uint16_t &val) {
        if (RCodeNames.find(val) != RCodeNames.end()) {
            return RCodeNames[val];
        } else {
            return std::to_string(val);
        }
    });
    _dns_topQType.to_prometheus(out, add_labels, [](const uint16_t &val) {
        if (QTypeNames.find(val) != QTypeNames.end()) {
            return QTypeNames[val];
        } else {
            return std::to_string(val);
        }
    });
}
void DnsMetricsBucket::process_filtered()
{
    std::unique_lock lock(_mutex);
    ++_counters.filtered;
}

// the general metrics manager entry point (both UDP and TCP)
void DnsMetricsManager::process_dns_layer(DnsLayer &payload, PacketDirection dir, pcpp::ProtocolType l3, pcpp::ProtocolType l4, uint32_t flowkey, uint16_t port, timespec stamp)
{
    // base event
    new_event(stamp);
    // process in the "live" bucket. this will parse the resources if we are deep sampling
    live_bucket()->process_dns_layer(_deep_sampling_now, payload, l3, l4, port);
    // handle dns transactions (query/response pairs)
    if (payload.getDnsHeader()->queryOrResponse == QR::response) {
        auto xact = _qr_pair_manager.maybe_end_transaction(flowkey, payload.getDnsHeader()->transactionID, stamp);
        if (xact.first) {
            live_bucket()->new_dns_transaction(_deep_sampling_now, _to90th, _from90th, payload, dir, xact.second);
        }
    } else {
        _qr_pair_manager.start_transaction(flowkey, payload.getDnsHeader()->transactionID, stamp);
    }
}
void DnsMetricsManager::process_filtered(timespec stamp)
{
    // base event, no sample
    new_event(stamp, false);
    live_bucket()->process_filtered();
}
}
