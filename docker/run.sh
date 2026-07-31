#!/bin/bash
shift
# omitting --cp-token "CP_TOKEN" --cp-url "CP_URL" as crashpad is inaccessible to NS1
pktvisord --cp-path "/usr/local/sbin/crashpad_handler" --default-geo-city "/geo-db/city.mmdb" --default-geo-asn "/geo-db/asn.mmdb" --default-service-registry "/iana/custom-iana.csv" "$@" &
echo $! > /var/run/pktvisord.pid