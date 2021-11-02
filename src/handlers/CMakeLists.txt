
add_subdirectory(net)
add_subdirectory(dns)
add_subdirectory(dhcp)
add_subdirectory(pcap)

add_subdirectory(ns1dns)

set(VISOR_STATIC_PLUGINS ${VISOR_STATIC_PLUGINS} PARENT_SCOPE)
