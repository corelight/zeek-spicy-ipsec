# @TEST-REQUIRES: test -e ${TRACES}/IPsec_ESP-AH_tunnel_mode.cap
# @TEST-EXEC: zeek -Cr ${TRACES}/IPsec_ESP-AH_tunnel_mode.cap %INPUT
# @TEST-EXEC: btest-diff .stdout
#
# @TEST-DOC: Test IPSEC against Zeek with a small trace.

@load analyzer

event IPSEC::ah_message_over_ip(p: raw_pkt_hdr, spi: count, seq: count, payload_len: count) { print cat("ah_message_over_ip ", p$ip$src, p$ip$dst, spi, seq, payload_len); }
event IPSEC::esp_message_over_ip(p: raw_pkt_hdr, spi: count, seq: count, payload_len: count) { print cat("esp_message_over_ip ", p$ip$src, p$ip$dst, spi, seq, payload_len); }
