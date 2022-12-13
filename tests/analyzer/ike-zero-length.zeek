# @TEST-EXEC: zeek -C -r ${TRACES}/ipsec-ikev1-zero-length.pcap %INPUT
# @TEST-EXEC: btest-diff conn.log
#
# @TEST-DOC: Test that IPSecIKE with length 0 does not produce integer overflow analyzer errors

@load analyzer
