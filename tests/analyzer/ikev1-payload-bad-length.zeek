# @TEST-EXEC: zeek -C -r ${TRACES}/ipsec-ikev1-payload-bad-length.pcap %INPUT
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: grep -q failed weird.log
#
# @TEST-DOC: Test that IPSecIKE with length 0 does not produce integer overflow analyzer errors

@load analyzer
