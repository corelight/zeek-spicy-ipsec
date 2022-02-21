# @TEST-EXEC: zeek -C -r ${TRACES}/ipsec-ikev1-zero-length.pcap %INPUT
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: zeek-cut -c uid name addl < weird.log > weird.log.cut
# @TEST-EXEC: btest-diff weird.log.cut
#
# @TEST-DOC: Test that IPSecIKE with length 0 does not produce integer overflow analyzer errors

@load analyzer
