# @TEST-EXEC: zeek -C -r ${TRACES}/ipsec-ikev1-zero-length.pcap %INPUT
# @TEST-EXEC: zeek-cut -m -n local_orig local_resp ip_proto < conn.log > conn.log.filtered
# @TEST-EXEC: btest-diff conn.log.filtered
#
# @TEST-DOC: Test that IPSecIKE with length 0 does not produce integer overflow analyzer errors

@load analyzer
