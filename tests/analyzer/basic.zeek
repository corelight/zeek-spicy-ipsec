# @TEST-REQUIRES: test -e ${TRACES}/ipsec_client.pcap
# @TEST-EXEC: zeek -Cr ${TRACES}/ipsec_client.pcap %INPUT
# @TEST-EXEC: zeek-cut -m -n local_orig local_resp ip_proto < conn.log > conn.log.filtered
# @TEST-EXEC: btest-diff ipsec.log
# @TEST-EXEC: btest-diff conn.log.filtered
# @TEST-EXEC: btest-diff .stdout
#
# @TEST-DOC: Test IPSEC against Zeek with a small trace.

@load analyzer

event IPSEC::ike_message(c: connection, is_orig: bool, msg: IPSEC::IKEMsg) { print cat("ike_message ", is_orig, c$uid, msg); }
event IPSEC::esp_message(c: connection, is_orig: bool, msg: IPSEC::ESPMsg) { print cat("esp_message ", is_orig, c$uid, msg); }
event IPSEC::ikev2_sa_proposal(c: connection, is_orig: bool, msg: IPSEC::IKE_SA_Proposal_Msg) { print cat("ike_sa_proposal ", is_orig, c$uid, msg); }
event IPSEC::ikev2_sa_transform(c: connection, is_orig: bool, msg: IPSEC::IKE_SA_Transform_Msg) { print cat("ike_sa_transform ", is_orig, c$uid, msg); }
event IPSEC::ike_data_attribute(c: connection, is_orig: bool, msg: IPSEC::IKE_SA_Transform_Attribute_Msg) { print cat("ike_data_attribute ", is_orig, c$uid, msg); }
event IPSEC::ikev2_ke_payload(c: connection, is_orig: bool, msg: IPSEC::IKE_KE_Msg) { print cat("ike_ke_payload ", is_orig, c$uid, msg); }
event IPSEC::ikev2_idi_payload(c: connection, is_orig: bool, msg: IPSEC::IKE_ID_Msg) { print cat("ike_idi_payload ", is_orig, c$uid, msg); }
event IPSEC::ikev2_idr_payload(c: connection, is_orig: bool, msg: IPSEC::IKE_ID_Msg) { print cat("ike_idr_payload ", is_orig, c$uid, msg); }
event IPSEC::ikev2_cert_payload(c: connection, is_orig: bool, msg: IPSEC::IKE_CERT_Msg) { print cat("ike_cert_payload ", is_orig, c$uid, msg); }
event IPSEC::ikev2_certreq_payload(c: connection, is_orig: bool, msg: IPSEC::IKE_CERTREQ_Msg) { print cat("ike_certreq_payload ", is_orig, c$uid, msg); }
event IPSEC::ikev2_auth_payload(c: connection, is_orig: bool, msg: IPSEC::IKE_AUTH_Msg) { print cat("ike_auth_payload ", is_orig, c$uid, msg); }
event IPSEC::ikev2_nonce_payload(c: connection, is_orig: bool, msg: IPSEC::IKE_NONCE_Msg) { print cat("ike_nonce_payload ", is_orig, c$uid, msg); }
event IPSEC::ikev2_notify_payload(c: connection, is_orig: bool, msg: IPSEC::IKE_NOTIFY_Msg) { print cat("ike_notify_payload ", is_orig, c$uid, msg); }
event IPSEC::ikev2_delete_payload(c: connection, is_orig: bool, msg: IPSEC::IKE_DELETE_Msg) { print cat("ike_delete_payload ", is_orig, c$uid, msg); }
event IPSEC::ikev2_vendorid_payload(c: connection, is_orig: bool, msg: IPSEC::IKE_VENDORID_Msg) { print cat("ike_vendorid_payload ", is_orig, c$uid, msg); }
event IPSEC::ikev2_ts_payload(c: connection, is_orig: bool, msg: IPSEC::IKE_TRAFFICSELECTOR_Msg) { print cat("ike_ts_payload ", is_orig, c$uid, msg); }
event IPSEC::ikev2_encrypted_payload(c: connection, is_orig: bool, msg: IPSEC::IKE_ENCRYPTED_Msg) { print cat("ike_encrypted_payload ", is_orig, c$uid, msg); }
event IPSEC::ikev2_configuration_attribute(c: connection, is_orig: bool, msg: IPSEC::IKE_CONFIG_ATTR_Msg) { print cat("ike_configuration_attribute ", is_orig, c$uid, msg); }
event IPSEC::ikev2_eap_payload(c: connection, is_orig: bool, msg: IPSEC::IKE_EAP_Msg) { print cat("ike_eap_payload ", is_orig, c$uid, msg); }
