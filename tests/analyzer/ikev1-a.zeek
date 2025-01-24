# @TEST-EXEC: zeek -C -r ${TRACES}/ikev1-certs.pcap %INPUT
# @TEST-EXEC: zeek-cut -m -n local_orig local_resp ip_proto < conn.log > conn.log.filtered
# @TEST-EXEC: btest-diff conn.log.filtered
#     Zeek 3.0 sorts dictionaries differently, leading to a change in vendor ID; not worth worrying about, so we just skip the diff for 3.0.
# @TEST-EXEC: if zeek-version 40000; then btest-diff ipsec.log; fi
# @TEST-EXEC: btest-diff .stdout

@load analyzer

event IPSEC::ike_message(c: connection, is_orig: bool, msg: IPSEC::IKEMsg) { print cat("ike_message ", is_orig, c$uid, msg); }
event IPSEC::esp_message(c: connection, is_orig: bool, msg: IPSEC::ESPMsg) { print cat("esp_message ", is_orig, c$uid, msg); }
event IPSEC::ikev1_sa_payload(c: connection, is_orig: bool, msg: IPSEC::IKEv1_SA_Msg) { print cat("ikev1_sa_payload ", is_orig, c$uid, msg); }
event IPSEC::ikev1_vid_payload(c: connection, is_orig: bool, msg: IPSEC::IKE_VENDORID_Msg) { print cat("ikev1_vid_payload ", is_orig, c$uid, msg); }
event IPSEC::ikev1_ke_payload(c: connection, is_orig: bool, msg: IPSEC::IKEv1_KE_Msg) { print cat("ikev1_ke_payload ", is_orig, c$uid, msg); }
event IPSEC::ikev1_nonce_payload(c: connection, is_orig: bool, msg: IPSEC::IKE_NONCE_Msg) { print cat("ikev1_n_payload ", is_orig, c$uid, msg); }
event IPSEC::ikev1_cert_payload(c: connection, is_orig: bool, msg: IPSEC::IKE_CERT_Msg) { print cat("ikev1_cert_payload ", is_orig, c$uid, msg); }
event IPSEC::ikev1_certreq_payload(c: connection, is_orig: bool, msg: IPSEC::IKE_CERTREQ_Msg) { print cat("ikev1_certreq_payload ", is_orig, c$uid, msg); }
event IPSEC::ikev1_id_payload(c: connection, is_orig: bool, msg: IPSEC::IKEv1_ID_Msg) { print cat("ikev1_id_payload ", is_orig, c$uid, msg); }
event IPSEC::ikev1_hash_payload(c: connection, is_orig: bool, msg: IPSEC::IKEv1_HASH_Msg) { print cat("ikev1_hash_payload ", is_orig, c$uid, msg); }
event IPSEC::ikev1_sig_payload(c: connection, is_orig: bool, msg: IPSEC::IKEv1_SIG_Msg) { print cat("ikev1_sig_payload ", is_orig, c$uid, msg); }
event IPSEC::ikev1_p_payload(c: connection, is_orig: bool, msg: IPSEC::IKEv1_P_Msg) { print cat("ikev1_p_payload ", is_orig, c$uid, msg); }
event IPSEC::ikev1_t_payload(c: connection, is_orig: bool, msg: IPSEC::IKEv1_T_Msg) { print cat("ikev1_t_payload ", is_orig, c$uid, msg); }
event IPSEC::ikev1_notify_payload(c: connection, is_orig: bool, msg: IPSEC::IKE_NOTIFY_Msg) { print cat("ikev1_notify_payload ", is_orig, c$uid, msg); }
event IPSEC::ikev1_delete_payload(c: connection, is_orig: bool, msg: IPSEC::IKE_DELETE_Msg) { print cat("ikev1_delete_payload ", is_orig, c$uid, msg); }
event IPSEC::ike_data_attribute(c: connection, is_orig: bool, msg: IPSEC::IKE_SA_Transform_Attribute_Msg) { print cat("ike_data_attribute ", is_orig, c$uid, msg); }
