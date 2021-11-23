# IPSec

This is a Zeek protocol analyzer that detects IPSec VPN based on Spicy.
You must install [Spicy](https://docs.zeek.org/projects/spicy/en/latest/)
to use this package.

A blog detailing the development of this analyzer:

- <https://zeek.org/2021/04/20/zeeks-ipsec-protocol-analyzer/>

RFCs:
- <https://tools.ietf.org/html/rfc2406> (ESP)
- <https://tools.ietf.org/html/rfc4302> (AH)
- <https://tools.ietf.org/html/rfc2408> (IKE v1)
- <https://tools.ietf.org/html/rfc2409> (IKE v1)
- <https://tools.ietf.org/html/rfc3948> (ESP packets encapsulated in UDP)
- <https://tools.ietf.org/html/rfc4306> (IKE v2)
- <https://tools.ietf.org/html/rfc7296> (IKE v2)
- <https://tools.ietf.org/html/rfc8229> (ESP packets encapsulated in TCP)

## Example Logs

```
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	conn
#open	2021-11-23-13-52-52
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	service	duration	orig_bytes	resp_bytes	conn_state	local_orig	local_resp	missed_bytes	history	orig_pkts	orig_ip_bytes	resp_pkts	resp_ip_bytes	tunnel_parents
#types	time	string	addr	port	addr	port	enum	string	interval	count	count	string	bool	bool	count	string	count	count	count	count	set[string]
1421270042.835161	CHhAvVGS1DHFjwGM9	192.168.0.10	500	144.76.154.114	500	udp	spicy_ipsec_ike_udp	0.032969	880	308	SF	-	-	0	Dd	1	908	1	336	-
1421270042.910124	ClEkJM2Vm5giqnMf4h	192.168.0.10	4500	144.76.154.114	4500	udp	spicy_ipsec_udp	2.000258	10416	0	S0	-	-	0	D	3	10500	0	0	-
#close	2021-11-23-13-52-52
```

```
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	ipsec
#open	2021-11-23-13-52-52
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	is_orig	initiator_spi	responder_spi	maj_ver	min_ver	exchange_type	flag_e	flag_c	flag_a	flag_i	flag_v	flag_r	message_id	vendor_ids	notify_messages	transforms	ke_dh_groups	proposals	certificates	transform_attributes	length	hash
#types	time	string	addr	port	addr	port	bool	string	string	count	count	count	bool	bool	bool	bool	bool	bool	count	vector[string]	vector[string]	vector[string]	vector[count]	vector[count]	vector[string]	vector[string]	count	string
1421270042.835161	CHhAvVGS1DHFjwGM9	192.168.0.10	500	144.76.154.114	500	T	238671c80375a0fb	0000000000000000	2	0	34	F	F	F	T	F	F	0	MS NT5 ISAKMPOAKLEY,MS-Negotiation Discovery Capable,Microsoft Initial-Contact,UNKNOWN:01528bbbc00696121849ab9a1c5b2a5100000002	NAT_DETECTION_SOURCE_IP,NAT_DETECTION_DESTINATION_IP	(empty)	2	1,2,3,4,5,6,7,8,9,10,11,12	(empty)	(empty)	880	d1cd39840e0aaa5420b8f65984bb4f5f
1421270042.868130	CHhAvVGS1DHFjwGM9	192.168.0.10	500	144.76.154.114	500	F	238671c80375a0fb	73d16a42f60ef7f0	2	0	34	F	F	F	F	F	T	0	(empty)	NAT_DETECTION_SOURCE_IP,NAT_DETECTION_DESTINATION_IP,MULTIPLE_AUTH_SUPPORTED	(empty)	2	1	(empty)	(empty)	308	f1885551a5b169444dd961e94d683d61
1421270042.910124	ClEkJM2Vm5giqnMf4h	192.168.0.10	4500	144.76.154.114	4500	T	238671c80375a0fb	73d16a42f60ef7f0	2	0	35	F	F	F	T	F	F	1	(empty)	(empty)	(empty)	(empty)	(empty)	(empty)	(empty)	3468	-
1421270043.910245	ClEkJM2Vm5giqnMf4h	192.168.0.10	4500	144.76.154.114	4500	T	238671c80375a0fb	73d16a42f60ef7f0	2	0	35	F	F	F	T	F	F	1	(empty)	(empty)	(empty)	(empty)	(empty)	(empty)	(empty)	3468	-
1421270044.910382	ClEkJM2Vm5giqnMf4h	192.168.0.10	4500	144.76.154.114	4500	T	238671c80375a0fb	73d16a42f60ef7f0	2	0	35	F	F	F	T	F	F	1	(empty)	(empty)	(empty)	(empty)	(empty)	(empty)	(empty)	3468	-
#close	2021-11-23-13-52-52
```

# Testing PCAPs:

The test suite comes with a set of traces collected from a variety of
places that we document below. While these traces are all coming from
public sources, please note that they may carry their own licenses.
We collect them here for convenience only.

- [ipsec_client.pcap](https://www.cloudshark.org/captures/9e63e31f9f56)
- [ikev1-certs.pcap](https://github.com/wireshark/wireshark/blob/master/test/captures/ikev1-certs.pcap)
- [ipsec-ikev1-isakmp-main-mode.pcap](https://www.cloudshark.org/captures/ff740838f1c2)
- [ipsec-ikev1-isakmp-aggressive-mode.pcap](https://www.cloudshark.org/captures/e51f5c8a6b24)
- ipsec-ikev1-payload-bad-length.pcap (self-made)
- ipsec-ikev1-zero-length.pcap (self-made)
- [IPsec_ESP-AH_tunnel_mode.cap](https://www.cloudshark.org/captures/dcbaa6ab009b)
- [ipsec.cap](https://www.cloudshark.org/captures/6ad6e687ed9d)
