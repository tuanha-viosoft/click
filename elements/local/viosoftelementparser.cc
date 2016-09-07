#include <click/config.h>
#include <clicknet/ip.h>
#include <click/glue.hh>
#include <click/args.hh>
#include <click/straccum.hh>
#include <click/error.hh>
#include <click/ipaddress.hh>
#include <click/standard/alignmentinfo.hh>

#include <click/packet_anno.hh>
#include <click/router.hh>
#include <click/nameinfo.hh>
#include <click/etheraddress.hh>
#include <clicknet/icmp.h>
#include <clicknet/tcp.h>
#include <clicknet/udp.h>
#include "viosoftelementparser.hh"

CLICK_DECLS

const char * const Viosoftelementparser::reason_texts[NREASONS] = {
		"tiny packet", "bad IP version", "bad IP header length",
		"bad IP length", "bad IP checksum", "bad source address" };

#define IPADDR_LIST_INTERFACES		((void *)0)
#define IPADDR_LIST_BADSRC		((void *)1)
#define IPADDR_LIST_BADSRC_OLD		((void *)2)
#define NETWORK_ID_SIZE			(26)

CLICK_DECLS

Viosoftelementparser::Viosoftelementparser() :
	_checksum(true), _reason_drops(0) {
	_drops = 0;
}

Viosoftelementparser::~Viosoftelementparser()
{
	delete[] _reason_drops;
}

bool Viosoftelementparser::OldBadSrcArg::parse(const String &str,
		Vector<IPAddress> &result, Args &args) {
	if (IPAddressArg().parse(str, result, args)) {
		result.push_back(IPAddress(0));
		result.push_back(IPAddress(0xFFFFFFFFU));
		return true;
	} else
		return false;
}

bool Viosoftelementparser::InterfacesArg::parse(const String &str,
		Vector<IPAddress> &result_bad_src, Vector<IPAddress> &result_good_dst,
		Args &args) {
	String arg(str);
	IPAddress ip, mask;
	int nwords = 0;
	while (String word = cp_shift_spacevec(arg)) {
		++nwords;
		if (IPPrefixArg(true).parse(word, ip, mask, args)) {
			result_bad_src.push_back((ip & mask) | ~mask);
			result_good_dst.push_back(ip);
		} else
			return false;
	}
	if (nwords == result_bad_src.size()) {
		result_bad_src.push_back(IPAddress(0));
		result_bad_src.push_back(IPAddress(0xFFFFFFFFU));
		return true;
	}
	args.error("out of memory");
	return false;
}

int Viosoftelementparser::configure(Vector<String> &conf, ErrorHandler *errh) {
	_offset = 0;
	bool verbose = false;
	bool details = false;

	if (Args(this, errh).bind(conf).read("INTERFACES", InterfacesArg(),
			_bad_src, _good_dst).read("BADSRC", _bad_src).read("GOODDST",
			_good_dst)
//      .read("OFFSET", _offset)
	.read("VERBOSE", verbose).read("DETAILS", details).read("CHECKSUM",
			_checksum).consume() < 0)
		return -1;
//
//  if (conf.size() == 0
//      || (conf.size() == 1 && IntArg().parse(conf[0], _offset)))
//    /* nada */;
//  else if (Args(conf, this, errh)
//	   .read("BADSRC", OldBadSrcArg(), _bad_src)
//	   .read("OFFSET", _offset)
//	   .complete() < 0)
//    return -1;

	_verbose = verbose;
	if (details) {
		_reason_drops = new atomic_uint32_t[NREASONS];
		for (int i = 0; i < NREASONS; ++i)
			_reason_drops[i] = 0;
	}

#if HAVE_FAST_CHECKSUM && FAST_CHECKSUM_ALIGNED
	// check alignment
	if (_checksum) {
		int ans, c, o;
		ans = AlignmentInfo::query(this, 0, c, o);
		o = (o + 4 - (_offset % 4)) % 4;
		_aligned = (ans && c == 4 && o == 0);
		if (!_aligned)
		errh->warning("IP header unaligned, cannot use fast IP checksum");
		if (!ans)
		errh->message("(Try passing the configuration through `click-align'.)");
	}
#endif

	//for (int i = 0; i < _bad_src.n; i++)
	//  click_chatter("bad: %s", IPAddress(_bad_src.vec[i]).s().c_str());
	//for (int i = 0; i < _good_dst.n; i++)
	//  click_chatter("good: %s", IPAddress(_good_dst.vec[i]).s().c_str());

	_bytes = 1500;
	String contents = "no";
	String payload = "no";
	_label = "";
	_swap = false;
	_payload = false;
	_active = true;
	bool print_id = false;
	bool print_time = true;
	bool print_paint = false;
	bool print_tos = false;
	bool print_ttl = false;
	bool print_len = false;
	bool print_aggregate = false;
	bool bcontents;
	String channel;

	if (Args(conf, this, errh).read_p("LABEL", _label).read("CONTENTS",
			WordArg(), contents).read("PAYLOAD", WordArg(), payload).read(
			"MAXLENGTH", _bytes).read("NBYTES", _bytes) // deprecated
	.read("ID", print_id).read("TIMESTAMP", print_time).read("PAINT",
			print_paint).read("TOS", print_tos).read("TTL", print_ttl).read(
			"SWAP", _swap).read("LENGTH", print_len).read("AGGREGATE",
			print_aggregate).read("ACTIVE", _active)
#if CLICK_USERLEVEL
			.read("OUTFILE", FilenameArg(), _outfilename)
#endif
			.read("CHANNEL", WordArg(), channel).complete() < 0)
		return -1;

	if (BoolArg().parse(contents, bcontents))
		_contents = bcontents;
	else if ((contents = contents.upper()), contents == "NONE")
		_contents = 0;
	else if (contents == "HEX")
		_contents = 1;
	else if (contents == "ASCII")
		_contents = 2;
	else
		return errh->error(
				"bad contents value '%s'; should be 'NONE', 'HEX', or 'ASCII'",
				contents.c_str());

	int payloadv;
	payload = payload.upper();
	if (payload == "NO" || payload == "FALSE")
		payloadv = 0;
	else if (payload == "YES" || payload == "TRUE" || payload == "HEX")
		payloadv = 1;
	else if (payload == "ASCII")
		payloadv = 2;
	else
		return errh->error(
				"bad payload value '%s'; should be 'false', 'hex', or 'ascii'",
				contents.c_str());

	if (payloadv > 0 && _contents > 0)
		return errh->error("specify at most one of PAYLOAD and CONTENTS");
	else if (payloadv > 0)
		_contents = payloadv, _payload = true;

	_print_id = print_id;
	_print_timestamp = print_time;
	_print_paint = print_paint;
	_print_tos = print_tos;
	_print_ttl = print_ttl;
	_print_len = print_len;
	_print_aggregate = print_aggregate;
	_errh = router()->chatter_channel(channel);
	// Configure offset of header in IP packet
	_offset = 14;

	return 0;
}

Packet *
Viosoftelementparser::drop(Reason reason, Packet *p) {
	if (_drops == 0 || _verbose)
		click_chatter("%s: IP header check failed: %s", name().c_str(),
				reason_texts[reason]);
	_drops++;

	if (_reason_drops)
		_reason_drops[reason]++;

	if (noutputs() == 2) {
//	output(1).push(p);
	} else
		p->kill();

	return 0;
}

/**
 * Create new packet with a new field as VIOSOFT TAG
 */
//Packet*
//Viosoftelementparser::make_packet_has_VDET(Packet *p, String vdet) {
//	WritablePacket *q = Packet::make(
//			p->length() + sizeof(struct viosoft_debug_element_tag));
//	if (!q)
//		return 0;
//
//	// Copy source data to destination data
//	memset(q->data(), '\0', p->length());
//	memcpy(q->data(), p->data(), p->length());
//
//	// Set VIOSOFT DEBUG ELEMENT TAG
//	memset(q->data() + p->length(), '\0',
//			sizeof(struct viosoft_debug_element_tag));
//	viosoft_debug_element_tag *tag =
//			reinterpret_cast<viosoft_debug_element_tag *>(q->data()
//					+ p->length());
//	tag->first_char = 'V';
//	tag->second_char = 'D';
//	tag->third_char = 'E';
//	tag->forth_char = 'T';
//
//	memcpy(q->data() + p->length(), tag,
//			sizeof(struct viosoft_debug_element_tag));
//
//	printf("add VDET\n");
//
//	return q;
//
//}

String Viosoftelementparser::parse_network_id_from_tag(const viosoft_debug_element_tag *tag) {
	String network_id;

	for(int i=0; i<NETWORK_ID_SIZE; i++) {
		network_id += tag->id[i];
	}
//	network_id = String(tag->id);
//	printf("Network ID: %s", network_id.c_str());

	return network_id;
}



bool Viosoftelementparser::has_viosoft_debug_element_tag(Packet *p) {
	bool result = false;

	int plen = p->length();

	if (plen > sizeof(struct viosoft_debug_element_tag)) {
		int offset = p->length() - sizeof(struct viosoft_debug_element_tag);
		const viosoft_debug_element_tag *tag =
				reinterpret_cast<const viosoft_debug_element_tag *>(p->data()
						+ offset);
		if (tag->first_char == 'V' && tag->second_char == 'D'
				&& tag->third_char == 'E' && tag->forth_char == 'T') {
			// Parse network id
			network_id = parse_network_id_from_tag(tag);
			result = true;
		}
	}

	return result;
}

Packet *
Viosoftelementparser::simple_action(Packet *q) {
	// Copy packet content
	Packet *p = q->clone();

	// Check if packet has viosoft debug element tag
	bool hasVDET = has_viosoft_debug_element_tag(p);
	if (!hasVDET) {
		// Packet has no viosoft tag then pass it
//		printf("Packet has no Viosoft TAG =======>\n");
		return q;
	}
//	printf("Packet has Viosoft TAG\n");
	const click_ip *ip = reinterpret_cast<const click_ip *>(p->data() + _offset);
	unsigned plen = p->length() - _offset;
	unsigned hlen, len;

	// cast to int so very large plen is interpreted as negative
	if ((int) plen < (int) sizeof(click_ip)) {
		_offset = 0;
		return drop(MINISCULE_PACKET, p);
	} else {
		_offset = 14;
	}

//  if (ip->ip_v != 4) {
//    return drop(BAD_VERSION, p);

	hlen = ip->ip_hl << 2;
//  if (hlen < sizeof(click_ip))
//    return drop(BAD_HLEN, p);

	len = ntohs(ip->ip_len);
//  if (len > plen || len < hlen)
//    return drop(BAD_IP_LEN, p);

	if (_checksum) {
		int val;
#if HAVE_FAST_CHECKSUM && FAST_CHECKSUM_ALIGNED
		if (_aligned)
		val = ip_fast_csum((unsigned char *)ip, ip->ip_hl);
		else
		val = click_in_cksum((const unsigned char *)ip, hlen);
#elif HAVE_FAST_CHECKSUM
		val = ip_fast_csum((unsigned char *)ip, ip->ip_hl);
#else
		val = click_in_cksum((const unsigned char *) ip, hlen);
#endif
//    if (val != 0)
//      return drop(BAD_CHECKSUM, p);
	}

	/*
	 * RFC1812 5.3.7 and 4.2.2.11: discard illegal source addresses.
	 * Configuration string should have listed all subnet
	 * broadcast addresses known to this router.
	 */
	if (find(_bad_src.begin(), _bad_src.end(), IPAddress(ip->ip_src))
			< _bad_src.end()
			&& find(_good_dst.begin(), _good_dst.end(), IPAddress(ip->ip_dst))
					== _good_dst.end())
//    return drop(BAD_SADDR, p);
		;

	/*
	 * RFC1812 4.2.3.1: discard illegal destinations.
	 * We now do this in the IP routing table.
	 */

	p->set_ip_header(ip, hlen);

	// shorten packet according to IP length field -- 7/28/2000
	if (plen > len)
		p->take(plen - len);

	// set destination IP address annotation if it doesn't exist already --
	// 9/26/2001
	// always set destination IP address annotation; linuxmodule problem
	// reported by Parveen Kumar Patel at Utah -- 4/3/2002
	p->set_dst_ip_anno(ip->ip_dst);
//  printf("%d\n", p->ip_header_offset());

	// Parse data
	if (!_active || !p->has_network_header()) {
//		printf("Has network header\n");
//		return q;
		return p;
	}

	StringAccum sa;
	sa << "viosoft_debug_element ";

	// Get configuration string
//	if (_label) {
//		printf("Has label\n");
		sa << "wrapper_id" << network_id << "end_wrapper_id";
//	}

	// Get source and destination MAC Address
	if (p->has_mac_header()) {
//		printf("Has mac header\n");
		const unsigned char *mac_header = p->mac_header();
		sa << "src_mac_add" << EtherAddress(&mac_header[6])
				<< "end_src_mac_add";
		sa << "dst_mac_add" << EtherAddress(mac_header) << "end_dst_mac_add";
	}

	if (!(p->network_length() < (int) sizeof(click_ip))) {
//		printf("Has network length\n");
		const click_ip *iph = p->ip_header();
		int ip_len = ntohs(iph->ip_len);
		int payload_len = ip_len - (iph->ip_hl << 2);
		int transport_length = p->transport_length();
		if (transport_length > payload_len) {
			transport_length = payload_len;
		}

		if (iph->ip_p == IP_PROTO_TCP) {
//			printf("TCP line\n");
			tcp_line(sa, p, transport_length);
		} else if (iph->ip_p == IP_PROTO_UDP) {
//			printf("UDP line\n");
			udp_line(sa, p, transport_length);
		} else if (iph->ip_p == IP_PROTO_ICMP) {
//			printf("ICMP line\n");
			icmp_line(sa, p, transport_length);
		} else {
//			printf("Has ip address\n");
			sa << "src_ip_add" << IPAddress(iph->ip_src) << "end_src_ip_add";
			sa << "dst_ip_add" << IPAddress(iph->ip_dst) << "end_dst_ip_add";
		}

		// print payload
		if (_contents > 0) {
//			printf("Print payload\n");
			const uint8_t *data;
			if (_payload) {
				if (IP_FIRSTFRAG(iph) && iph->ip_p == IP_PROTO_TCP)
					data = p->transport_header()
							+ (p->tcp_header()->th_off << 2);
				else if (IP_FIRSTFRAG(iph) && iph->ip_p == IP_PROTO_UDP)
					data = p->transport_header() + sizeof(click_udp);
				else
					data = p->transport_header();
			} else
				data = p->data();

			int bytes = _bytes;
			if (data >= p->end_data())
				bytes = 0;
			else if (bytes < 0 || (int) (p->end_data() - data) < bytes)
				bytes = p->end_data() - data;
			int amt = 3 * bytes + (bytes / 4 + 1) + 3 * (bytes / 24 + 1) + 1;

			char *buf = sa.reserve(amt);
			char *orig_buf = buf;

			if (buf && _contents == 1) {
				for (int i = 0; i < bytes; i++, data++) {
					if ((i % 24) == 0) {
						*buf++ = '\n';
						*buf++ = ' ';
						*buf++ = ' ';
					} else if ((i % 4) == 0)
						*buf++ = ' ';
					buf += 2;
				}
			} else if (buf && _contents == 2) {
				for (int i = 0; i < bytes; i++, data++) {
					if ((i % 48) == 0) {
						*buf++ = '\n';
						*buf++ = ' ';
						*buf++ = ' ';
					} else if ((i % 8) == 0)
						*buf++ = ' ';
					if (*data < 32 || *data > 126)
						*buf++ = '.';
					else
						*buf++ = *data;
				}
			}

			if (orig_buf) {
				assert(buf <= orig_buf + amt);
				sa.adjust_length(buf - orig_buf);
			}
		}
	}
//	printf("End of simple action\n");
#if CLICK_USERLEVEL
	sa << '\n';
#endif
	_errh->message("%s", sa.c_str());

//	if (!hasVDET) {
//		p = make_packet_has_VDET(q, "abcdefghik12345678");
//		printf("Q size: %d   P size: %d", q->length(), p->length());
//	} else {
//		printf("Packet has VDET ===========================================================>");
//	}

//	return (q);
	return p;
}

String Viosoftelementparser::read_handler(Element *e, void *) {
	Viosoftelementparser *c = reinterpret_cast<Viosoftelementparser *>(e);
	StringAccum sa;
	for (int i = 0; i < NREASONS; i++)
		sa << c->_reason_drops[i] << '\t' << reason_texts[i] << '\n';
	return sa.take_string();
}

void Viosoftelementparser::add_handlers() {
	add_data_handlers("drops", Handler::OP_READ, &_drops);
	if (_reason_drops)
		add_read_handler("drop_details", read_handler, 1);
}

StringAccum &
Viosoftelementparser::address_pair(StringAccum &sa, const click_ip *iph) {
	sa << "src_ip_add" << IPAddress(iph->ip_src) << "end_src_ip_add";
	sa << "dst_ip_add" << IPAddress(iph->ip_dst) << "end_dst_ip_add";
	return sa;
}

void Viosoftelementparser::tcp_line(StringAccum &sa, const Packet *p,
		int transport_length) const {
	const click_ip *iph = p->ip_header();
	const click_tcp *tcph = p->tcp_header();
	int ip_len, seqlen;
	uint32_t seq;

	if (transport_length < 4 || !IP_FIRSTFRAG(iph)) {
		address_pair(sa, iph)
				<< (IP_FIRSTFRAG(iph) ? ": truncated-tcp" : ": tcp");
		return;
	}

	sa << "src_ip_add" << IPAddress(iph->ip_src) << "end_src_ip_add";
	sa << "dst_ip_add" << IPAddress(iph->ip_dst) << "end_dst_ip_add";

	if (transport_length < 14)
		goto truncated_tcp;

	ip_len = ntohs(iph->ip_len);
	seqlen = ip_len - (iph->ip_hl << 2) - (tcph->th_off << 2);

	seq = ntohl(tcph->th_seq);

	if (transport_length < 16)
		goto truncated_tcp;

	return;

	truncated_tcp: ;
}

void Viosoftelementparser::udp_line(StringAccum &sa, const Packet *p,
		int transport_length) const {
	const click_ip *iph = p->ip_header();
	const click_udp *udph = p->udp_header();

	if (transport_length < 4 || !IP_FIRSTFRAG(iph)) {
		address_pair(sa, iph)
				<< (IP_FIRSTFRAG(iph) ? ": truncated-udp" : ": udp");
		return;
	}

	sa << "src_ip_add" << IPAddress(iph->ip_src) << "end_src_ip_add";
	sa << "dst_ip_add" << IPAddress(iph->ip_dst) << "end_dst_ip_add";

	if (transport_length < 8)
		goto truncated_udp;

	return;

	truncated_udp: ;
}

static String unparse_proto(int ip_p, bool prepend) {
	if (String s = NameInfo::revquery_int(NameInfo::T_IP_PROTO, 0, ip_p))
		return s;
	else if (prepend)
		return String::make_stable("protocol ", 9) + String(ip_p);
	else
		return String(ip_p);
}

void Viosoftelementparser::icmp_line(StringAccum &sa, const Packet *p,
		int transport_length) const {
	const click_ip *iph = p->ip_header();
	const click_icmp *icmph = p->icmp_header();
	address_pair(sa, iph);

	if (!IP_FIRSTFRAG(iph)) {
		return;
	} else if (transport_length < 2)
		goto truncated_icmp;

	switch (icmph->icmp_type) {

	case ICMP_ECHOREPLY:
		goto icmp_echo;
	case ICMP_ECHO:
		/* fallthru */
		icmp_echo: {
			if (transport_length < 8)
				goto truncated_icmp;
			const click_icmp_sequenced *seqh =
					reinterpret_cast<const click_icmp_sequenced *>(icmph);
#define swapit(x) (_swap ? ((((x) & 0xff) << 8) | ((x) >> 8)) : (x))
			break;
		}

	case ICMP_UNREACH: {
		String code = NameInfo::revquery_int(
				NameInfo::T_ICMP_CODE + icmph->icmp_type, this,
				icmph->icmp_code);
		if (!code)
			code = "code " + String((int) icmph->icmp_code);

		const click_ip *eiph = reinterpret_cast<const click_ip *>(icmph + 1);
		int eiph_len = transport_length - sizeof(click_icmp);
		if (eiph_len < (int) sizeof(click_ip)) {
			goto truncated_icmp;
		}

		const click_udp *eudph =
				reinterpret_cast<const click_udp *>(reinterpret_cast<const uint8_t *>(eiph)
						+ (eiph->ip_hl << 2));
		int eudph_len = eiph_len - (eiph->ip_hl << 2);

		switch (icmph->icmp_code) {
		case ICMP_UNREACH_PROTOCOL:
			break;
		case ICMP_UNREACH_PORT:
			if (eudph_len < 4)
				goto truncated_icmp;
			break;
		case ICMP_UNREACH_NEEDFRAG: {
			const click_icmp_needfrag *nfh =
					reinterpret_cast<const click_icmp_needfrag *>(icmph);
			break;
		}
		}
		break;
	}

	default:
		break;
	}
	return;

	truncated_icmp: ;
}

CLICK_ENDDECLS
EXPORT_ELEMENT(Viosoftelementparser)
