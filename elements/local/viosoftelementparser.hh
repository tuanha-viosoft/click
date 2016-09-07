#ifndef CLICK_VIOSOFTELEMENTPARSER_HH
#define CLICK_VIOSOFTELEMENTPARSER_HH

#include <click/element.hh>
#include <click/atomic.hh>
CLICK_DECLS
class Args;

class Viosoftelementparser : public Element { public:

	Viosoftelementparser();
  ~Viosoftelementparser();

	const char *class_name() const	{return "Viosoftelementparser"; }
	const char *port_count() const	{return "1/1"; }
	const char *processing() const	{return AGNOSTIC; }
  const char *flags() const			{ return "A"; }

  int configure(Vector<String> &, ErrorHandler *);
  void add_handlers();

  Packet *simple_action(Packet *);

  struct OldBadSrcArg {
      static bool parse(const String &str, Vector<IPAddress> &result,
			Args &args);
  };

  struct InterfacesArg {
      static bool parse(const String &str, Vector<IPAddress> &result_bad_src,
			Vector<IPAddress> &result_good_dst, Args &args);
  };

 private:

  unsigned _offset;

  Vector<IPAddress> _bad_src;	// array of illegal IP src addresses

  bool _checksum;
#if HAVE_FAST_CHECKSUM && FAST_CHECKSUM_ALIGNED
  bool _aligned;
#endif
  bool _verbose;

  Vector<IPAddress> _good_dst;	// array of IP dst addrs for which _bad_src
				// does not apply

  atomic_uint32_t _drops;
  atomic_uint32_t *_reason_drops;

  enum Reason {
    MINISCULE_PACKET,
    BAD_VERSION,
    BAD_HLEN,
    BAD_IP_LEN,
    BAD_CHECKSUM,
    BAD_SADDR,
    NREASONS
  };
  static const char * const reason_texts[NREASONS];

  Packet *drop(Reason, Packet *);
  static String read_handler(Element *, void *);

  friend class CheckIPHeader2;


	bool _swap;
	bool _active;
	String _label;
	int _bytes;			// Number of bytes to dump
	bool _print_id :1;		// Print IP ID?
	bool _print_timestamp :1;
	bool _print_paint :1;
	bool _print_tos :1;
	bool _print_ttl :1;
	bool _print_len :1;
	bool _print_aggregate :1;
	bool _payload :1;		// '_contents' refers to payload
	unsigned _contents :2;	// Whether to dump packet contents

#if CLICK_USERLEVEL
	String _outfilename;
	FILE *_outfile;
#endif
	ErrorHandler *_errh;
	/* VIOSOFT DEBUG ELEMENT TAG */
	struct viosoft_debug_element_tag {
	    uint8_t		first_char;
	    uint8_t		second_char;
	    uint8_t		third_char;
	    uint8_t		forth_char;
	    uint8_t		id[26];
	};
	String network_id;

	static StringAccum &address_pair(StringAccum &sa, const click_ip *iph);
	void tcp_line(StringAccum &, const Packet *, int transport_len) const;
	void udp_line(StringAccum &, const Packet *, int transport_len) const;
	void icmp_line(StringAccum &, const Packet *, int transport_len) const;
//	Packet* make_packet_has_VDET(Packet *, String);
	bool has_viosoft_debug_element_tag(Packet *);
	String parse_network_id_from_tag(const viosoft_debug_element_tag *);

};

CLICK_ENDDECLS
#endif /* CLICK_VIOSOFTELEMENTPARSER_HH */
