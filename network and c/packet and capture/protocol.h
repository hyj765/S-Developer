
#define ETH_ALEN 6

struct ether_header
{
  u_int8_t  ether_dhost[ETH_ALEN];        /* destination eth addr        */
  u_int8_t  ether_shost[ETH_ALEN];        /* source ether addr        */
  u_int16_t ether_type;                        /* packet type ID field        */
} __attribute__ ((__packed__));

struct ip_header {
#if BYTE_ORDER == LITTLE_ENDIAN
	u_char	ip_hl:4,		/* header length */
		ip_v:4;			/* version */
#endif
#if BYTE_ORDER == BIG_ENDIAN
	u_char	ip_v:4,			/* version */
		ip_hl:4;		/* header length */
#endif
	u_char	ip_tos;			/* type of service */
	u_short	ip_len;			/* total length */
	u_short	ip_id;			/* identification */
	u_short	ip_off;			/* fragment offset field */
#define	IP_RF 0x8000			/* reserved fragment flag */
#define	IP_DF 0x4000			/* dont fragment flag */
#define	IP_MF 0x2000			/* more fragments flag */
#define	IP_OFFMASK 0x1fff		/* mask for fragmenting bits */
	u_char	ip_ttl;			/* time to live */
	u_char	ip_p;			/* protocol */
	u_short	ip_sum;			/* checksum */
	struct	in_addr ip_src,ip_dst;	/* source and dest address */
};
struct tcp_header
{
    unsigned short source_port;
    unsigned short dest_port;
    unsigned int sequence;
    unsigned int acknowledge;
    unsigned char ns : 1;
    unsigned char reserved_part1 : 3;
    unsigned char data_offset : 4;
    unsigned char fin : 1;
    unsigned char syn : 1;
    unsigned char rst : 1;
    unsigned char psh : 1;
    unsigned char ack : 1;
    unsigned char urg : 1;
    unsigned char ecn : 1;
    unsigned char cwr : 1;
    unsigned short window;
    unsigned short checksum;
    unsigned short urgent_pointer;
};