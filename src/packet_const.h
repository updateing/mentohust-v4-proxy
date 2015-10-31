/**
 * EAP Packet Constants and Structures
 *
 * Author: Hamster Tian <haotia@gmail.com>
 * Date: 2015/07
 */

enum {
	EAP_REQUEST = 1,
	EAP_RESPONSE,
	EAP_SUCCESS,
	EAP_FAILURE
} EAP_CODE; // Note: starts from 1

#define EAP_CODE_MIN EAP_REQUEST
#define EAP_CODE_MAX EAP_FAILURE

enum {
	EAP_PACKET = 0,
	EAPOL_START,
	EAPOL_LOGOFF,
	EAPOL_RJ_PROPRIETARY_KEEPALIVE = 0xbf
} EAPOL_PACKET_TYPE;

#define EAPOL_TYPE_MIN EAP_PACKET
#define EAPOL_TYPE_MAX EAPOL_RJ_PROPRIETARY_KEEPALIVE

enum {
	IDENTITY = 1,
	MD5_CHALLENGE = 4
} EAP_TYPE;

typedef struct {
	unsigned char dest_mac[6];
	unsigned char src_mac[6];
	unsigned char protocol[2];
} ETHERNET_HEADER;

typedef struct {
	unsigned char code;
	unsigned char id;
	unsigned char length[2];
	unsigned char type;
} EAP_HEADER;

typedef struct {
	unsigned char version;
	unsigned char type;
	unsigned char length[2]; // 802.1Q will be preserved
} EAPOL_HEADER;

typedef struct {
	ETHERNET_HEADER eth_hdr; // 14 bytes (0~13)
	EAPOL_HEADER eapol_hdr; // 4 bytes (14~17)
	EAP_HEADER eap_hdr; // 5 bytes, Absent in EAPOL-Start and Logoff
} PACKET_HEADER; // Skip the 8021x header manually!
