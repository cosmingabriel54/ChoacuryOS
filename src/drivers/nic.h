// nic.h
#ifndef NIC_H
#define NIC_H
#include <stdint.h>
#include "types.h"

#define ETHERNET_ADDR_LEN 6

typedef struct ethernet_header {
    uint8_t  dest_mac[ETHERNET_ADDR_LEN];   // Destination MAC address
    uint8_t  src_mac[ETHERNET_ADDR_LEN];    // Source MAC address
    uint16_t ethertype;                     // EtherType field
} __attribute__((packed)) ethernet_header_t;
typedef struct {
    uint8_t type;        // ICMP message type
    uint8_t code;        // ICMP message code
    uint16_t checksum;   // ICMP checksum
    uint16_t identifier; // Identifier (used for matching requests and replies)
    uint16_t sequence;   // Sequence number (used for matching requests and replies)
} __attribute__((packed)) icmp_header_t;
typedef struct {
    uint16_t htype;      // Hardware type
    uint16_t ptype;      // Protocol type
    uint8_t hlen;        // Hardware address length
    uint8_t plen;        // Protocol address length
    uint16_t opcode;     // ARP opcode (request/reply)
    uint8_t sender_mac[6]; // Sender hardware address
    uint8_t sender_ip[4];  // Sender IP address
    uint8_t target_mac[6]; // Target hardware address
    uint8_t target_ip[4];  // Target IP address
} arp_header_t;
typedef struct {
    uint64_t buffer_address; // Address of the packet buffer
    uint16_t length;         // Length of the received packet
    uint16_t checksum;     // Packet checksum (if enabled)
    uint8_t status;          // Descriptor status (e.g., if packet is received)
    uint8_t errors;          // Error information
    uint16_t special;        // Special information (e.g., VLAN, etc.)
} __attribute__((packed)) rx_descriptor_t;

typedef struct {
    uint8_t version_ihl;      // Version and IHL
    uint8_t tos;              // Type of Service
    uint16_t total_length;    // Total Length
    uint16_t identification;  // Identification
    uint16_t flags_offset;    // Flags and Fragment Offset
    uint8_t ttl;              // Time to Live
    uint8_t protocol;         // Protocol
    uint16_t checksum;        // Header checksum
    uint8_t source_ip[4];     // Source IP address
    uint8_t dest_ip[4];       // Destination IP address
} ip_header_t;
typedef struct {
    uint8_t op;      // Message opcode/type
    uint8_t htype;   // Hardware address type
    uint8_t hlen;    // Hardware address length
    uint8_t hops;    // Hops
    uint32_t xid;    // Transaction ID
    uint16_t secs;   // Seconds elapsed
    uint16_t flags;  // Flags
    uint8_t ciaddr[4]; // Client IP address
    uint8_t yiaddr[4]; // 'Your' IP address
    uint8_t siaddr[4]; // Server IP address
    uint8_t giaddr[4]; // Gateway IP address
    uint8_t chaddr[16]; // Client hardware address
    uint8_t sname[64];  // Server host name
    uint8_t file[128];  // Boot file name
    uint32_t magic_cookie; // Magic cookie
    uint8_t options[308];  // Optional parameters
} __attribute__((packed)) dhcp_packet_t;
typedef struct {
    uint16_t ethertype;
    void (*handler)(uint8_t* packet, uint16_t length);
} protocol_handler_entry_t;
uint32_t ntohl(uint32_t netlong);
uint16_t htons(uint16_t hostshort);
void nic_init(void);
void dhcp_client_start();
void nic_send_packet(uint8_t* packet, uint16_t length);
void nic_receive_packet(void);
void process_packet(uint8_t* packet, uint16_t length);
void process_arp_packet(uint8_t* packet, uint16_t length);
void process_ip_packet(uint8_t* packet, uint16_t length);
#endif
