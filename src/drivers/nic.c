#include "nic.h"
#include "pci.h"
#include "idt.h"
#include "ports.h"
#include "debug.h"
#include "../memory/kmalloc.h"
#include "../shell/terminal.h"
#include "utils.h"
#define NIC_RESET_REGISTER 0x34
#define NIC_INTERRUPT_ENABLE_REGISTER 0xD0
#define NIC_INTERRUPT_RX 0x01
#define NIC_INTERRUPT_TX 0x02
#define NIC_CONTROL_REGISTER 0x0000
#define NIC_CONTROL_START 0x0400
#define NIC_TX_BUFFER_OFFSET 0x0380
#define NIC_TX_LENGTH_REGISTER 0x0388
#define NIC_TX_CONTROL_REGISTER 0x0400
#define NIC_TX_START 0x0800
#define NIC_RX_PACKET_RECEIVED 0x01
#define NIC_RX_STATUS_REGISTER 0xC0
#define NIC_RX_BUFFER_OFFSET 0x2800
#define NIC_RX_CONTROL_REGISTER 0x0100
#define NIC_INTERRUPT_STATUS_REGISTER 0xC0
#define ETHERTYPE_ARP 0x0806
#define ETHERTYPE_IP 0x0800
#define ARP_HTYPE_ETHERNET 0x0001
#define ARP_PTYPE_IPV4 0x0800
#define ARP_OPCODE_REQUEST 0x0001
#define ARP_OPCODE_REPLY 0x0002
#define NIC_RDBAL 0x2800
#define NIC_RDBAH 0x2804
#define NIC_TDBAL 0x3800
#define NIC_TDBAH 0x3804
#define NIC_RDT   0x2818
#define NIC_TDT   0x3818
#define NIC_ICR 0xC0
#define ARP_PLEN_IPV4 4
#define ARP_HLEN_ETHERNET 6
#define RX_BUFFER_COUNT 128
#define NIC_RDH 0x2810
#define DESCRIPTOR_STATUS_DD 0x01
#define TX_BUFFER_COUNT 128
#define MAX_PACKET_QUEUE_SIZE 64
#define NIC_TDH 0x3810
#define NIC_TX_CMD_EOP 0x01   // End of Packet
#define NIC_TX_CMD_IFCS 0x02  // Insert FCS (Frame Check Sequence)
#define NIC_TX_CMD_RS 0x08    // Report Status
#define DHCP_MAGIC_COOKIE 0x63825363
#define DHCP_OPTION_END 255

// DHCP message types
#define DHCP_DISCOVER 1
#define DHCP_OFFER 2
#define DHCP_REQUEST 3
#define DHCP_DECLINE 4
#define DHCP_ACK 5
#define DHCP_NAK 6
#define DHCP_RELEASE 7
#define DHCP_INFORM 8

// DHCP ports
#define DHCP_SERVER_PORT 67
#define DHCP_CLIENT_PORT 68
#define MAX_PROTOCOL_HANDLERS 16
typedef struct {
    uint8_t *packet;
    uint16_t length;
} packet_queue_entry_t;
protocol_handler_entry_t protocol_handlers[MAX_PROTOCOL_HANDLERS];
int protocol_handler_count = 0;
packet_queue_entry_t packet_queue[MAX_PACKET_QUEUE_SIZE];
int packet_queue_head = 0;
int packet_queue_tail = 0;
rx_descriptor_t rx_descriptors[RX_BUFFER_COUNT];
uint32_t* rx_buffer;
uint32_t* tx_buffer;
uint8_t ip_address[4] = {192, 168, 1, 2}; // example IP address
typedef struct {
    uint64_t buffer_address;  // address of packet bffr
    uint16_t length;          // length of packet
    uint8_t cso;              // checksum offset
    uint8_t cmd;              // command
    uint8_t status;           // descriptor status
    uint8_t css;              // checksum start
    uint16_t special;         // special field (e.g., VLAN)
} __attribute__((packed)) tx_descriptor_t;
tx_descriptor_t tx_descriptors[TX_BUFFER_COUNT];
uint32_t current_tx_descriptor = 0;
uint8_t mac_address[ETHERNET_ADDR_LEN] = {0};
void enable_bus_mastering(uint8_t bus, uint8_t slot, uint8_t func);
uint16_t calculate_checksum(uint16_t *data, int length);
void send_arp_request(uint8_t* target_ip);
void process_icmp_packet(uint8_t* packet, uint16_t length);
void get_mac_address(uint8_t bus, uint8_t slot, uint8_t func);
void send_dhcp_request(dhcp_packet_t* offer_packet, uint8_t* offered_ip);
void setup_rx_descriptors(uint32_t io_base) {
    for (int i = 0; i < RX_BUFFER_COUNT; i++) {
        rx_descriptors[i].buffer_address = (uintptr_t)kmalloc(2048);
        rx_descriptors[i].status = 0;  // Initialize status to 0
        rx_descriptors[i].length = 0;  // Initialize length to 0
    }

    write_device_register(io_base + NIC_RDBAL, (uintptr_t)rx_descriptors & 0xFFFFFFFF);
    if (sizeof(uintptr_t) > 4) {  // 64-bit
        write_device_register(io_base + NIC_RDBAH, (uintptr_t)rx_descriptors >> 32);
    } else {  // 32-bit
        write_device_register(io_base + NIC_RDBAH, 0);  // No high part
    }

    // Set the RDT to indicate that the NIC can start using the descriptors
    write_device_register(io_base + NIC_RDT, RX_BUFFER_COUNT - 1);
}

void setup_tx_descriptors(uint32_t io_base) {
    for (int i = 0; i < TX_BUFFER_COUNT; i++) {
        tx_descriptors[i].buffer_address = 0;
        tx_descriptors[i].length = 0;
        tx_descriptors[i].cmd = 0;
        tx_descriptors[i].status = 0;
        tx_descriptors[i].cso = 0;
        tx_descriptors[i].css = 0;
        tx_descriptors[i].special = 0;
    }

    // Use uintptr_t to ensure the correct size
    uintptr_t tx_desc_addr = (uintptr_t)tx_descriptors;

    write_device_register(io_base + NIC_TDBAL, (uint32_t)(tx_desc_addr & 0xFFFFFFFF));
    if (sizeof(uintptr_t) > 4) {  // 64-bit system
        write_device_register(io_base + NIC_TDBAH, (uint32_t)(tx_desc_addr >> 32));
    } else {
        write_device_register(io_base + NIC_TDBAH, 0);  // 32-bit system
    }

    // Initialize the TX descriptor tail to the beginning of the ring buffer
    write_device_register(io_base + NIC_TDT, 0);
}

void setup_buffers(uint32_t io_base) {
    rx_buffer = (uint32_t*)kmalloc(2048);  // Allocate memory for RX buffer
    tx_buffer = (uint32_t*)kmalloc(2048);  // Allocate memory for TX buffer

    // Write the buffer base address to the NIC registers
    uint32_t rx_buffer_addr = (uint32_t)rx_buffer;
    uint32_t tx_buffer_addr = (uint32_t)tx_buffer;

    write_device_register(io_base + NIC_RDBAL, rx_buffer_addr & 0xFFFFFFFF);
    if (sizeof(rx_buffer_addr) > 4) {
        write_device_register(io_base + NIC_RDBAH, (rx_buffer_addr >> 32) & 0xFFFFFFFF);
    } else {
        write_device_register(io_base + NIC_RDBAH, 0);
    }


    write_device_register(io_base + NIC_TDBAL, tx_buffer_addr & 0xFFFFFFFF);
    write_device_register(io_base + NIC_TDBAH, (tx_buffer_addr >> 32) & 0xFFFFFFFF);

    // Initialize the descriptor tails
    write_device_register(io_base + NIC_RDT, 0);
    write_device_register(io_base + NIC_TDT, 0);
}

void enqueue_packet(uint8_t* packet, uint16_t length) {
    if ((packet_queue_tail + 1) % MAX_PACKET_QUEUE_SIZE == packet_queue_head) {
        // Queue is full, drop the packet or handle overflow
        return;
    }
    packet_queue[packet_queue_tail].packet = packet;
    packet_queue[packet_queue_tail].length = length;
    packet_queue_tail = (packet_queue_tail + 1) % MAX_PACKET_QUEUE_SIZE;
}
void dequeue_and_send_packets() {
    while (packet_queue_head != packet_queue_tail) {
        nic_send_packet(packet_queue[packet_queue_head].packet, packet_queue[packet_queue_head].length);
        packet_queue_head = (packet_queue_head + 1) % MAX_PACKET_QUEUE_SIZE;
    }
}

uint16_t ntohs(uint16_t netshort) {
    return (netshort >> 8) | (netshort << 8);
}
uint32_t ntohl(uint32_t netlong) {
    return ((netlong >> 24) & 0xFF) |
           ((netlong >> 8) & 0xFF00) |
           ((netlong << 8) & 0xFF0000) |
           ((netlong << 24) & 0xFF000000);
}
uint16_t htons(uint16_t hostshort) {
    return (hostshort >> 8) | (hostshort << 8);
}

void nic_init() {
    uint8_t bus = network_device_bus;
    uint8_t slot = network_device_slot;
    uint8_t func = network_device_func;

    enable_bus_mastering(bus, slot, func);
    uint32_t io_base = pci_read_bar(bus, slot, func, 0);
    if (io_base == 0) {
        dprintf("Error: Failed to read BAR0 for NIC\n");
        return;
    }

    // Get and set MAC address
    get_mac_address(bus, slot, func);
    dprintf("NIC MAC Address: %02x:%02x:%02x:%02x:%02x:%02x\n",
        mac_address[0], mac_address[1], mac_address[2],
        mac_address[3], mac_address[4], mac_address[5]);

    write_device_register(io_base + NIC_RESET_REGISTER, 0x1);

    setup_buffers(io_base);
    setup_rx_descriptors(io_base);
    setup_tx_descriptors(io_base);

    write_device_register(io_base + NIC_INTERRUPT_ENABLE_REGISTER, NIC_INTERRUPT_RX | NIC_INTERRUPT_TX);

    write_device_register(io_base + NIC_CONTROL_REGISTER, NIC_CONTROL_START);
}

void nic_send_packet(uint8_t* packet, uint16_t length) {
    uint32_t io_base = pci_read_bar(network_device_bus, network_device_slot, network_device_func, 0);

    // Read the current Tail Descriptor (TDT)
    // Remove the variable or cast it to void if it might be used later
    uint32_t tdt = read_device_register(io_base + NIC_TDT);
    tx_descriptor_t *desc = &tx_descriptors[tdt];

    // If the descriptor is still in use, queue the packet for later transmission
    if (!(desc->status & DESCRIPTOR_STATUS_DD)) {
        enqueue_packet(packet, length);
        return;
    }

    // Prepare the descriptor for transmission
    desc->buffer_address = (uint64_t)packet;
    desc->length = length;
    desc->cmd = NIC_TX_CMD_EOP | NIC_TX_CMD_IFCS | NIC_TX_CMD_RS;
    desc->status = 0;  // Clear the status

    // Update TDT to point to the next descriptor
    tdt = (tdt + 1) % TX_BUFFER_COUNT;
    write_device_register(io_base + NIC_TDT, tdt);
}

void register_protocol_handler(uint16_t ethertype, void (*handler)(uint8_t* packet, uint16_t length)) {
    if (protocol_handler_count >= MAX_PROTOCOL_HANDLERS) {
        dprintf("Error: Maximum number of protocol handlers reached.\n");
        return;
    }

    // Check if the handler for this ethertype is already registered
    for (int i = 0; i < protocol_handler_count; i++) {
        if (protocol_handlers[i].ethertype == ethertype) {
            dprintf("Error: Protocol handler for ethertype %04x is already registered.\n", ethertype);
            return;
        }
    }

    // Register the new handler
    protocol_handlers[protocol_handler_count].ethertype = ethertype;
    protocol_handlers[protocol_handler_count].handler = handler;
    protocol_handler_count++;

    dprintf("Registered protocol handler for ethertype %04x.\n", ethertype);
}


void nic_receive_packet() {
    uint32_t io_base = pci_read_bar(network_device_bus, network_device_slot, network_device_func, 0);

    uint32_t rdt = read_device_register(io_base + NIC_RDT);
    uint32_t rdh = read_device_register(io_base + NIC_RDH);

    // Check if there are packets ready to be processed
    while (rdt != rdh) {
        rx_descriptor_t* descriptor = &rx_descriptors[rdt];

        if (descriptor->status & DESCRIPTOR_STATUS_DD) {
            uint16_t length = descriptor->length;

            uint8_t* packet = (uint8_t*)descriptor->buffer_address;

            // Process the packet (e.g., pass it to an IP stack)
            process_packet(packet, length);

            // Reset the status of the descriptor
            descriptor->status = 0;

            // Update the RDT to mark this descriptor as processed
            rdt = (rdt + 1) % RX_BUFFER_COUNT;
            write_device_register(io_base + NIC_RDT, rdt);
        }
    }
}

void handle_tx_completion() {
    uint32_t io_base = pci_read_bar(network_device_bus, network_device_slot, network_device_func, 0);
    uint32_t tdh = read_device_register(io_base + NIC_TDH);
    uint32_t tdt = read_device_register(io_base + NIC_TDT);

    while (current_tx_descriptor != tdh) {
        tx_descriptor_t *desc = &tx_descriptors[current_tx_descriptor];

        if (desc->status & DESCRIPTOR_STATUS_DD) {
            // Transmission completed
            desc->status = 0;  // Reset the status
            // Optionally, you can free the buffer or mark it as reusable
            dequeue_and_send_packets();
            // Move to the next descriptor
            current_tx_descriptor = (current_tx_descriptor + 1) % TX_BUFFER_COUNT;
        }
    }
}


void nic_irq_handler() {
    uint32_t io_base = pci_read_bar(network_device_bus, network_device_slot, network_device_func, 0);

    uint32_t status = read_device_register(io_base + NIC_ICR);

    if (status & NIC_INTERRUPT_RX) {
        // Handle packet reception
        nic_receive_packet();
    }

    if (status & NIC_INTERRUPT_TX) {
        // Handle packet transmission completion
        handle_tx_completion();
    }

    // Acknowledge the interrupt
    write_device_register(io_base + NIC_ICR, status);
}



void process_packet(uint8_t* packet, uint16_t length) {
    if (length < sizeof(ethernet_header_t)) {
        dprintf("Received packet is too short\n");
        return;
    }

    ethernet_header_t* eth_hdr = (ethernet_header_t*)packet;
    uint16_t ethertype = ntohs(eth_hdr->ethertype);

    // Look for a registered handler for this ethertype
    for (int i = 0; i < protocol_handler_count; i++) {
        if (protocol_handlers[i].ethertype == ethertype) {
            protocol_handlers[i].handler(packet, length);
            return;
        }
    }

    dprintf("No handler registered for ethertype %04x\n", ethertype);
}

void copy_bytes(uint8_t* dest, uint8_t* src, uint16_t length) {
    for (uint16_t i = 0; i < length; i++) {
        dest[i] = src[i];
    }
}



void process_arp_packet(uint8_t* packet, uint16_t length) {
    if (length < sizeof(ethernet_header_t) + sizeof(arp_header_t)) {
        return;  // Packet is too short to contain a full ARP header
    }

    ethernet_header_t* eth_hdr = (ethernet_header_t*)packet;
    arp_header_t* arp_hdr = (arp_header_t*)(packet + sizeof(ethernet_header_t));

    if (ntohs(arp_hdr->htype) == ARP_HTYPE_ETHERNET &&
        ntohs(arp_hdr->ptype) == ARP_PTYPE_IPV4 &&
        arp_hdr->hlen == ARP_HLEN_ETHERNET &&
        arp_hdr->plen == ARP_PLEN_IPV4) {

        if (ntohs(arp_hdr->opcode) == ARP_OPCODE_REQUEST) {
            // Handle ARP request
            // Send ARP reply if the target IP matches this device's IP
        } else if (ntohs(arp_hdr->opcode) == ARP_OPCODE_REPLY) {
            // Handle ARP reply
            // Update ARP cache with the sender's MAC and IP
        }
    }
}
void process_ip_packet(uint8_t* packet, uint16_t length) {
    if (length < sizeof(ethernet_header_t) + sizeof(ip_header_t)) {
        return;  // Packet is too short to contain a full IP header
    }

    ethernet_header_t* eth_hdr = (ethernet_header_t*)packet;
    ip_header_t* ip_hdr = (ip_header_t*)(packet + sizeof(ethernet_header_t));

    // Validate IP version and header length
    uint8_t version = (ip_hdr->version_ihl >> 4) & 0xF;
    uint8_t ihl = ip_hdr->version_ihl & 0xF;

    if (version != 4 || ihl < 5) {
        return;  // Not IPv4 or invalid header length
    }

    // Handle the IP packet based on its protocol field
    switch (ip_hdr->protocol) {
        case 1: // ICMP
            process_icmp_packet(packet, length);
        break;
        case 6: // TCP (You can add TCP processing here)
            break;
        case 17: // UDP (You can add UDP processing here)
            break;
        default:
            break;
    }
}
void process_icmp_packet(uint8_t* packet, uint16_t length) {
    ip_header_t* ip_hdr = (ip_header_t*)(packet + sizeof(ethernet_header_t));
    icmp_header_t* icmp_hdr = (icmp_header_t*)(packet + sizeof(ethernet_header_t) + sizeof(ip_header_t));

    // Safely access the checksum
    uint16_t temp_checksum;
    memcpy(&temp_checksum, &icmp_hdr->checksum, sizeof(uint16_t));
    temp_checksum = calculate_checksum((uint16_t*)icmp_hdr, length - sizeof(ethernet_header_t) - sizeof(ip_header_t));

    // Update checksum
    icmp_hdr->checksum = temp_checksum;
    // Check if this is an Echo Request
    if (icmp_hdr->type == 8 && icmp_hdr->code == 0) { // Echo Request
        dprintf("Received ICMP Echo Request\n");

        // Create a reply
        uint8_t* reply_packet = kmalloc(length);
        memcpy(reply_packet, packet, length);

        // Swap Ethernet addresses
        ethernet_header_t* eth_hdr = (ethernet_header_t*)reply_packet;
        memcpy(eth_hdr->dest_mac, eth_hdr->src_mac, ETHERNET_ADDR_LEN);
        memcpy(eth_hdr->src_mac, mac_address, ETHERNET_ADDR_LEN); // Replace with your NIC's MAC

        // Swap IP addresses
        ip_hdr = (ip_header_t*)(reply_packet + sizeof(ethernet_header_t));
        uint32_t temp_ip[4];
        memcpy(temp_ip, ip_hdr->source_ip, 4);
        memcpy(ip_hdr->source_ip, ip_hdr->dest_ip, 4);
        memcpy(ip_hdr->dest_ip, temp_ip, 4);

        // Modify ICMP header for the reply
        icmp_hdr = (icmp_header_t*)(reply_packet + sizeof(ethernet_header_t) + sizeof(ip_header_t));
        icmp_hdr->type = 0; // Echo Reply
        icmp_hdr->checksum = 0;
        temp_checksum = calculate_checksum((uint16_t*)icmp_hdr, length - sizeof(ethernet_header_t) - sizeof(ip_header_t));
        memcpy(&icmp_hdr->checksum, &temp_checksum, sizeof(uint16_t));

        // Send the reply
        nic_send_packet(reply_packet, length);

        // Free the allocated memory
        kfree(reply_packet);
    }
}
uint16_t calculate_checksum(uint16_t *data, int length) {
    uint32_t sum = 0;
    while (length > 1) {
        sum += *data++;
        length -= 2;
    }

    if (length == 1) {
        sum += *(uint8_t *)data;
    }

    // Fold 32-bit sum to 16 bits
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return ~sum;
}

void send_arp_request(uint8_t* target_ip) {
    uint8_t* arp_request = kmalloc(sizeof(ethernet_header_t) + sizeof(arp_header_t));

    ethernet_header_t* eth_hdr = (ethernet_header_t*)arp_request;
    memset(eth_hdr->dest_mac, 0xFF, ETHERNET_ADDR_LEN); // Broadcast MAC address
    memcpy(eth_hdr->src_mac, mac_address, ETHERNET_ADDR_LEN); // Your NIC's MAC
    eth_hdr->ethertype = htons(ETHERTYPE_ARP);

    arp_header_t* arp_hdr = (arp_header_t*)(arp_request + sizeof(ethernet_header_t));
    arp_hdr->htype = htons(ARP_HTYPE_ETHERNET);
    arp_hdr->ptype = htons(ARP_PTYPE_IPV4);
    arp_hdr->hlen = ARP_HLEN_ETHERNET;
    arp_hdr->plen = ARP_PLEN_IPV4;
    arp_hdr->opcode = htons(ARP_OPCODE_REQUEST);
    memcpy(arp_hdr->sender_mac, mac_address, ETHERNET_ADDR_LEN);
    memcpy(arp_hdr->sender_ip, ip_address, 4);
    memset(arp_hdr->target_mac, 0, ETHERNET_ADDR_LEN);
    memcpy(arp_hdr->target_ip, target_ip, 4);

    nic_send_packet(arp_request, sizeof(ethernet_header_t) + sizeof(arp_header_t));

    kfree(arp_request);
}


void enable_bus_mastering(uint8_t bus, uint8_t slot, uint8_t func) {
    uint32_t command_register = read_pci(bus, slot, func, 0x04);
    if (!(command_register & 0x04)) {
        command_register |= 0x04;
        write_pci(bus, slot, func, 0x04, command_register);
    }
}
void get_mac_address(uint8_t bus, uint8_t slot, uint8_t func) {
    // This is highly NIC-specific; below is a generic example
    uint32_t mac_low = pci_read_bar(bus, slot, func, 0x10); // Assume MAC is stored at offset 0x10
    uint32_t mac_high = pci_read_bar(bus, slot, func, 0x14); // Assume MAC continuation at 0x14

    mac_address[0] = (mac_low >> 0) & 0xFF;
    mac_address[1] = (mac_low >> 8) & 0xFF;
    mac_address[2] = (mac_low >> 16) & 0xFF;
    mac_address[3] = (mac_low >> 24) & 0xFF;
    mac_address[4] = (mac_high >> 0) & 0xFF;
    mac_address[5] = (mac_high >> 8) & 0xFF;
}

void send_dhcp_discover(uint8_t* mac_address) {
    dhcp_packet_t discover;
    memset(&discover, 0, sizeof(dhcp_packet_t));

    discover.op = 1; // Boot request
    discover.htype = 1; // Ethernet
    discover.hlen = 6; // MAC address length
    discover.xid = ntohl(0x12345678); // Transaction ID (random value)
    discover.flags = htons(0x8000); // Broadcast flag
    memcpy(discover.chaddr, mac_address, 6);
    discover.magic_cookie = ntohl(DHCP_MAGIC_COOKIE);

    // DHCP options
    uint8_t *options = discover.options;
    *options++ = 53; // DHCP message type option
    *options++ = 1;  // Length
    *options++ = DHCP_DISCOVER; // DHCP Discover message

    *options++ = 255; // End option

    // Send the packet (using your NIC's send function)
    nic_send_packet((uint8_t*)&discover, sizeof(dhcp_packet_t));
}
void process_dhcp_offer(dhcp_packet_t* packet) {
    // Extract offered IP address
    uint8_t offered_ip[4];
    memcpy(offered_ip, packet->yiaddr, 4);

    dprintf("Received DHCP Offer: %d.%d.%d.%d\n",
        offered_ip[0], offered_ip[1], offered_ip[2], offered_ip[3]);

    // Here you would typically send a DHCP Request to accept the offer
    send_dhcp_request(packet, offered_ip);
}
void send_dhcp_request(dhcp_packet_t* offer_packet, uint8_t* offered_ip) {
    dprintf("Sending DHCP Discover...\n");

    dhcp_packet_t request;
    memset(&request, 0, sizeof(dhcp_packet_t));

    request.op = 1; // Boot request
    request.htype = 1; // Ethernet
    request.hlen = 6; // MAC address length
    request.xid = offer_packet->xid; // Use the same transaction ID as the offer
    request.flags = htons(0x8000); // Broadcast flag
    memcpy(request.chaddr, mac_address, 6);
    request.magic_cookie = ntohl(DHCP_MAGIC_COOKIE);

    // DHCP options
    uint8_t *options = request.options;
    *options++ = 53; // DHCP message type option
    *options++ = 1;  // Length
    *options++ = DHCP_REQUEST; // DHCP Request message

    *options++ = 50; // Requested IP address option
    *options++ = 4;  // Length
    memcpy(options, offered_ip, 4);
    options += 4;

    *options++ = 255; // End option

    // Send the packet (using your NIC's send function)
    nic_send_packet((uint8_t*)&request, sizeof(dhcp_packet_t));
}
void process_dhcp_ack(dhcp_packet_t* packet) {
    // Extract assigned IP address
    memcpy(ip_address, packet->yiaddr, 4);

    dprintf("DHCP ACK: IP Address assigned: %d.%d.%d.%d\n",
        ip_address[0], ip_address[1], ip_address[2], ip_address[3]);

    // Here you would typically store the IP address and other configuration parameters
}
bool receive_packet(dhcp_packet_t* packet) {
    uint32_t io_base = pci_read_bar(network_device_bus, network_device_slot, network_device_func, 0);

    uint32_t rdt = read_device_register(io_base + NIC_RDT);
    uint32_t rdh = read_device_register(io_base + NIC_RDH);

    // Check if there are packets ready to be processed
    if (rdt == rdh) {
        // No new packets to process
        return false;
    }

    rx_descriptor_t* descriptor = &rx_descriptors[rdt];

    if (descriptor->status & DESCRIPTOR_STATUS_DD) {
        // Ensure the packet fits into the provided buffer
        uint16_t length = descriptor->length;
        if (length > sizeof(dhcp_packet_t)) {
            length = sizeof(dhcp_packet_t); // Truncate to avoid overflow
        }

        // Copy the received packet into the provided structure
        memcpy(packet, (uint8_t*)descriptor->buffer_address, length);

        // Reset the status of the descriptor
        descriptor->status = 0;

        // Update the RDT to mark this descriptor as processed
        rdt = (rdt + 1) % RX_BUFFER_COUNT;
        write_device_register(io_base + NIC_RDT, rdt);

        return true; // Packet received successfully
    }

    return false; // No valid packet received
}

void dhcp_client_start() {
    // Step 1: Send DHCP Discover
    send_dhcp_discover(mac_address);

    // Wait for DHCP Offer (in a real implementation, you'd have to wait asynchronously)
    dhcp_packet_t packet;
    while (receive_packet(&packet)) { // Assume you have a function to receive packets
        if (packet.options[2] == DHCP_OFFER) {
            process_dhcp_offer(&packet);
        } else if (packet.options[2] == DHCP_ACK) {
            process_dhcp_ack(&packet);
            break;
        }
    }
}