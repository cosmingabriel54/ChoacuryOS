#include "idt.h"
#include "pic.h"
#include "ports.h"

#define PIC_PORT_CMD_MASTER  0x20
#define PIC_PORT_DATA_MASTER 0x21
#define PIC_PORT_CMD_SLAVE   0xA0
#define PIC_PORT_DATA_SLAVE  0xA1

#define ICW1_ICW4       0x01
#define ICW1_SINGLE     0x02
#define ICW1_INTERVAL4  0x04
#define ICW1_LEVEL      0x08
#define ICW1_INIT       0x10

#define ICW4_8086       0x01

#define PIC_CMD_EOI 0x20

void pic_init() {
    port_byte_out(PIC_PORT_CMD_MASTER, ICW1_INIT | ICW1_ICW4);
    port_byte_out(PIC_PORT_CMD_SLAVE,  ICW1_INIT | ICW1_ICW4);

    port_byte_out(PIC_PORT_DATA_MASTER, IRQ_BASE);
    port_byte_out(PIC_PORT_DATA_SLAVE,  IRQ_BASE + 8);

    port_byte_out(PIC_PORT_DATA_MASTER, 4);
    port_byte_out(PIC_PORT_DATA_SLAVE,  2);

    port_byte_out(PIC_PORT_DATA_MASTER, ICW4_8086);
    port_byte_out(PIC_PORT_DATA_SLAVE,  ICW4_8086);

    port_byte_out(PIC_PORT_DATA_MASTER, 0xFB);  // Initially mask everything but slave
    port_byte_out(PIC_PORT_DATA_SLAVE,  0xFF);
}

void pic_unmask(u8 irq) {
    u16 port;
    if (irq >= 8) {
        port = PIC_PORT_DATA_SLAVE;
        irq -= 8;
    } else {
        port = PIC_PORT_DATA_MASTER;
    }

    u8 original = port_byte_in(port);
    port_byte_out(port, original & ~(1u << irq));
}

void pic_send_eoi(u8 irq) {
    if (irq >= 8) {
        port_byte_out(PIC_PORT_CMD_SLAVE, PIC_CMD_EOI);
    }
    port_byte_out(PIC_PORT_CMD_MASTER, PIC_CMD_EOI);
}

bool pic_is_in_service(u8 irq) {
    u16 port = PIC_PORT_CMD_MASTER;
    if (irq >= 8) {
        port = PIC_PORT_CMD_SLAVE;
        irq -= 8;
    }
    port_byte_out(port, PIC_CMD_EOI);
    return port_byte_in(port) & (1 << irq);
}
