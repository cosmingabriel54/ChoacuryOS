#include "pci.h"
#include "types.h"
#include "ports.h"
#include "debug.h"
#include "../shell/terminal.h"
#include "idt.h"
#include "nic.h"

u32 read_pci(u16 bus, u16 device, u16 function, u32 regoffset) {
    u32 id = 0x1 << 31 | ((bus & 0xFF) << 16) | ((device & 0x1F) << 11) | ((function & 0x07) << 8) | (regoffset & 0xFC);
    port_dword_out(0xCF8, id);  // give ID to PCI's command port
    u32 result = port_dword_in(0xCFC);  // read the result from PCI's data port
    return result;  // Return the raw result without any shifts
}

uint32_t pci_read_bar(uint8_t bus, uint8_t slot, uint8_t func, uint8_t bar_num) {
    // The BARs are located at offsets 0x10 to 0x24 in the PCI configuration space.
    uint32_t bar = read_pci(bus, slot, func, 0x10);
    dprintf("Raw BAR0 value: 0x%08x\n", bar);


    // Check if the BAR is for I/O space or memory space
    if (bar & 1) {
        // I/O space
        bar &= ~0x3;  // Mask the I/O space indicator bits
    } else {
        // Memory space
        bar &= ~0xF;  // Mask the memory space indicator bits
    }

    // Check for invalid BAR
    if (bar == 0) {
        dprintf("Error: BAR %d is not valid (0x%08x)\n", bar_num, bar);
    }

    return bar;
}


void write_pci(u16 bus, u16 device, u16 function, u32 regoffset, u32 data) {
    u32 id = 0x1 << 31 | ((bus & 0xFF) << 16) | ((device & 0x1F) << 11) | ((function & 0x07) << 8) | (regoffset & 0xFC); //we construct an ID like in the read function
    port_dword_out(0xCF8, id); //we give the ID to PCI's command port
    port_dword_out(0xCFC, data); //we give the data we want to send to PCI's data port
}

device_descriptor get_device_descriptor(u16 bus, u16 device, u16 function) {
    device_descriptor result;

    result.bus = bus;
    result.device = device;
    result.function = function;

    result.vendor_id = read_pci(bus, device, function, 0x00);
    result.device_id = read_pci(bus, device, function, 0x02);

    result.class_id = read_pci(bus, device, function, 0x0b);
    result.subclass_id = read_pci(bus, device, function, 0x0a);
    result.interface_id = read_pci(bus, device, function, 0x09);

    result.revision = read_pci(bus, device, function, 0x08);
    result.interrupt = read_pci(bus, device, function, 0x3c);

    return result;
}
void setup_network_device(uint8_t bus, uint8_t slot, uint8_t func) {
    dprintf("Setting up network device at bus: %d, slot: %d, function: %d\n", bus, slot, func);

    // Store the PCI location for later use in the interrupt handler
    network_device_bus = bus;
    network_device_slot = slot;
    network_device_func = func;

    // Read and print BAR0 and BAR1 to debug
    uint32_t bar0 = pci_read_bar(bus, slot, func, 0);
    dprintf("BAR0: 0x%08x\n", bar0);

    uint32_t bar1 = pci_read_bar(bus, slot, func, 1);
    dprintf("BAR1: 0x%08x\n", bar1);

    // Use bar0 or bar1 depending on which is valid
    uint32_t io_base = (bar0 != 0) ? bar0 : bar1;

    if (io_base == 0) {
        dprintf("Error: Failed to read any valid BAR for NIC\n");
        return;
    }

    // Initialize the NIC
    nic_init();
}


void debug_print_pci() {
    for(int bus = 0; bus < 8; bus++) {
        for(int device = 0; device < 32; device++) {
            for(int function = 0; function < 8; function++) {
                device_descriptor desc = get_device_descriptor(bus, device, function);
                if(desc.vendor_id == 0xFFFF) // Skip if the vendor ID is 0xFFFF, which means the function doesn't exist
                    continue;

                dprint("Bus: ");
                dprintbyte(bus);
                dprint(", Device: ");
                dprintbyte(device);
                dprint(", Function: ");
                dprintbyte(function);
                dprint(", Vendor ID: ");
                dprintbyte((u8)((desc.vendor_id & 0xFF00) >> 8));
                dprintbyte((u8)(desc.vendor_id & 0xFF));
                dprint("\r\n");

                if(desc.vendor_id == 0x0000)
                    continue;

                // Check if this is the NIC we're interested in
                if (desc.vendor_id == 0x8086 && desc.device_id == 0x100e) {
                    dprintf("Found NIC - Bus: %d, Device: %d, Function: %d\n", bus, device, function);
                    setup_network_device(bus, device, function);  // Call setup with correct bus/slot/func
                }
            }
        }
    }
}

void find_nic() {
    for (int bus = 0; bus < 8; bus++) {
        for (int device = 0; device < 32; device++) {
            for (int function = 0; function < 8; function++) {
                device_descriptor desc = get_device_descriptor(bus, device, function);
                if (desc.vendor_id == 0xFFFF) {
                    continue;  // Skip if no device
                }
                if (desc.class_id == 0x02) { // Network Controller
                    dprintf("Found NIC - Bus: %d, Device: %d, Function: %d, Vendor ID: %04x, Device ID: %04x\n",
                            bus, device, function, desc.vendor_id, desc.device_id);
                    // Store the bus, device, function for further use
                    setup_network_device(bus, device, function);
                    return;
                }
            }
        }
    }
    dprintf("No NIC found.\n");
}

