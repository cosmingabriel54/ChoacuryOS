#pragma once

#ifndef PCI_H
#define PCI_H

#include "types.h"

u32 read_pci(u16 bus, u16 device, u16 function, u32 regoffset);
void write_pci(u16 bus, u16 device, u16 function, u32 regoffset, u32 data);
uint32_t pci_read_bar(uint8_t bus, uint8_t slot, uint8_t func, uint8_t bar_num);
void debug_print_pci();
void find_nic();

static uint8_t network_device_bus;
static uint8_t network_device_slot;
static uint8_t network_device_func;

typedef struct device_descriptor //to be updated eventually: there are more important values one might weant to read, like the BARs (base addresses of device buffers)
{
    u32 portBase;
    u32 interrupt;

    u16 bus;
    u16 device;
    u16 function;

    u16 vendor_id;
    u16 device_id;

    u8 class_id;
    u8 subclass_id;
    u8 interface_id;

    u8 revision;
} device_descriptor;

device_descriptor get_device_descriptor(u16 bus, u16 device, u16 function);

#endif