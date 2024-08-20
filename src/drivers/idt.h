#pragma once
#include "types.h"
#define IRQ_BASE 32

typedef void(*irq_handler_t)();

void idt_register_irq_handler(int irq, irq_handler_t handler);
void idt_init();
void network_device_irq_handler();
void write_device_register(uint32_t address, uint32_t value);
uint32_t read_device_register(uint32_t address);