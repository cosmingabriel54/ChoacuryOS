/*
    The kernel of Choacury
    I call it the Choakern! The code still needs to be finished tho...
*/

/* Includes needed for the kernel to actually work.*/
#include "../drivers/gdt.h"
#include "../drivers/idt.h"
#include "../drivers/keymaps/ps2_keymap_us.h"   // <-- US Keyboard Layout.
#include "../drivers/mouse.h"
#include "../drivers/pic.h"
#include "../drivers/pci.h"
#include "../drivers/pit.h"
#include "../drivers/ports.h"
#include "../drivers/ps2.h"
#include "../drivers/sound.h"
#include "../drivers/storage/device.h"
#include "../drivers/types.h"
#include "../drivers/utils.h"
#include "../drivers/vga.h"
#include "../memory/kmalloc.h"
#include "../memory/pmm.h"
#include "../shell/shell.h"
#include "../shell/terminal.h"
#include "multiboot.h"
#include "panic.h"
#include "process.h"
#include "../drivers/nic.h"
/* Startup Beep*/
void StartUp_Beeps() {
    startbeep(450);
    pit_sleep_ms(100);
    mutebeep();
    startbeep(775);
    pit_sleep_ms(50);
    mutebeep();
}

/* A Simple kernel written in C
 * These parameters are pushed onto the stack by the assembly kernel entry file.
 */

void k_main(multiboot_info_t* mbd, uint32_t magic) {
    gdt_init();
    idt_init();
    kmalloc_init();

    vga_text_init(TC_BLACK);

    u32 term_width = VGA_width;
    u32 visible_height = VGA_height;
    u32 buffer_height = visible_height + 100;

    term_init(term_width, buffer_height, visible_height, vga_set_char, vga_move_cursor);

    term_write("\n\xB0\xB1\xB2\xDB Welcome to Choacury! \xDB\xB2\xB1\xB0\n", TC_LIME);
    term_write("Version: Build " __DATE__ " (GUI Testing)\n", TC_WHITE);
    term_write("(C)opyright: \2 Pineconium 2023, 2024.\n\n", TC_WHITE);

    if (magic != MULTIBOOT_BOOTLOADER_MAGIC) {
        panic("Bootloader did not provide multiboot information\n");
    }

    pmm_init(mbd);
    pic_init();
	pit_init();
	asm volatile("sti");
    ps2_init();

    ps2_init_keymap_us();

    // StartUp_Beeps();
    storage_device_init();
    //debug_print_pci();
    //nic_init();

    // Start the DHCP client
    //dhcp_client_start();
    shell_start();
}



