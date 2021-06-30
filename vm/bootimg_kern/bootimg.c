// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2013 Intel Corporation; author Matt Fleming
 */

// This file is largely copied from drivers/firmware/efi/earlycon.c

#include <linux/console.h>
#include <linux/delay.h>
#include <linux/efi.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/serial_core.h>
#include <linux/screen_info.h>

#include <asm/early_ioremap.h>

#include "bootimg.h"

#define BOOTIMG_X 240
#define BOOTIMG_Y 80

static const struct console *earlycon_console __initdata;
static u64 fb_base;
static bool fb_wb;
static void *efi_fb;

/*
 * EFI earlycon needs to use early_memremap() to map the framebuffer.
 * But early_memremap() is not usable for 'earlycon=efifb keep_bootcon',
 * memremap() should be used instead. memremap() will be available after
 * paging_init() which is earlier than initcall callbacks. Thus adding this
 * early initcall function early_efi_map_fb() to map the whole EFI framebuffer.
 */
static int __init bootimg_remap_fb(void)
{
	/* bail if there is no bootconsole or it has been disabled already */
	if (!earlycon_console || !(earlycon_console->flags & CON_ENABLED))
		return 0;

	efi_fb = memremap(fb_base, screen_info.lfb_size,
			  fb_wb ? MEMREMAP_WB : MEMREMAP_WC);

	return efi_fb ? 0 : -ENOMEM;
}
early_initcall(bootimg_remap_fb);

static int __init bootimg_unmap_fb(void)
{
	/* unmap the bootconsole fb unless keep_bootcon has left it enabled */
	if (efi_fb && !(earlycon_console->flags & CON_ENABLED))
		memunmap(efi_fb);
	return 0;
}
late_initcall(bootimg_unmap_fb);

static __ref void *bootimg_map(unsigned long start, unsigned long len)
{
	pgprot_t fb_prot;

	if (efi_fb)
		return efi_fb + start;

	fb_prot = fb_wb ? PAGE_KERNEL : pgprot_writecombine(PAGE_KERNEL);
	return early_memremap_prot(fb_base + start, len, pgprot_val(fb_prot));
}

static __ref void bootimg_unmap(void *addr, unsigned long len)
{
	if (efi_fb)
		return;

	early_memunmap(addr, len);
}

static void bootimg_newline(void)
{
	unsigned long line_bytes = screen_info.lfb_width * 4;
	static u8 frame = 1;
	static u8 cnt = 0;
	u32 r, c;
	u32 *dst;

	if (cnt)
		goto end;

	for (r = 0; r < BOOTIMG_H; r++) {
		dst = bootimg_map((BOOTIMG_Y + r) * line_bytes,
				  line_bytes);
		if (!dst)
			return;

		for (c = 0; c < BOOTIMG_W; c++) {
			dst[c + BOOTIMG_X] = bootimg_data[frame][r][c];
		}

		bootimg_unmap(dst, line_bytes);
	}

	frame = (frame + 1) % BOOTIMG_F;

end:
	cnt = (cnt + 1) % 2;
	mdelay(50);
}

static void
bootimg_write(struct console *con, const char *str, unsigned int num)
{
	const char *s;
	unsigned int count = 0;

	for (s = str; *s; s++) {
		if (count == num)
			break;
		count++;

		if (*s == '\n')
			bootimg_newline();
	}
}

static int __init bootimg_setup(struct earlycon_device *device,
				const char *opt)
{
	if (screen_info.orig_video_isVGA != VIDEO_TYPE_EFI)
		return -ENODEV;

	fb_base = screen_info.lfb_base;
	if (screen_info.capabilities & VIDEO_CAPABILITY_64BIT_BASE)
		fb_base |= (u64)screen_info.ext_lfb_base << 32;

	fb_wb = opt && !strcmp(opt, "ram");

	/*
	 * bootimg_write_char() implicitly assumes a framebuffer with
	 * 32 bits per pixel.
	 */
	if (screen_info.lfb_depth != 32)
		return -ENODEV;

	device->con->write = bootimg_write;
	earlycon_console = device->con;
	return 0;
}
EARLYCON_DECLARE(bootimg, bootimg_setup);
