/*
 * QEMU OpenTitan Darjeeling Ibex wrapper device
 *
 * Copyright (c) 2022-2023 Rivos, Inc.
 *
 * Author(s):
 *  Emmanuel Blot <eblot@rivosinc.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "qemu/osdep.h"
#include "qemu/log.h"
#include "qemu/main-loop.h"
#include "qemu/typedefs.h"
#include "qapi/error.h"
#include "exec/address-spaces.h"
#include "hw/opentitan/ot_edn.h"
#include "hw/opentitan/ot_ibex_wrapper_darjeeling.h"
#include "hw/qdev-properties-system.h"
#include "hw/qdev-properties.h"
#include "hw/registerfields.h"
#include "hw/riscv/ibex_common.h"
#include "hw/sysbus.h"
#include "trace.h"


/* DEBUG: define to print the full memory view on remap */
#undef PRINT_MTREE

#define PARAM_NUM_SW_ALERTS     2u
#define PARAM_NUM_REGIONS       32u
#define PARAM_NUM_SCRATCH_WORDS 8u
#define PARAM_NUM_ALERTS        4u

/* clang-format off */
REG32(ALERT_TEST, 0x0u)
    FIELD(ALERT_TEST, FATAL_SW, 0u, 1u)
    FIELD(ALERT_TEST, RECOV_SW, 1u, 1u)
    FIELD(ALERT_TEST, FATAL_HW, 2u, 1u)
    FIELD(ALERT_TEST, RECOV_HW, 3u, 1u)
REG32(SW_RECOV_ERR, 0x4u)
    FIELD(SW_RECOV_ERR, VAL, 0u, 4u)
REG32(SW_FATAL_ERR, 0x8u)
    FIELD(SW_FATAL_ERR, VAL, 0u, 4u)
REG32(IBUS_REGWEN_0, 0xcu)
    SHARED_FIELD(REGWEN_EN, 0u, 1u)
REG32(IBUS_REGWEN_1, 0x10u)
REG32(IBUS_REGWEN_2, 0x14u)
REG32(IBUS_REGWEN_3, 0x18u)
REG32(IBUS_REGWEN_4, 0x1cu)
REG32(IBUS_REGWEN_5, 0x20u)
REG32(IBUS_REGWEN_6, 0x24u)
REG32(IBUS_REGWEN_7, 0x28u)
REG32(IBUS_REGWEN_8, 0x2cu)
REG32(IBUS_REGWEN_9, 0x30u)
REG32(IBUS_REGWEN_10, 0x34u)
REG32(IBUS_REGWEN_11, 0x38u)
REG32(IBUS_REGWEN_12, 0x3cu)
REG32(IBUS_REGWEN_13, 0x40u)
REG32(IBUS_REGWEN_14, 0x44u)
REG32(IBUS_REGWEN_15, 0x48u)
REG32(IBUS_REGWEN_16, 0x4cu)
REG32(IBUS_REGWEN_17, 0x50u)
REG32(IBUS_REGWEN_18, 0x54u)
REG32(IBUS_REGWEN_19, 0x58u)
REG32(IBUS_REGWEN_20, 0x5cu)
REG32(IBUS_REGWEN_21, 0x60u)
REG32(IBUS_REGWEN_22, 0x64u)
REG32(IBUS_REGWEN_23, 0x68u)
REG32(IBUS_REGWEN_24, 0x6cu)
REG32(IBUS_REGWEN_25, 0x70u)
REG32(IBUS_REGWEN_26, 0x74u)
REG32(IBUS_REGWEN_27, 0x78u)
REG32(IBUS_REGWEN_28, 0x7cu)
REG32(IBUS_REGWEN_29, 0x80u)
REG32(IBUS_REGWEN_30, 0x84u)
REG32(IBUS_REGWEN_31, 0x88u)
REG32(IBUS_ADDR_EN_0, 0x8cu)
    SHARED_FIELD(ADDR_EN, 0u, 1u)
REG32(IBUS_ADDR_EN_1, 0x90u)
REG32(IBUS_ADDR_EN_2, 0x94u)
REG32(IBUS_ADDR_EN_3, 0x98u)
REG32(IBUS_ADDR_EN_4, 0x9cu)
REG32(IBUS_ADDR_EN_5, 0xa0u)
REG32(IBUS_ADDR_EN_6, 0xa4u)
REG32(IBUS_ADDR_EN_7, 0xa8u)
REG32(IBUS_ADDR_EN_8, 0xacu)
REG32(IBUS_ADDR_EN_9, 0xb0u)
REG32(IBUS_ADDR_EN_10, 0xb4u)
REG32(IBUS_ADDR_EN_11, 0xb8u)
REG32(IBUS_ADDR_EN_12, 0xbcu)
REG32(IBUS_ADDR_EN_13, 0xc0u)
REG32(IBUS_ADDR_EN_14, 0xc4u)
REG32(IBUS_ADDR_EN_15, 0xc8u)
REG32(IBUS_ADDR_EN_16, 0xccu)
REG32(IBUS_ADDR_EN_17, 0xd0u)
REG32(IBUS_ADDR_EN_18, 0xd4u)
REG32(IBUS_ADDR_EN_19, 0xd8u)
REG32(IBUS_ADDR_EN_20, 0xdcu)
REG32(IBUS_ADDR_EN_21, 0xe0u)
REG32(IBUS_ADDR_EN_22, 0xe4u)
REG32(IBUS_ADDR_EN_23, 0xe8u)
REG32(IBUS_ADDR_EN_24, 0xecu)
REG32(IBUS_ADDR_EN_25, 0xf0u)
REG32(IBUS_ADDR_EN_26, 0xf4u)
REG32(IBUS_ADDR_EN_27, 0xf8u)
REG32(IBUS_ADDR_EN_28, 0xfcu)
REG32(IBUS_ADDR_EN_29, 0x100u)
REG32(IBUS_ADDR_EN_30, 0x104u)
REG32(IBUS_ADDR_EN_31, 0x108u)
REG32(IBUS_ADDR_MATCHING_0, 0x10cu)
REG32(IBUS_ADDR_MATCHING_1, 0x110u)
REG32(IBUS_ADDR_MATCHING_2, 0x114u)
REG32(IBUS_ADDR_MATCHING_3, 0x118u)
REG32(IBUS_ADDR_MATCHING_4, 0x11cu)
REG32(IBUS_ADDR_MATCHING_5, 0x120u)
REG32(IBUS_ADDR_MATCHING_6, 0x124u)
REG32(IBUS_ADDR_MATCHING_7, 0x128u)
REG32(IBUS_ADDR_MATCHING_8, 0x12cu)
REG32(IBUS_ADDR_MATCHING_9, 0x130u)
REG32(IBUS_ADDR_MATCHING_10, 0x134u)
REG32(IBUS_ADDR_MATCHING_11, 0x138u)
REG32(IBUS_ADDR_MATCHING_12, 0x13cu)
REG32(IBUS_ADDR_MATCHING_13, 0x140u)
REG32(IBUS_ADDR_MATCHING_14, 0x144u)
REG32(IBUS_ADDR_MATCHING_15, 0x148u)
REG32(IBUS_ADDR_MATCHING_16, 0x14cu)
REG32(IBUS_ADDR_MATCHING_17, 0x150u)
REG32(IBUS_ADDR_MATCHING_18, 0x154u)
REG32(IBUS_ADDR_MATCHING_19, 0x158u)
REG32(IBUS_ADDR_MATCHING_20, 0x15cu)
REG32(IBUS_ADDR_MATCHING_21, 0x160u)
REG32(IBUS_ADDR_MATCHING_22, 0x164u)
REG32(IBUS_ADDR_MATCHING_23, 0x168u)
REG32(IBUS_ADDR_MATCHING_24, 0x16cu)
REG32(IBUS_ADDR_MATCHING_25, 0x170u)
REG32(IBUS_ADDR_MATCHING_26, 0x174u)
REG32(IBUS_ADDR_MATCHING_27, 0x178u)
REG32(IBUS_ADDR_MATCHING_28, 0x17cu)
REG32(IBUS_ADDR_MATCHING_29, 0x180u)
REG32(IBUS_ADDR_MATCHING_30, 0x184u)
REG32(IBUS_ADDR_MATCHING_31, 0x188u)
REG32(IBUS_REMAP_ADDR_0, 0x18cu)
REG32(IBUS_REMAP_ADDR_1, 0x190u)
REG32(IBUS_REMAP_ADDR_2, 0x194u)
REG32(IBUS_REMAP_ADDR_3, 0x198u)
REG32(IBUS_REMAP_ADDR_4, 0x19cu)
REG32(IBUS_REMAP_ADDR_5, 0x1a0u)
REG32(IBUS_REMAP_ADDR_6, 0x1a4u)
REG32(IBUS_REMAP_ADDR_7, 0x1a8u)
REG32(IBUS_REMAP_ADDR_8, 0x1acu)
REG32(IBUS_REMAP_ADDR_9, 0x1b0u)
REG32(IBUS_REMAP_ADDR_10, 0x1b4u)
REG32(IBUS_REMAP_ADDR_11, 0x1b8u)
REG32(IBUS_REMAP_ADDR_12, 0x1bcu)
REG32(IBUS_REMAP_ADDR_13, 0x1c0u)
REG32(IBUS_REMAP_ADDR_14, 0x1c4u)
REG32(IBUS_REMAP_ADDR_15, 0x1c8u)
REG32(IBUS_REMAP_ADDR_16, 0x1ccu)
REG32(IBUS_REMAP_ADDR_17, 0x1d0u)
REG32(IBUS_REMAP_ADDR_18, 0x1d4u)
REG32(IBUS_REMAP_ADDR_19, 0x1d8u)
REG32(IBUS_REMAP_ADDR_20, 0x1dcu)
REG32(IBUS_REMAP_ADDR_21, 0x1e0u)
REG32(IBUS_REMAP_ADDR_22, 0x1e4u)
REG32(IBUS_REMAP_ADDR_23, 0x1e8u)
REG32(IBUS_REMAP_ADDR_24, 0x1ecu)
REG32(IBUS_REMAP_ADDR_25, 0x1f0u)
REG32(IBUS_REMAP_ADDR_26, 0x1f4u)
REG32(IBUS_REMAP_ADDR_27, 0x1f8u)
REG32(IBUS_REMAP_ADDR_28, 0x1fcu)
REG32(IBUS_REMAP_ADDR_29, 0x200u)
REG32(IBUS_REMAP_ADDR_30, 0x204u)
REG32(IBUS_REMAP_ADDR_31, 0x208u)
REG32(DBUS_REGWEN_0, 0x20cu)
REG32(DBUS_REGWEN_1, 0x210u)
REG32(DBUS_REGWEN_2, 0x214u)
REG32(DBUS_REGWEN_3, 0x218u)
REG32(DBUS_REGWEN_4, 0x21cu)
REG32(DBUS_REGWEN_5, 0x220u)
REG32(DBUS_REGWEN_6, 0x224u)
REG32(DBUS_REGWEN_7, 0x228u)
REG32(DBUS_REGWEN_8, 0x22cu)
REG32(DBUS_REGWEN_9, 0x230u)
REG32(DBUS_REGWEN_10, 0x234u)
REG32(DBUS_REGWEN_11, 0x238u)
REG32(DBUS_REGWEN_12, 0x23cu)
REG32(DBUS_REGWEN_13, 0x240u)
REG32(DBUS_REGWEN_14, 0x244u)
REG32(DBUS_REGWEN_15, 0x248u)
REG32(DBUS_REGWEN_16, 0x24cu)
REG32(DBUS_REGWEN_17, 0x250u)
REG32(DBUS_REGWEN_18, 0x254u)
REG32(DBUS_REGWEN_19, 0x258u)
REG32(DBUS_REGWEN_20, 0x25cu)
REG32(DBUS_REGWEN_21, 0x260u)
REG32(DBUS_REGWEN_22, 0x264u)
REG32(DBUS_REGWEN_23, 0x268u)
REG32(DBUS_REGWEN_24, 0x26cu)
REG32(DBUS_REGWEN_25, 0x270u)
REG32(DBUS_REGWEN_26, 0x274u)
REG32(DBUS_REGWEN_27, 0x278u)
REG32(DBUS_REGWEN_28, 0x27cu)
REG32(DBUS_REGWEN_29, 0x280u)
REG32(DBUS_REGWEN_30, 0x284u)
REG32(DBUS_REGWEN_31, 0x288u)
REG32(DBUS_ADDR_EN_0, 0x28cu)
REG32(DBUS_ADDR_EN_1, 0x290u)
REG32(DBUS_ADDR_EN_2, 0x294u)
REG32(DBUS_ADDR_EN_3, 0x298u)
REG32(DBUS_ADDR_EN_4, 0x29cu)
REG32(DBUS_ADDR_EN_5, 0x2a0u)
REG32(DBUS_ADDR_EN_6, 0x2a4u)
REG32(DBUS_ADDR_EN_7, 0x2a8u)
REG32(DBUS_ADDR_EN_8, 0x2acu)
REG32(DBUS_ADDR_EN_9, 0x2b0u)
REG32(DBUS_ADDR_EN_10, 0x2b4u)
REG32(DBUS_ADDR_EN_11, 0x2b8u)
REG32(DBUS_ADDR_EN_12, 0x2bcu)
REG32(DBUS_ADDR_EN_13, 0x2c0u)
REG32(DBUS_ADDR_EN_14, 0x2c4u)
REG32(DBUS_ADDR_EN_15, 0x2c8u)
REG32(DBUS_ADDR_EN_16, 0x2ccu)
REG32(DBUS_ADDR_EN_17, 0x2d0u)
REG32(DBUS_ADDR_EN_18, 0x2d4u)
REG32(DBUS_ADDR_EN_19, 0x2d8u)
REG32(DBUS_ADDR_EN_20, 0x2dcu)
REG32(DBUS_ADDR_EN_21, 0x2e0u)
REG32(DBUS_ADDR_EN_22, 0x2e4u)
REG32(DBUS_ADDR_EN_23, 0x2e8u)
REG32(DBUS_ADDR_EN_24, 0x2ecu)
REG32(DBUS_ADDR_EN_25, 0x2f0u)
REG32(DBUS_ADDR_EN_26, 0x2f4u)
REG32(DBUS_ADDR_EN_27, 0x2f8u)
REG32(DBUS_ADDR_EN_28, 0x2fcu)
REG32(DBUS_ADDR_EN_29, 0x300u)
REG32(DBUS_ADDR_EN_30, 0x304u)
REG32(DBUS_ADDR_EN_31, 0x308u)
REG32(DBUS_ADDR_MATCHING_0, 0x30cu)
REG32(DBUS_ADDR_MATCHING_1, 0x310u)
REG32(DBUS_ADDR_MATCHING_2, 0x314u)
REG32(DBUS_ADDR_MATCHING_3, 0x318u)
REG32(DBUS_ADDR_MATCHING_4, 0x31cu)
REG32(DBUS_ADDR_MATCHING_5, 0x320u)
REG32(DBUS_ADDR_MATCHING_6, 0x324u)
REG32(DBUS_ADDR_MATCHING_7, 0x328u)
REG32(DBUS_ADDR_MATCHING_8, 0x32cu)
REG32(DBUS_ADDR_MATCHING_9, 0x330u)
REG32(DBUS_ADDR_MATCHING_10, 0x334u)
REG32(DBUS_ADDR_MATCHING_11, 0x338u)
REG32(DBUS_ADDR_MATCHING_12, 0x33cu)
REG32(DBUS_ADDR_MATCHING_13, 0x340u)
REG32(DBUS_ADDR_MATCHING_14, 0x344u)
REG32(DBUS_ADDR_MATCHING_15, 0x348u)
REG32(DBUS_ADDR_MATCHING_16, 0x34cu)
REG32(DBUS_ADDR_MATCHING_17, 0x350u)
REG32(DBUS_ADDR_MATCHING_18, 0x354u)
REG32(DBUS_ADDR_MATCHING_19, 0x358u)
REG32(DBUS_ADDR_MATCHING_20, 0x35cu)
REG32(DBUS_ADDR_MATCHING_21, 0x360u)
REG32(DBUS_ADDR_MATCHING_22, 0x364u)
REG32(DBUS_ADDR_MATCHING_23, 0x368u)
REG32(DBUS_ADDR_MATCHING_24, 0x36cu)
REG32(DBUS_ADDR_MATCHING_25, 0x370u)
REG32(DBUS_ADDR_MATCHING_26, 0x374u)
REG32(DBUS_ADDR_MATCHING_27, 0x378u)
REG32(DBUS_ADDR_MATCHING_28, 0x37cu)
REG32(DBUS_ADDR_MATCHING_29, 0x380u)
REG32(DBUS_ADDR_MATCHING_30, 0x384u)
REG32(DBUS_ADDR_MATCHING_31, 0x388u)
REG32(DBUS_REMAP_ADDR_0, 0x38cu)
REG32(DBUS_REMAP_ADDR_1, 0x390u)
REG32(DBUS_REMAP_ADDR_2, 0x394u)
REG32(DBUS_REMAP_ADDR_3, 0x398u)
REG32(DBUS_REMAP_ADDR_4, 0x39cu)
REG32(DBUS_REMAP_ADDR_5, 0x3a0u)
REG32(DBUS_REMAP_ADDR_6, 0x3a4u)
REG32(DBUS_REMAP_ADDR_7, 0x3a8u)
REG32(DBUS_REMAP_ADDR_8, 0x3acu)
REG32(DBUS_REMAP_ADDR_9, 0x3b0u)
REG32(DBUS_REMAP_ADDR_10, 0x3b4u)
REG32(DBUS_REMAP_ADDR_11, 0x3b8u)
REG32(DBUS_REMAP_ADDR_12, 0x3bcu)
REG32(DBUS_REMAP_ADDR_13, 0x3c0u)
REG32(DBUS_REMAP_ADDR_14, 0x3c4u)
REG32(DBUS_REMAP_ADDR_15, 0x3c8u)
REG32(DBUS_REMAP_ADDR_16, 0x3ccu)
REG32(DBUS_REMAP_ADDR_17, 0x3d0u)
REG32(DBUS_REMAP_ADDR_18, 0x3d4u)
REG32(DBUS_REMAP_ADDR_19, 0x3d8u)
REG32(DBUS_REMAP_ADDR_20, 0x3dcu)
REG32(DBUS_REMAP_ADDR_21, 0x3e0u)
REG32(DBUS_REMAP_ADDR_22, 0x3e4u)
REG32(DBUS_REMAP_ADDR_23, 0x3e8u)
REG32(DBUS_REMAP_ADDR_24, 0x3ecu)
REG32(DBUS_REMAP_ADDR_25, 0x3f0u)
REG32(DBUS_REMAP_ADDR_26, 0x3f4u)
REG32(DBUS_REMAP_ADDR_27, 0x3f8u)
REG32(DBUS_REMAP_ADDR_28, 0x3fcu)
REG32(DBUS_REMAP_ADDR_29, 0x400u)
REG32(DBUS_REMAP_ADDR_30, 0x404u)
REG32(DBUS_REMAP_ADDR_31, 0x408u)
REG32(NMI_ENABLE, 0x40cu)
    SHARED_FIELD(NMI_ALERT_EN_BIT, 0u, 1u)
    SHARED_FIELD(NMI_WDOG_EN_BIT, 1u, 1u)
REG32(NMI_STATE, 0x410u)
REG32(ERR_STATUS, 0x414u)
    FIELD(ERR_STATUS, REG_INTG, 0u, 1u)
    FIELD(ERR_STATUS, FATAL_INTG, 8u, 1u)
    FIELD(ERR_STATUS, FATAL_CORE, 9u, 1u)
    FIELD(ERR_STATUS, RECOV_CORE, 10u, 1u)
REG32(RND_DATA, 0x418u)
REG32(RND_STATUS, 0x41cu)
    FIELD(RND_STATUS, RND_DATA_VALID, 0u, 1u)
    FIELD(RND_STATUS, RND_DATA_FIPS, 1u, 1u)
REG32(FPGA_INFO, 0x420u)
/* clang-format on */

#define R32_OFF(_r_) ((_r_) / sizeof(uint32_t))

#define R_LAST_REG (R_FPGA_INFO)
#define REGS_COUNT (R_LAST_REG + 1u)
#define REGS_SIZE  (REGS_COUNT * sizeof(uint32_t))
#define REG_NAME(_reg_) \
    ((((_reg_) <= REGS_COUNT) && REG_NAMES[_reg_]) ? REG_NAMES[_reg_] : "?")

#define REG_NAME_ENTRY(_reg_) [R_##_reg_] = stringify(_reg_)
static const char *REG_NAMES[REGS_COUNT] = {
    REG_NAME_ENTRY(ALERT_TEST),
    REG_NAME_ENTRY(SW_RECOV_ERR),
    REG_NAME_ENTRY(SW_FATAL_ERR),
    REG_NAME_ENTRY(IBUS_REGWEN_0),
    REG_NAME_ENTRY(IBUS_REGWEN_1),
    REG_NAME_ENTRY(IBUS_REGWEN_2),
    REG_NAME_ENTRY(IBUS_REGWEN_3),
    REG_NAME_ENTRY(IBUS_REGWEN_4),
    REG_NAME_ENTRY(IBUS_REGWEN_5),
    REG_NAME_ENTRY(IBUS_REGWEN_6),
    REG_NAME_ENTRY(IBUS_REGWEN_7),
    REG_NAME_ENTRY(IBUS_REGWEN_8),
    REG_NAME_ENTRY(IBUS_REGWEN_9),
    REG_NAME_ENTRY(IBUS_REGWEN_10),
    REG_NAME_ENTRY(IBUS_REGWEN_11),
    REG_NAME_ENTRY(IBUS_REGWEN_12),
    REG_NAME_ENTRY(IBUS_REGWEN_13),
    REG_NAME_ENTRY(IBUS_REGWEN_14),
    REG_NAME_ENTRY(IBUS_REGWEN_15),
    REG_NAME_ENTRY(IBUS_REGWEN_16),
    REG_NAME_ENTRY(IBUS_REGWEN_17),
    REG_NAME_ENTRY(IBUS_REGWEN_18),
    REG_NAME_ENTRY(IBUS_REGWEN_19),
    REG_NAME_ENTRY(IBUS_REGWEN_20),
    REG_NAME_ENTRY(IBUS_REGWEN_21),
    REG_NAME_ENTRY(IBUS_REGWEN_22),
    REG_NAME_ENTRY(IBUS_REGWEN_23),
    REG_NAME_ENTRY(IBUS_REGWEN_24),
    REG_NAME_ENTRY(IBUS_REGWEN_25),
    REG_NAME_ENTRY(IBUS_REGWEN_26),
    REG_NAME_ENTRY(IBUS_REGWEN_27),
    REG_NAME_ENTRY(IBUS_REGWEN_28),
    REG_NAME_ENTRY(IBUS_REGWEN_29),
    REG_NAME_ENTRY(IBUS_REGWEN_30),
    REG_NAME_ENTRY(IBUS_REGWEN_31),
    REG_NAME_ENTRY(IBUS_ADDR_EN_0),
    REG_NAME_ENTRY(IBUS_ADDR_EN_1),
    REG_NAME_ENTRY(IBUS_ADDR_EN_2),
    REG_NAME_ENTRY(IBUS_ADDR_EN_3),
    REG_NAME_ENTRY(IBUS_ADDR_EN_4),
    REG_NAME_ENTRY(IBUS_ADDR_EN_5),
    REG_NAME_ENTRY(IBUS_ADDR_EN_6),
    REG_NAME_ENTRY(IBUS_ADDR_EN_7),
    REG_NAME_ENTRY(IBUS_ADDR_EN_8),
    REG_NAME_ENTRY(IBUS_ADDR_EN_9),
    REG_NAME_ENTRY(IBUS_ADDR_EN_10),
    REG_NAME_ENTRY(IBUS_ADDR_EN_11),
    REG_NAME_ENTRY(IBUS_ADDR_EN_12),
    REG_NAME_ENTRY(IBUS_ADDR_EN_13),
    REG_NAME_ENTRY(IBUS_ADDR_EN_14),
    REG_NAME_ENTRY(IBUS_ADDR_EN_15),
    REG_NAME_ENTRY(IBUS_ADDR_EN_16),
    REG_NAME_ENTRY(IBUS_ADDR_EN_17),
    REG_NAME_ENTRY(IBUS_ADDR_EN_18),
    REG_NAME_ENTRY(IBUS_ADDR_EN_19),
    REG_NAME_ENTRY(IBUS_ADDR_EN_20),
    REG_NAME_ENTRY(IBUS_ADDR_EN_21),
    REG_NAME_ENTRY(IBUS_ADDR_EN_22),
    REG_NAME_ENTRY(IBUS_ADDR_EN_23),
    REG_NAME_ENTRY(IBUS_ADDR_EN_24),
    REG_NAME_ENTRY(IBUS_ADDR_EN_25),
    REG_NAME_ENTRY(IBUS_ADDR_EN_26),
    REG_NAME_ENTRY(IBUS_ADDR_EN_27),
    REG_NAME_ENTRY(IBUS_ADDR_EN_28),
    REG_NAME_ENTRY(IBUS_ADDR_EN_29),
    REG_NAME_ENTRY(IBUS_ADDR_EN_30),
    REG_NAME_ENTRY(IBUS_ADDR_EN_31),
    REG_NAME_ENTRY(IBUS_ADDR_MATCHING_0),
    REG_NAME_ENTRY(IBUS_ADDR_MATCHING_1),
    REG_NAME_ENTRY(IBUS_ADDR_MATCHING_2),
    REG_NAME_ENTRY(IBUS_ADDR_MATCHING_3),
    REG_NAME_ENTRY(IBUS_ADDR_MATCHING_4),
    REG_NAME_ENTRY(IBUS_ADDR_MATCHING_5),
    REG_NAME_ENTRY(IBUS_ADDR_MATCHING_6),
    REG_NAME_ENTRY(IBUS_ADDR_MATCHING_7),
    REG_NAME_ENTRY(IBUS_ADDR_MATCHING_8),
    REG_NAME_ENTRY(IBUS_ADDR_MATCHING_9),
    REG_NAME_ENTRY(IBUS_ADDR_MATCHING_10),
    REG_NAME_ENTRY(IBUS_ADDR_MATCHING_11),
    REG_NAME_ENTRY(IBUS_ADDR_MATCHING_12),
    REG_NAME_ENTRY(IBUS_ADDR_MATCHING_13),
    REG_NAME_ENTRY(IBUS_ADDR_MATCHING_14),
    REG_NAME_ENTRY(IBUS_ADDR_MATCHING_15),
    REG_NAME_ENTRY(IBUS_ADDR_MATCHING_16),
    REG_NAME_ENTRY(IBUS_ADDR_MATCHING_17),
    REG_NAME_ENTRY(IBUS_ADDR_MATCHING_18),
    REG_NAME_ENTRY(IBUS_ADDR_MATCHING_19),
    REG_NAME_ENTRY(IBUS_ADDR_MATCHING_20),
    REG_NAME_ENTRY(IBUS_ADDR_MATCHING_21),
    REG_NAME_ENTRY(IBUS_ADDR_MATCHING_22),
    REG_NAME_ENTRY(IBUS_ADDR_MATCHING_23),
    REG_NAME_ENTRY(IBUS_ADDR_MATCHING_24),
    REG_NAME_ENTRY(IBUS_ADDR_MATCHING_25),
    REG_NAME_ENTRY(IBUS_ADDR_MATCHING_26),
    REG_NAME_ENTRY(IBUS_ADDR_MATCHING_27),
    REG_NAME_ENTRY(IBUS_ADDR_MATCHING_28),
    REG_NAME_ENTRY(IBUS_ADDR_MATCHING_29),
    REG_NAME_ENTRY(IBUS_ADDR_MATCHING_30),
    REG_NAME_ENTRY(IBUS_ADDR_MATCHING_31),
    REG_NAME_ENTRY(IBUS_REMAP_ADDR_0),
    REG_NAME_ENTRY(IBUS_REMAP_ADDR_1),
    REG_NAME_ENTRY(IBUS_REMAP_ADDR_2),
    REG_NAME_ENTRY(IBUS_REMAP_ADDR_3),
    REG_NAME_ENTRY(IBUS_REMAP_ADDR_4),
    REG_NAME_ENTRY(IBUS_REMAP_ADDR_5),
    REG_NAME_ENTRY(IBUS_REMAP_ADDR_6),
    REG_NAME_ENTRY(IBUS_REMAP_ADDR_7),
    REG_NAME_ENTRY(IBUS_REMAP_ADDR_8),
    REG_NAME_ENTRY(IBUS_REMAP_ADDR_9),
    REG_NAME_ENTRY(IBUS_REMAP_ADDR_10),
    REG_NAME_ENTRY(IBUS_REMAP_ADDR_11),
    REG_NAME_ENTRY(IBUS_REMAP_ADDR_12),
    REG_NAME_ENTRY(IBUS_REMAP_ADDR_13),
    REG_NAME_ENTRY(IBUS_REMAP_ADDR_14),
    REG_NAME_ENTRY(IBUS_REMAP_ADDR_15),
    REG_NAME_ENTRY(IBUS_REMAP_ADDR_16),
    REG_NAME_ENTRY(IBUS_REMAP_ADDR_17),
    REG_NAME_ENTRY(IBUS_REMAP_ADDR_18),
    REG_NAME_ENTRY(IBUS_REMAP_ADDR_19),
    REG_NAME_ENTRY(IBUS_REMAP_ADDR_20),
    REG_NAME_ENTRY(IBUS_REMAP_ADDR_21),
    REG_NAME_ENTRY(IBUS_REMAP_ADDR_22),
    REG_NAME_ENTRY(IBUS_REMAP_ADDR_23),
    REG_NAME_ENTRY(IBUS_REMAP_ADDR_24),
    REG_NAME_ENTRY(IBUS_REMAP_ADDR_25),
    REG_NAME_ENTRY(IBUS_REMAP_ADDR_26),
    REG_NAME_ENTRY(IBUS_REMAP_ADDR_27),
    REG_NAME_ENTRY(IBUS_REMAP_ADDR_28),
    REG_NAME_ENTRY(IBUS_REMAP_ADDR_29),
    REG_NAME_ENTRY(IBUS_REMAP_ADDR_30),
    REG_NAME_ENTRY(IBUS_REMAP_ADDR_31),
    REG_NAME_ENTRY(DBUS_REGWEN_0),
    REG_NAME_ENTRY(DBUS_REGWEN_1),
    REG_NAME_ENTRY(DBUS_REGWEN_2),
    REG_NAME_ENTRY(DBUS_REGWEN_3),
    REG_NAME_ENTRY(DBUS_REGWEN_4),
    REG_NAME_ENTRY(DBUS_REGWEN_5),
    REG_NAME_ENTRY(DBUS_REGWEN_6),
    REG_NAME_ENTRY(DBUS_REGWEN_7),
    REG_NAME_ENTRY(DBUS_REGWEN_8),
    REG_NAME_ENTRY(DBUS_REGWEN_9),
    REG_NAME_ENTRY(DBUS_REGWEN_10),
    REG_NAME_ENTRY(DBUS_REGWEN_11),
    REG_NAME_ENTRY(DBUS_REGWEN_12),
    REG_NAME_ENTRY(DBUS_REGWEN_13),
    REG_NAME_ENTRY(DBUS_REGWEN_14),
    REG_NAME_ENTRY(DBUS_REGWEN_15),
    REG_NAME_ENTRY(DBUS_REGWEN_16),
    REG_NAME_ENTRY(DBUS_REGWEN_17),
    REG_NAME_ENTRY(DBUS_REGWEN_18),
    REG_NAME_ENTRY(DBUS_REGWEN_19),
    REG_NAME_ENTRY(DBUS_REGWEN_20),
    REG_NAME_ENTRY(DBUS_REGWEN_21),
    REG_NAME_ENTRY(DBUS_REGWEN_22),
    REG_NAME_ENTRY(DBUS_REGWEN_23),
    REG_NAME_ENTRY(DBUS_REGWEN_24),
    REG_NAME_ENTRY(DBUS_REGWEN_25),
    REG_NAME_ENTRY(DBUS_REGWEN_26),
    REG_NAME_ENTRY(DBUS_REGWEN_27),
    REG_NAME_ENTRY(DBUS_REGWEN_28),
    REG_NAME_ENTRY(DBUS_REGWEN_29),
    REG_NAME_ENTRY(DBUS_REGWEN_30),
    REG_NAME_ENTRY(DBUS_REGWEN_31),
    REG_NAME_ENTRY(DBUS_ADDR_EN_0),
    REG_NAME_ENTRY(DBUS_ADDR_EN_1),
    REG_NAME_ENTRY(DBUS_ADDR_EN_2),
    REG_NAME_ENTRY(DBUS_ADDR_EN_3),
    REG_NAME_ENTRY(DBUS_ADDR_EN_4),
    REG_NAME_ENTRY(DBUS_ADDR_EN_5),
    REG_NAME_ENTRY(DBUS_ADDR_EN_6),
    REG_NAME_ENTRY(DBUS_ADDR_EN_7),
    REG_NAME_ENTRY(DBUS_ADDR_EN_8),
    REG_NAME_ENTRY(DBUS_ADDR_EN_9),
    REG_NAME_ENTRY(DBUS_ADDR_EN_10),
    REG_NAME_ENTRY(DBUS_ADDR_EN_11),
    REG_NAME_ENTRY(DBUS_ADDR_EN_12),
    REG_NAME_ENTRY(DBUS_ADDR_EN_13),
    REG_NAME_ENTRY(DBUS_ADDR_EN_14),
    REG_NAME_ENTRY(DBUS_ADDR_EN_15),
    REG_NAME_ENTRY(DBUS_ADDR_EN_16),
    REG_NAME_ENTRY(DBUS_ADDR_EN_17),
    REG_NAME_ENTRY(DBUS_ADDR_EN_18),
    REG_NAME_ENTRY(DBUS_ADDR_EN_19),
    REG_NAME_ENTRY(DBUS_ADDR_EN_20),
    REG_NAME_ENTRY(DBUS_ADDR_EN_21),
    REG_NAME_ENTRY(DBUS_ADDR_EN_22),
    REG_NAME_ENTRY(DBUS_ADDR_EN_23),
    REG_NAME_ENTRY(DBUS_ADDR_EN_24),
    REG_NAME_ENTRY(DBUS_ADDR_EN_25),
    REG_NAME_ENTRY(DBUS_ADDR_EN_26),
    REG_NAME_ENTRY(DBUS_ADDR_EN_27),
    REG_NAME_ENTRY(DBUS_ADDR_EN_28),
    REG_NAME_ENTRY(DBUS_ADDR_EN_29),
    REG_NAME_ENTRY(DBUS_ADDR_EN_30),
    REG_NAME_ENTRY(DBUS_ADDR_EN_31),
    REG_NAME_ENTRY(DBUS_ADDR_MATCHING_0),
    REG_NAME_ENTRY(DBUS_ADDR_MATCHING_1),
    REG_NAME_ENTRY(DBUS_ADDR_MATCHING_2),
    REG_NAME_ENTRY(DBUS_ADDR_MATCHING_3),
    REG_NAME_ENTRY(DBUS_ADDR_MATCHING_4),
    REG_NAME_ENTRY(DBUS_ADDR_MATCHING_5),
    REG_NAME_ENTRY(DBUS_ADDR_MATCHING_6),
    REG_NAME_ENTRY(DBUS_ADDR_MATCHING_7),
    REG_NAME_ENTRY(DBUS_ADDR_MATCHING_8),
    REG_NAME_ENTRY(DBUS_ADDR_MATCHING_9),
    REG_NAME_ENTRY(DBUS_ADDR_MATCHING_10),
    REG_NAME_ENTRY(DBUS_ADDR_MATCHING_11),
    REG_NAME_ENTRY(DBUS_ADDR_MATCHING_12),
    REG_NAME_ENTRY(DBUS_ADDR_MATCHING_13),
    REG_NAME_ENTRY(DBUS_ADDR_MATCHING_14),
    REG_NAME_ENTRY(DBUS_ADDR_MATCHING_15),
    REG_NAME_ENTRY(DBUS_ADDR_MATCHING_16),
    REG_NAME_ENTRY(DBUS_ADDR_MATCHING_17),
    REG_NAME_ENTRY(DBUS_ADDR_MATCHING_18),
    REG_NAME_ENTRY(DBUS_ADDR_MATCHING_19),
    REG_NAME_ENTRY(DBUS_ADDR_MATCHING_20),
    REG_NAME_ENTRY(DBUS_ADDR_MATCHING_21),
    REG_NAME_ENTRY(DBUS_ADDR_MATCHING_22),
    REG_NAME_ENTRY(DBUS_ADDR_MATCHING_23),
    REG_NAME_ENTRY(DBUS_ADDR_MATCHING_24),
    REG_NAME_ENTRY(DBUS_ADDR_MATCHING_25),
    REG_NAME_ENTRY(DBUS_ADDR_MATCHING_26),
    REG_NAME_ENTRY(DBUS_ADDR_MATCHING_27),
    REG_NAME_ENTRY(DBUS_ADDR_MATCHING_28),
    REG_NAME_ENTRY(DBUS_ADDR_MATCHING_29),
    REG_NAME_ENTRY(DBUS_ADDR_MATCHING_30),
    REG_NAME_ENTRY(DBUS_ADDR_MATCHING_31),
    REG_NAME_ENTRY(DBUS_REMAP_ADDR_0),
    REG_NAME_ENTRY(DBUS_REMAP_ADDR_1),
    REG_NAME_ENTRY(DBUS_REMAP_ADDR_2),
    REG_NAME_ENTRY(DBUS_REMAP_ADDR_3),
    REG_NAME_ENTRY(DBUS_REMAP_ADDR_4),
    REG_NAME_ENTRY(DBUS_REMAP_ADDR_5),
    REG_NAME_ENTRY(DBUS_REMAP_ADDR_6),
    REG_NAME_ENTRY(DBUS_REMAP_ADDR_7),
    REG_NAME_ENTRY(DBUS_REMAP_ADDR_8),
    REG_NAME_ENTRY(DBUS_REMAP_ADDR_9),
    REG_NAME_ENTRY(DBUS_REMAP_ADDR_10),
    REG_NAME_ENTRY(DBUS_REMAP_ADDR_11),
    REG_NAME_ENTRY(DBUS_REMAP_ADDR_12),
    REG_NAME_ENTRY(DBUS_REMAP_ADDR_13),
    REG_NAME_ENTRY(DBUS_REMAP_ADDR_14),
    REG_NAME_ENTRY(DBUS_REMAP_ADDR_15),
    REG_NAME_ENTRY(DBUS_REMAP_ADDR_16),
    REG_NAME_ENTRY(DBUS_REMAP_ADDR_17),
    REG_NAME_ENTRY(DBUS_REMAP_ADDR_18),
    REG_NAME_ENTRY(DBUS_REMAP_ADDR_19),
    REG_NAME_ENTRY(DBUS_REMAP_ADDR_20),
    REG_NAME_ENTRY(DBUS_REMAP_ADDR_21),
    REG_NAME_ENTRY(DBUS_REMAP_ADDR_22),
    REG_NAME_ENTRY(DBUS_REMAP_ADDR_23),
    REG_NAME_ENTRY(DBUS_REMAP_ADDR_24),
    REG_NAME_ENTRY(DBUS_REMAP_ADDR_25),
    REG_NAME_ENTRY(DBUS_REMAP_ADDR_26),
    REG_NAME_ENTRY(DBUS_REMAP_ADDR_27),
    REG_NAME_ENTRY(DBUS_REMAP_ADDR_28),
    REG_NAME_ENTRY(DBUS_REMAP_ADDR_29),
    REG_NAME_ENTRY(DBUS_REMAP_ADDR_30),
    REG_NAME_ENTRY(DBUS_REMAP_ADDR_31),
    REG_NAME_ENTRY(NMI_ENABLE),
    REG_NAME_ENTRY(NMI_STATE),
    REG_NAME_ENTRY(ERR_STATUS),
    REG_NAME_ENTRY(RND_DATA),
    REG_NAME_ENTRY(RND_STATUS),
    REG_NAME_ENTRY(FPGA_INFO),
};

#define CASE_RANGE(_reg_, _cnt_) (_reg_)...((_reg_) + (_cnt_) - (1u))

#define xtrace_ot_ibex_wrapper_info(_msg_) \
    trace_ot_ibex_wrapper_info(__func__, __LINE__, _msg_)

#define OtIbexWrapperDjState OtIbexWrapperDarjeelingState

struct OtIbexWrapperDarjeelingState {
    SysBusDevice parent_obj;

    MemoryRegion mmio;
    MemoryRegion remappers[PARAM_NUM_REGIONS];

    uint32_t *regs;
    bool entropy_requested;
    bool edn_connected;

    OtEDNState *edn; /* EDN connection is optional */
    uint8_t edn_ep;
};

static void
ot_ibex_wrapper_dj_remapper_destroy(OtIbexWrapperDjState *s, unsigned slot)
{
    g_assert(slot < PARAM_NUM_REGIONS);
    MemoryRegion *mr = &s->remappers[slot];
    if (memory_region_is_mapped(mr)) {
        trace_ot_ibex_wrapper_unmap(slot);
        memory_region_transaction_begin();
        memory_region_set_enabled(mr, false);
        /* QEMU memory model enables unparenting alias regions */
        MemoryRegion *sys_mem = get_system_memory();
        memory_region_del_subregion(sys_mem, mr);
        memory_region_transaction_commit();
    }
}

static void ot_ibex_wrapper_dj_remapper_create(
    OtIbexWrapperDjState *s, unsigned slot, hwaddr dst, hwaddr src, size_t size)
{
    g_assert(slot < PARAM_NUM_REGIONS);
    MemoryRegion *mr = &s->remappers[slot];
    trace_ot_ibex_wrapper_map(slot, src, dst, size);
    g_assert(!memory_region_is_mapped(mr));

    int priority = (int)(PARAM_NUM_REGIONS - slot);

    MemoryRegion *sys_mem = get_system_memory();
    MemoryRegion *mr_dst;

    char *name =
        g_strdup_printf(TYPE_OT_IBEX_WRAPPER_DARJEELING "-remap[%u]", slot);

    memory_region_transaction_begin();
    /*
     * try to map onto the actual device if there's a single one, otherwise
     * map on the whole address space.
     */
    MemoryRegionSection mrs;
    mrs = memory_region_find(sys_mem, dst, (uint64_t)size);
    size_t mrs_lsize = int128_getlo(mrs.size);
    mr_dst = (mrs.mr && mrs_lsize >= size) ? mrs.mr : sys_mem;
    hwaddr offset = dst - mr_dst->addr;
    memory_region_init_alias(mr, OBJECT(s), name, mr_dst, offset,
                             (uint64_t)size);
    memory_region_add_subregion_overlap(sys_mem, src, mr, priority);
    memory_region_set_enabled(mr, true);
    memory_region_transaction_commit();
    g_free(name);

#ifdef PRINT_MTREE
    mtree_info(false, false, false, true);
#endif
}

static void
ot_ibex_wrapper_dj_fill_entropy(void *opaque, uint32_t bits, bool fips)
{
    OtIbexWrapperDjState *s = opaque;

    trace_ot_ibex_wrapper_fill_entropy(bits, fips);

    s->regs[R_RND_DATA] = bits;
    s->regs[R_RND_STATUS] = R_RND_STATUS_RND_DATA_VALID_MASK;
    if (fips) {
        s->regs[R_RND_STATUS] |= R_RND_STATUS_RND_DATA_FIPS_MASK;
    }

    s->entropy_requested = false;
}

static bool ot_ibex_wrapper_dj_has_edn(OtIbexWrapperDjState *s)
{
    return (s->edn != NULL) && (s->edn_ep != UINT8_MAX);
}

static void ot_ibex_wrapper_dj_request_entropy(OtIbexWrapperDjState *s)
{
    if (!s->entropy_requested && ot_ibex_wrapper_dj_has_edn(s)) {
        if (unlikely(!s->edn_connected)) {
            ot_edn_connect_endpoint(s->edn, s->edn_ep,
                                    &ot_ibex_wrapper_dj_fill_entropy, s);
            s->edn_connected = true;
        }
        s->entropy_requested = true;
        trace_ot_ibex_wrapper_request_entropy(s->entropy_requested);
        if (ot_edn_request_entropy(s->edn, s->edn_ep)) {
            s->entropy_requested = false;
            trace_ot_ibex_wrapper_error("failed to request entropy");
        }
    }
}

static void ot_ibex_wrapper_dj_update_remap(OtIbexWrapperDjState *s, bool doi,
                                            unsigned slot)
{
    (void)doi;
    g_assert(slot < PARAM_NUM_REGIONS);
    /*
     * Warning:
     * for now, QEMU is unable to distinguish instruction or data access.
     * in this implementation, we chose to enable remap whenever either D or I
     * remapping is selected, and both D & I configuration match; we disable
     * translation when both D & I are remapping are disabled
     */

    bool en_remap_i = s->regs[R_IBUS_ADDR_EN_0 + slot];
    bool en_remap_d = s->regs[R_DBUS_ADDR_EN_0 + slot];
    if (!en_remap_i && !en_remap_d) {
        /* disable */
        ot_ibex_wrapper_dj_remapper_destroy(s, slot);
    } else {
        uint32_t src_match_i = s->regs[R_IBUS_ADDR_MATCHING_0 + slot];
        uint32_t src_match_d = s->regs[R_DBUS_ADDR_MATCHING_0 + slot];
        if (src_match_i != src_match_d) {
            /* I and D do not match, do nothing */
            xtrace_ot_ibex_wrapper_info("src remapping do not match");
            return;
        }
        uint32_t remap_addr_i = s->regs[R_IBUS_REMAP_ADDR_0 + slot];
        uint32_t remap_addr_d = s->regs[R_DBUS_REMAP_ADDR_0 + slot];
        if (remap_addr_i != remap_addr_d) {
            /* I and D do not match, do nothing */
            xtrace_ot_ibex_wrapper_info("dst remapping do not match");
            return;
        }
        /* enable */
        uint32_t map_size = (-src_match_i & (src_match_i + 1u)) << 1u;
        uint32_t src_base = src_match_i & ~(map_size - 1u);
        uint32_t dst_base = remap_addr_i;

        ot_ibex_wrapper_dj_remapper_destroy(s, slot);
        ot_ibex_wrapper_dj_remapper_create(s, slot, (hwaddr)dst_base,
                                           (hwaddr)src_base, (size_t)map_size);
    }
}

static uint64_t
ot_ibex_wrapper_dj_regs_read(void *opaque, hwaddr addr, unsigned size)
{
    OtIbexWrapperDjState *s = opaque;
    (void)size;
    uint32_t val32;

    hwaddr reg = R32_OFF(addr);

    switch (reg) {
    case R_RND_DATA:
        if (!ot_ibex_wrapper_dj_has_edn(s)) {
            qemu_log_mask(LOG_GUEST_ERROR, "%s: No EDN connection\n", __func__);
            val32 = 0;
            break;
        }
        val32 = s->regs[reg];
        if (!(s->regs[R_RND_STATUS] & R_RND_STATUS_RND_DATA_VALID_MASK)) {
            qemu_log_mask(LOG_GUEST_ERROR,
                          "%s: Read invalid entropy data 0x%08x\n", __func__,
                          val32);
        }
        s->regs[reg] = 0;
        s->regs[R_RND_STATUS] = 0;
        ot_ibex_wrapper_dj_request_entropy(s);
        break;
    case R_RND_STATUS:
        if (!ot_ibex_wrapper_dj_has_edn(s)) {
            qemu_log_mask(LOG_GUEST_ERROR, "%s: No EDN connection\n", __func__);
            val32 = 0;
            break;
        }
        val32 = s->regs[reg];
        if (!(val32 & R_RND_STATUS_RND_DATA_VALID_MASK)) {
            ot_ibex_wrapper_dj_request_entropy(s);
        }
        break;
    default:
        val32 = s->regs[reg];
        break;
    }

    uint64_t pc = ibex_get_current_pc();
    trace_ot_ibex_wrapper_io_read_out((unsigned)addr, REG_NAME(reg), val32, pc);

    return (uint64_t)val32;
};

static void ot_ibex_wrapper_dj_regs_write(void *opaque, hwaddr addr,
                                          uint64_t val64, unsigned size)
{
    OtIbexWrapperDjState *s = opaque;
    (void)size;
    uint32_t val32 = (uint32_t)val64;

    hwaddr reg = R32_OFF(addr);

    uint64_t pc = ibex_get_current_pc();
    trace_ot_ibex_wrapper_io_write((unsigned)addr, REG_NAME(reg), val64, pc);

    switch (reg) {
    case R_SW_FATAL_ERR:
        if ((val32 >> 16u) == 0xC0DEu) {
            /* discard MSB magic */
            val32 &= UINT16_MAX;
            /* discard multibool4false mark */
            val32 >>= 4u;
            /* std exit code should be in [0..127] range */
            if (val32 > 127u) {
                val32 = 127u;
            }
            exit((int)val32);
        }
        break;
    case CASE_RANGE(R_IBUS_REGWEN_0, PARAM_NUM_REGIONS):
    case CASE_RANGE(R_DBUS_REGWEN_0, PARAM_NUM_REGIONS):
        val32 &= REGWEN_EN_MASK;
        s->regs[reg] &= val32; /* RW0C */
        break;
    case CASE_RANGE(R_IBUS_ADDR_EN_0, PARAM_NUM_REGIONS):
        if (s->regs[reg - R_IBUS_ADDR_EN_0 + R_IBUS_REGWEN_0]) {
            s->regs[reg] = val32;
        }
        ot_ibex_wrapper_dj_update_remap(s, false, reg - R_IBUS_ADDR_EN_0);
        break;
    case CASE_RANGE(R_IBUS_ADDR_MATCHING_0, PARAM_NUM_REGIONS):
        if (s->regs[reg - R_IBUS_ADDR_MATCHING_0 + R_IBUS_REGWEN_0]) {
            s->regs[reg] = val32;
        }
        break;
    case CASE_RANGE(R_IBUS_REMAP_ADDR_0, PARAM_NUM_REGIONS):
        if (s->regs[reg - R_IBUS_REMAP_ADDR_0 + R_IBUS_REGWEN_0]) {
            s->regs[reg] = val32;
        }
        ot_ibex_wrapper_dj_update_remap(s, false, reg - R_IBUS_REMAP_ADDR_0);
        break;
    case CASE_RANGE(R_DBUS_ADDR_EN_0, PARAM_NUM_REGIONS):
        if (s->regs[reg - R_DBUS_ADDR_EN_0 + R_DBUS_REGWEN_0]) {
            s->regs[reg] = val32;
        }
        ot_ibex_wrapper_dj_update_remap(s, true, reg - R_DBUS_ADDR_EN_0);
        break;
    case CASE_RANGE(R_DBUS_ADDR_MATCHING_0, PARAM_NUM_REGIONS):
        if (s->regs[reg - R_DBUS_ADDR_MATCHING_0 + R_DBUS_REGWEN_0]) {
            s->regs[reg] = val32;
        }
        break;
    case CASE_RANGE(R_DBUS_REMAP_ADDR_0, PARAM_NUM_REGIONS):
        if (s->regs[reg - R_DBUS_REMAP_ADDR_0 + R_DBUS_REGWEN_0]) {
            s->regs[reg] = val32;
        }
        ot_ibex_wrapper_dj_update_remap(s, true, reg - R_DBUS_REMAP_ADDR_0);
        break;
    default:
        s->regs[reg] = val32;
        break;
    }
};

static Property ot_ibex_wrapper_dj_properties[] = {
    DEFINE_PROP_LINK("edn", OtIbexWrapperDjState, edn, TYPE_OT_EDN,
                     OtEDNState *),
    DEFINE_PROP_UINT8("edn-ep", OtIbexWrapperDjState, edn_ep, UINT8_MAX),
    DEFINE_PROP_END_OF_LIST(),
};

static const MemoryRegionOps ot_ibex_wrapper_dj_regs_ops = {
    .read = &ot_ibex_wrapper_dj_regs_read,
    .write = &ot_ibex_wrapper_dj_regs_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .impl.min_access_size = 4u,
    .impl.max_access_size = 4u,
};

static void ot_ibex_wrapper_dj_reset(DeviceState *dev)
{
    OtIbexWrapperDjState *s = OT_IBEX_WRAPPER_DARJEELING(dev);

    for (unsigned slot = 0; slot < PARAM_NUM_REGIONS; slot++) {
        ot_ibex_wrapper_dj_remapper_destroy(s, slot);
    }

    memset(s->regs, 0, REGS_SIZE);
    s->regs[R_SW_RECOV_ERR] = 0x9u;
    s->regs[R_SW_FATAL_ERR] = 0x9u;
    for (unsigned ix = 0; ix < PARAM_NUM_REGIONS; ix++) {
        s->regs[R_IBUS_REGWEN_0 + ix] = 0x1u;
        s->regs[R_DBUS_REGWEN_0 + ix] = 0x1u;
    }
    s->regs[R_FPGA_INFO] = 0x554d4551u; /* 'QEMU' in LE */
    s->entropy_requested = false;
}

static void ot_ibex_wrapper_dj_init(Object *obj)
{
    OtIbexWrapperDjState *s = OT_IBEX_WRAPPER_DARJEELING(obj);

    memory_region_init_io(&s->mmio, obj, &ot_ibex_wrapper_dj_regs_ops, s,
                          TYPE_OT_IBEX_WRAPPER_DARJEELING, REGS_SIZE);
    sysbus_init_mmio(SYS_BUS_DEVICE(s), &s->mmio);

    s->regs = g_new0(uint32_t, REGS_COUNT);
}

static void ot_ibex_wrapper_dj_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    (void)data;

    dc->reset = &ot_ibex_wrapper_dj_reset;
    device_class_set_props(dc, ot_ibex_wrapper_dj_properties);
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
}

static const TypeInfo ot_ibex_wrapper_dj_info = {
    .name = TYPE_OT_IBEX_WRAPPER_DARJEELING,
    .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(OtIbexWrapperDjState),
    .instance_init = &ot_ibex_wrapper_dj_init,
    .class_size = sizeof(OtIbexWrapperStateClass),
    .class_init = &ot_ibex_wrapper_dj_class_init,
};

static void ot_ibex_wrapper_dj_register_types(void)
{
    type_register_static(&ot_ibex_wrapper_dj_info);
}

type_init(ot_ibex_wrapper_dj_register_types)
