/*-----------------------------------------------------------------------------
 * atemsys.h
 * Copyright (c) 2009 - 2024 acontis technologies GmbH, Weingarten, Germany
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
 *
 *  NOTE! This copyright does *not* cover user programs that use kernel
 * services by normal system calls - this is merely considered normal use
 * of the kernel, and does *not* fall under the heading of "derived work".
 * Also note that the GPL below is copyrighted by the Free Software
 * Foundation, but the instance of code that it refers to (the Linux
 * kernel) is copyrighted by me and others who actually wrote it.
 *
 * Also note that the only valid version of the GPL as far as the kernel
 * is concerned is _this_ particular version of the license (ie v2, not
 * v2.2 or v3.x or whatever), unless explicitly otherwise stated.
 *
 * This program is free software; you can redistribute  it and/or modify it
 * under  the terms of  the GNU General  Public License as published by the
 * Free Software Foundation;  either version 2 of the  License, or (at your
 * option) any later version.
 *
 * Response                  Paul Bussmann
 * Description               atemsys.ko headerfile
 * Note: This header is also the user space API (uapi) header file
 *  Changes:
 *
 *  V1.0.00 - Inital, PCI/PCIe only.
 *  V1.1.00 - PowerPC tweaks.
 *            Support for SoC devices (no PCI, i.e. Freescale eTSEC).
 *            Support for current linux kernel's (3.0). Removed deprecated code.
 *  V1.2.00 - 64 bit support. Compat IOCTL's for 32-Bit usermode apps.
 *  V1.2.01 - request_irq() sometimes failed -> Map irq to virq under powerpc.
 *  V1.2.02 - Support for current Linux kernel (3.8.0)
 *  V1.2.03 - Support for current Linux kernel (3.8.13) on armv7l (beaglebone)
 *  V1.2.04 - Use dma_alloc_coherent for arm, because of DMA memory corruption on
 *            Xilinx Zynq.
 *  V1.2.05 - OF Device Tree support for Xilinx Zynq (VIRQ mapping)
 *  V1.2.06 - Wrong major version.
 *  V1.2.07 - Tolerate closing, e.g. due to system()-calls.
 *  V1.2.08 - Add VM_DONTCOPY to prevent crash on system()-calls
 *  V1.2.09 - Apply second controller name change in dts (standard GEM driver for Xilinx Zynq) to avoid default driver loading.
 *  V1.2.10 - Removed IO address alignment to support R6040
 *  V1.2.11 - Fix lockup in device_read (tLinkOsIst if NIC in interrupt mode) on dev_int_disconnect
 *  V1.2.12 - Fix underflow in dev_disable_irq() when more than one interrupts pending because of disable_irq_nosync usage
 *  V1.2.13 - Fix usage of x64 PCI physical addresses
 *  V1.2.14 - Changes for using with kernel beginnig from 2.6.18
 *  V1.2.15 - Add udev auto-loading support via DTB
 *  V1.2.16 - Add interrupt mode support for Xenomai 3 (Cobalt)
 *  V1.3.01 - Add IOCTL_MOD_GETVERSION
 *  V1.3.02 - Add support for kernel >= 4.11.00
 *  V1.3.03 - Fix IOCTL_MOD_GETVERSION
 *  V1.3.04 - Fix interrupt deadlock in Xenomai 2
 *  V1.3.05 - Use correct PCI domain
 *  V1.3.06 - Use rtdm_printk for Cobalt, add check if dev_int_disconnect was successful
 *  V1.3.07 - Remove IOCTL_PCI_RELEASE_DEVICE warnings due to untracked IOCTL_PCI_CONF_DEVICE
 *  V1.3.08 - Add support for kernel >= 4.13.00
 *  V1.3.09 - Add support for PRU ICSS in Device Tree
 *  V1.3.10 - Fix compilation on Ubuntu 18.04, Kernel 4.9.90, Xenomai 3.0.6 x64 Cobalt
 *  V1.3.11 - Add enable access to ARM cycle count register(CCNT)
 *  V1.3.12 - Add atemsys API version selection
 *  V1.3.13 - Add ARM64 support
 *  V1.3.14 - Fix edge type interrupt (enabled if Kernel >= 3.4.1, because exported irq_to_desc needed)
 *            Fix Xenomai Cobalt interrupt mode
 *  V1.3.15 - Fix crash while loading kernel module on ARM64
 *            Add support for kernel >= 5.0.00
 *  V1.3.16 - Handle API changes at kernel >= 4.18.00
 *            Fix ARM DMA allocation for PCIe
 *  V1.4.01 - Register atemsys as Device Tree Ethernet driver "atemsys"
 *            and use Linux PHY and Mdio-Bus Handling
 *  V1.4.02 - Device Tree Ethernet driver improved robustness for unbind linux driver
 *            Fix for kernel >= 5.0.00  with device tree,
 *            Fix ARM/AARCH64 DMA configuration for PCIe and
 *            Fix occasional insmod Kernel Oops
 *  V1.4.03 - Add log level (insmod atemsys loglevel=6) analog to kernel log level
 *  V1.4.04 - Fix Device Tree Ethernet driver robustness
 *            Add Device Tree Ethernet driver support for ICSS
 *  V1.4.05 - Add IOMMU/Vt-D support
 *  V1.4.06 - Fix IOMMU/Vt-D support for ARM
 *            Fix Mdio-Bus timeout for kernel >= 5.0.00
 *  V1.4.07 - Add support for imx8 / FslFec 64bit
 *  V1.4.08 - Fix Xilinx Ultrascale
 *            Fix cleanup of Device Tree Ethernet driver
 *  V1.4.09 - Add atemsys as PCI driver for Intel, Realtek and Beckhoff
 *            Add memory allocation and mapping on platform / PCI driver device
 *            Fix PHY driver for FslFec 64Bit
 *  V1.4.10 - Fix Device Tree Ethernet driver: Mdio/Phy sup-node, test 4.6.x kernel
 *            Add Device Tree Ethernet driver support for GEM
 *            Fix PCI driver: force DMA to 32 bit
 *  V1.4.11 - Fix for kernel >= 5.5.00  with device tree,
 *            Fix Device Tree Ethernet driver support for DW3504
 *            Fix PCI driver: only for kernel >= 4.4.00
 *  V1.4.12 - Fix for kernel >= 5.11.00,
 *            Add support for 64Bit IO Memory of PCI card
 *  V1.4.13 - Fix for kernel <= 3.16.00,
 *            Add HAVE_ACCESS_OK_TYPE define to handle non-mainstream API variance
 *            Connect to interrupt via binded device tree - platform device
 *  V1.4.14 - Fix for arm/aarch64 kernel >= 5.10.00,
 *            Add support for 64Bit DMA Memory
 *            Add support for PCI DMA address translation
 *  V1.4.15 - Fix API version IO Controls
 *  V1.4.16 - Fix Xenomai3 on arm,
 *            Add support for Device Tree Ethernet driver and PCI driver with Xenomai3
 *            Fix PCI DMA address translation on arm
 *  V1.4.17 - Fix dma_set_mask_and_coherent() missing in kernels under 3.12.55
 *  V1.4.18 - Remove obsolete ARM cycle count register(CCNT)
 *            Fix PCI driver do registration for all Ethernet network adapters
 *            Add modul parameter AllowedPciDevices to adjust PCI driver, AllowedPciDevices="" will turn off PCI driver,
 *            (insmod atemsys AllowedPciDevices="0000:01:00.0;0000:02:00.0")
 *  V1.4.19 - Fix Xenomai2 ARMv8 32Bit
 *  V1.4.20 - Fix support for CMA for kernel > 4.9.00
 *  V1.4.21 - Add Device Tree Ethernet driver support for CPSW
 *            Add Device Tree Ethernet driver phy reset
 *            Fix Device Tree Ethernet on Xenomai3
 *            Add HAVE_IRQ_TO_DESC define to handle non-mainstream API variance
 *  V1.4.22 - Fix Build Warnings
 *            Fix kernel config depending irq structures
 *            Fix kernel version 4.12 to 4.15 for handle of dma_coherent bit
 *            Add IOMMU support, new mapping to userspace active and tested for kernel > 5.4,
 *             use old mapping with ATEMSYS_LEGACY_DMA=1 define or
 *             activate new mapping with ATEMSYS_LEGACY_DMA=0 define for older kernel
 *  V1.4.23 - Fix PCI bars
 *  V1.4.24 - Add Device Tree Ethernet driver support for STM32mp135
 *  V1.4.25 - Add IOCTL_INT_CPU_AFFINITY
 *            Add Device Tree Ethernet driver support for RockChip
 *  V1.4.26 - Fix for arm/aarch64 kernel >= 6.00.00,
 *            Fix version of_dma_configure
 *            Add ATEMSYS_IOCTL_IOMEM_CMD for Kernel mode access to protected registers
 *            Add ATEMSYS_IOCTL_CPSWG_CMD to configure K3_UDMA_CPSWG Channels, Flows and Rings
 *  V1.4.27 - Fix ATEMSYS_IOCTL_CPSWG_CMD kernel version,
 *            Add Device Tree Ethernet driver support for CPSWG
 *  V1.4.28 - Fix for PCIe compatibility with Atemsys before V1.3.5,
 *            Fix for Kernel > 6.05.00
 *  V1.4.29 - Add support for TI AM64 CPSWG
 *            Fix PCI dma_coherent bit handling for Kernel between 4.15.0 and 5.4.0
 *  V1.4.30 - Fix for Kernel > 6.4.00
 *            Fix for systems without 32-bit DMA
 *  V1.4.31 - Add license for user space API
 *  V1.4.32 - Add support for dsa driver with Device Tree (insmod atemsys bRegisterDtbNetDevice=1)
 *            Fix Device Tree support for Kernel > 6.1.00
 *            Add support for TI AM64 CPSWG Second Port
 *  V1.4.33 - Fix integration in Kernel >= 6.11.00 on arm/aarch64
              Fix ATEMSYS_IOCTL_INT_SET_CPU_AFFINITY using irq_force_affinity()
 *  V1.4.34 - Fix for platform devices without 32-bit DMA
 *            Add Device Tree Ethernet driver support for Raspberry Pi 5
 *            Fix non-PCI IO Memory for PCI devices
 *  V1.4.35 - Add driver initialization entry point for Kernel >= 6.6.00
 *            Fix Xenomai 3.3
 *            Fix CPSWG for Kernel >= 6.12
 *            Add RiscV support
 *            Fix PCI IO memory resource management Kernel >= 6.0.00
 *  V1.4.36 - Fix PCI MSI interrupt broken since V1.4.35 for Kernel >= 6.0.00
 *  atemsys is shared across EC-Master V2.7+

 *----------------------------------------------------------------------------*/

#ifndef ATEMSYS_H
#define ATEMSYS_H

#include <linux/ioctl.h>
#include <linux/types.h>

#ifndef EC_ATEMSYSVERSION
#define EC_ATEMSYSVERSION(a,b,c) (((a)<<2*8)+((b)<<1*8)+((c)<<0*8))
#endif

#define ATEMSYS_VERSION_STR "1.4.36"
#define ATEMSYS_VERSION_NUM  1,4,36
#if (defined ATEMSYS_C)
#define USE_ATEMSYS_API_VERSION EC_ATEMSYSVERSION(1,4,36)
#endif

/* support selection */

#if   (USE_ATEMSYS_API_VERSION < EC_ATEMSYSVERSION(1,3,5)) || (!defined USE_ATEMSYS_API_VERSION)
/* till v1.3.04 */
#define ATEMSYS_T_PCI_SELECT_DESC               ATEMSYS_T_PCI_SELECT_DESC_v1_0_00
#define ATEMSYS_T_PCI_MEMBAR                    ATEMSYS_T_PCI_MEMBAR_v1_0_00
#define ATEMSYS_IOCTL_PCI_FIND_DEVICE           ATEMSYS_IOCTL_PCI_FIND_DEVICE_v1_0_00
#define ATEMSYS_IOCTL_PCI_CONF_DEVICE           ATEMSYS_IOCTL_PCI_CONF_DEVICE_v1_0_00

#elif (USE_ATEMSYS_API_VERSION < EC_ATEMSYSVERSION(1,4,12))
/* v1.3.05 till v1.4.11 */
#define ATEMSYS_T_PCI_SELECT_DESC               ATEMSYS_T_PCI_SELECT_DESC_v1_3_05
#define ATEMSYS_T_PCI_MEMBAR                    ATEMSYS_T_PCI_MEMBAR_v1_3_05
#define ATEMSYS_IOCTL_PCI_FIND_DEVICE           ATEMSYS_IOCTL_PCI_FIND_DEVICE_v1_3_05
#define ATEMSYS_IOCTL_PCI_CONF_DEVICE           ATEMSYS_IOCTL_PCI_CONF_DEVICE_v1_3_05

#else /* v1.4.12 and later */
#define ATEMSYS_T_PCI_SELECT_DESC               ATEMSYS_T_PCI_SELECT_DESC_v1_4_12
#define ATEMSYS_T_PCI_MEMBAR                    ATEMSYS_T_PCI_MEMBAR_v1_4_12
#define ATEMSYS_IOCTL_PCI_FIND_DEVICE           ATEMSYS_IOCTL_PCI_FIND_DEVICE_v1_4_12
#define ATEMSYS_IOCTL_PCI_CONF_DEVICE           ATEMSYS_IOCTL_PCI_CONF_DEVICE_v1_4_12
#endif

#define DRIVER_SUCCESS  0

/*
 * The major device number. We can't rely on dynamic
 * registration any more, because ioctls need to know
 * it.
 */
#define MAJOR_NUM 101

#define ATEMSYS_IOCTL_PCI_RELEASE_DEVICE        _IO(MAJOR_NUM,    2)
#define ATEMSYS_IOCTL_INT_CONNECT               _IOW(MAJOR_NUM,   3, __u32)
#define ATEMSYS_IOCTL_INT_DISCONNECT            _IOW(MAJOR_NUM,   4, __u32)
#define ATEMSYS_IOCTL_INT_INFO                  _IOR(MAJOR_NUM,   5, ATEMSYS_T_INT_INFO)
#define ATEMSYS_IOCTL_MOD_GETVERSION            _IOR(MAJOR_NUM,   6, __u32)
#define ATEMSYS_IOCTL_CPU_ENABLE_CYCLE_COUNT    _IOW(MAJOR_NUM,   7, __u32)
#define ATEMSYS_IOCTL_GET_MAC_INFO              _IOWR(MAJOR_NUM,  8, ATEMSYS_T_MAC_INFO)
#define ATEMSYS_IOCTL_PHY_START_STOP            _IOWR(MAJOR_NUM,  9, ATEMSYS_T_PHY_START_STOP_INFO)
#define ATEMSYS_IOCTL_GET_MDIO_ORDER            _IOWR(MAJOR_NUM, 10, ATEMSYS_T_MDIO_ORDER)
#define ATEMSYS_IOCTL_RETURN_MDIO_ORDER         _IOWR(MAJOR_NUM, 11, ATEMSYS_T_MDIO_ORDER)
#define ATEMSYS_IOCTL_GET_PHY_INFO              _IOWR(MAJOR_NUM, 12, ATEMSYS_T_PHY_INFO)
#define ATEMSYS_IOCTL_MOD_SET_API_VERSION       _IOR(MAJOR_NUM,  13, __u32)
#define ATEMSYS_IOCTL_PHY_RESET                 _IOWR(MAJOR_NUM, 14, __u32)
#define ATEMSYS_IOCTL_INT_SET_CPU_AFFINITY      _IOWR(MAJOR_NUM, 15, __u32)
#define ATEMSYS_IOCTL_IOMEM_CMD                 _IOWR(MAJOR_NUM, 16, ATEMSYS_T_IOMEM_CMD)
#define ATEMSYS_IOCTL_CPSWG_CMD                 _IOWR(MAJOR_NUM, 17, ATEMSYS_T_CPSWG_CMD)

/* support legacy source code */
#define IOCTL_PCI_FIND_DEVICE           ATEMSYS_IOCTL_PCI_FIND_DEVICE
#define IOCTL_PCI_CONF_DEVICE           ATEMSYS_IOCTL_PCI_CONF_DEVICE
#define IOCTL_PCI_RELEASE_DEVICE        ATEMSYS_IOCTL_PCI_RELEASE_DEVICE
#define IOCTL_INT_CONNECT               ATEMSYS_IOCTL_INT_CONNECT
#define IOCTL_INT_DISCONNECT            ATEMSYS_IOCTL_INT_DISCONNECT
#define IOCTL_INT_INFO                  ATEMSYS_IOCTL_INT_INFO
#define IOCTL_MOD_GETVERSION            ATEMSYS_IOCTL_MOD_GETVERSION
#define IOCTL_CPU_ENABLE_CYCLE_COUNT    ATEMSYS_IOCTL_CPU_ENABLE_CYCLE_COUNT
#define IOCTL_PCI_FIND_DEVICE_v1_3_04   ATEMSYS_IOCTL_PCI_FIND_DEVICE_v1_3_04
#define IOCTL_PCI_CONF_DEVICE_v1_3_04   ATEMSYS_IOCTL_PCI_CONF_DEVICE_v1_3_04
#define USE_PCI_INT                     ATEMSYS_USE_PCI_INT
#define INT_INFO                        ATEMSYS_T_INT_INFO
#define PCI_SELECT_DESC                 ATEMSYS_T_PCI_SELECT_DESC


/*
 * The name of the device driver
 */
#define ATEMSYS_DEVICE_NAME "atemsys"

/* CONFIG_XENO_COBALT/CONFIG_XENO_MERCURY defined in xeno_config.h (may not be available when building atemsys.ko) */
#if (!defined CONFIG_XENO_COBALT) && (!defined CONFIG_XENO_MERCURY) && (defined CONFIG_XENO_VERSION_MAJOR) && (CONFIG_XENO_VERSION_MAJOR >= 3)
#define CONFIG_XENO_COBALT
#endif

/*
 * The name of the device file
 */
#ifdef CONFIG_XENO_COBALT
#define ATEMSYS_FILE_NAME "/dev/rtdm/" ATEMSYS_DEVICE_NAME
#else
#define ATEMSYS_FILE_NAME "/dev/" ATEMSYS_DEVICE_NAME
#endif /* CONFIG_XENO_COBALT */

#define ATEMSYS_PCI_MAXBAR (6)
#define ATEMSYS_USE_PCI_INT (0xFFFFFFFF) /* Query the selected PCI device for the assigned IRQ number */

typedef struct
{
    __u32       dwInterrupt;
} __attribute__((packed)) ATEMSYS_T_INT_INFO;


/* v1_4_12 */

#define ATEMSYS_IOCTL_PCI_FIND_DEVICE_v1_4_12   _IOWR(MAJOR_NUM,  0, ATEMSYS_T_PCI_SELECT_DESC_v1_4_12)
#define ATEMSYS_IOCTL_PCI_CONF_DEVICE_v1_4_12   _IOWR(MAJOR_NUM,  1, ATEMSYS_T_PCI_SELECT_DESC_v1_4_12)

typedef struct
{
    __u64       qwIOMem;          /* [out] IO Memory of PCI card (physical address) */
    __u32       dwIOLen;          /* [out] Length of the IO Memory area*/
} __attribute__((packed)) ATEMSYS_T_PCI_MEMBAR_v1_4_12;

typedef struct
{
    __s32       nVendID;          /* [in] vendor ID */
    __s32       nDevID;           /* [in] device ID */
    __s32       nInstance;        /* [in] instance to look for (0 is the first instance) */
    __s32       nPciBus;          /* [in/out] bus */
    __s32       nPciDev;          /* [in/out] device */
    __s32       nPciFun;          /* [in/out] function */
    __s32       nBarCnt;          /* [out] Number of entries in aBar */
    __u32       dwIrq;            /* [out] IRQ or USE_PCI_INT */
    ATEMSYS_T_PCI_MEMBAR_v1_4_12  aBar[ATEMSYS_PCI_MAXBAR]; /* [out] IO memory */
    __s32       nPciDomain;       /* [in/out] domain */
} __attribute__((packed)) ATEMSYS_T_PCI_SELECT_DESC_v1_4_12;


/* v1_3_05 */

#define ATEMSYS_IOCTL_PCI_FIND_DEVICE_v1_3_05   _IOWR(MAJOR_NUM,  0, ATEMSYS_T_PCI_SELECT_DESC_v1_3_05)
#define ATEMSYS_IOCTL_PCI_CONF_DEVICE_v1_3_05   _IOWR(MAJOR_NUM,  1, ATEMSYS_T_PCI_SELECT_DESC_v1_3_05)

typedef struct
{
    __u32       dwIOMem;          /* [out] IO Memory of PCI card (physical address) */
    __u32       dwIOLen;          /* [out] Length of the IO Memory area*/
} __attribute__((packed)) ATEMSYS_T_PCI_MEMBAR_v1_3_05;

typedef struct
{
    __s32       nVendID;          /* [in] vendor ID */
    __s32       nDevID;           /* [in] device ID */
    __s32       nInstance;        /* [in] instance to look for (0 is the first instance) */
    __s32       nPciBus;          /* [in/out] bus */
    __s32       nPciDev;          /* [in/out] device */
    __s32       nPciFun;          /* [in/out] function */
    __s32       nBarCnt;          /* [out] Number of entries in aBar */
    __u32       dwIrq;            /* [out] IRQ or USE_PCI_INT */
    ATEMSYS_T_PCI_MEMBAR_v1_3_05  aBar[ATEMSYS_PCI_MAXBAR]; /* [out] IO memory */
    __s32       nPciDomain;       /* [in/out] domain */
} __attribute__((packed)) ATEMSYS_T_PCI_SELECT_DESC_v1_3_05;


/* v1_0_00 */

#define ATEMSYS_IOCTL_PCI_FIND_DEVICE_v1_3_04   ATEMSYS_IOCTL_PCI_FIND_DEVICE_v1_0_00
#define ATEMSYS_IOCTL_PCI_CONF_DEVICE_v1_3_04   ATEMSYS_IOCTL_PCI_CONF_DEVICE_v1_0_00

#define ATEMSYS_IOCTL_PCI_FIND_DEVICE_v1_0_00   _IOWR(MAJOR_NUM, 0, ATEMSYS_T_PCI_SELECT_DESC_v1_0_00)
#define ATEMSYS_IOCTL_PCI_CONF_DEVICE_v1_0_00   _IOWR(MAJOR_NUM, 1, ATEMSYS_T_PCI_SELECT_DESC_v1_0_00)

typedef struct
{
    __u32       dwIOMem;          /* [out] IO Memory of PCI card (physical address) */
    __u32       dwIOLen;          /* [out] Length of the IO Memory area*/
} __attribute__((packed)) ATEMSYS_T_PCI_MEMBAR_v1_0_00;

typedef struct
{
    __s32       nVendID;          /* [in] vendor ID */
    __s32       nDevID;           /* [in] device ID */
    __s32       nInstance;        /* [in] instance to look for (0 is the first instance) */
    __s32       nPciBus;          /* [in/out] bus */
    __s32       nPciDev;          /* [in/out] device */
    __s32       nPciFun;          /* [in/out] function */
    __s32       nBarCnt;          /* [out] Number of entries in aBar */
    __u32       dwIrq;            /* [out] IRQ or USE_PCI_INT */
    ATEMSYS_T_PCI_MEMBAR_v1_0_00   aBar[ATEMSYS_PCI_MAXBAR]; /* [out] IO memory */
} __attribute__((packed)) ATEMSYS_T_PCI_SELECT_DESC_v1_0_00;

/* must match EC_T_PHYINTERFACE in EcLink.h */
typedef enum _EC_T_PHYINTERFACE_ATEMSYS
{
    eATEMSYS_PHY_FIXED_LINK = 1 << 0,
    eATEMSYS_PHY_MII        = 1 << 1,
    eATEMSYS_PHY_RMII       = 1 << 2,
    eATEMSYS_PHY_GMII       = 1 << 3,
    eATEMSYS_PHY_SGMII      = 1 << 4,
    eATEMSYS_PHY_RGMII      = 1 << 5,
    eATEMSYS_PHY_OSDRIVER   = 1 << 6,

    /* Borland C++ datatype alignment correction */
    eATEMSYS_PHY_BCppDummy  = 0xFFFFFFFF
} ATEMSYS_T_PHYINTERFACE;


#define EC_LINKOS_IDENT_MAX_LEN            0x20  /* must match EcLink.h */
#define PHY_AUTO_ADDR                (__u32) -1  /* must match EcPhy.h */
typedef struct
{
    char                        szIdent[EC_LINKOS_IDENT_MAX_LEN];   /* [out]    Name of Mac e.g. "FslFec" */
    __u32                       dwInstance;                         /* [out]    Number of used Mac (in official order!) */
    __u32                       dwIndex;                            /* [in]     Index of Mac in atemsys handling */
    __u64                       qwRegAddr;                          /* [in]     Hardware register address of mac */
    __u32                       dwRegSize;                          /* [in]     Hardware register size of mac */
    __u32                       dwStatus;                           /* [in]     Status of mac according to device tree */
    ATEMSYS_T_PHYINTERFACE      ePhyMode;                           /* [in]     Phy mac connection mode mii, rmii, rgmii, gmii, sgmii defined in SDK/INC/EcLink.h */
    __u32                       bNoMdioBus;                         /* [in]     Mac don't need to run own Mdio Bus */
    __u32                       dwPhyAddr;                          /* [in]     Address of PHY on mdio bus */
    __u32                       dwErrorCode;                        /* [in]     Error code defined in SDK/INC/EcError.h */
    __u32                       bPhyResetSupported;                 /* [in]    Device tree has data for phy reset */
    __u32                       dwReserved[15];
} __attribute__((packed)) ATEMSYS_T_MAC_INFO;

typedef struct
{
    __u32                       dwIndex;                            /* [out]    Index of Mac in atemsys handling */
    __u32                       bInUse;                             /* [in]     Descriptor is in use */
    __u32                       bInUseByIoctl;                      /* [in]     Descriptor is in use by ATEMSYS_IOCTRLs */
    __u32                       bWriteOrder;                        /* [in/out] Mdio operation - write = 1, read = 0 */
    __u16                       wMdioAddr;                          /* [in/out] Current address */
    __u16                       wReg;                               /* [in/out] Current register */
    __u16                       wValue;                             /* [in/out] Current value read or write */
    __u32                       dwTimeoutMsec;                      /* [in]     Timeout in milli seconds */
    __u32                       dwErrorCode;                        /* [in]     Error code defined in SDK/INC/EcError.h */
    __u32                       dwReserved[4];
} __attribute__((packed)) ATEMSYS_T_MDIO_ORDER;

typedef struct
{
    __u32                       dwIndex;                            /* [out]    Index of Mac in atemsys handling */
    __u32                       dwLink;                             /* [in]     Link defined in /linux/phy.h */
    __u32                       dwDuplex;                           /* [in]     Duplex defined in /linux/phy.h (0x00: half, 0x01: full, 0xFF: unknown) */
    __u32                       dwSpeed;                            /* [in]     Speed defined in /linux/phy.h */
    __u32                       bPhyReady;                          /* [in]     Mdio Bus is currently not active */
    __u32                       dwErrorCode;                        /* [in]     Error code defined in SDK/INC/EcError.h */
    __u32                       dwReserved[4];
} __attribute__((packed)) ATEMSYS_T_PHY_INFO;

typedef struct
{
    __u32                       dwIndex;                            /* [out]    Index of Mac in atemsys handling */
    __u32                       bStart;                             /* [out]    Start = 1, stop = 0 */
    __u32                       dwErrorCode;                        /* [in]     Error code defined in SDK/INC/EcError.h */
    __u32                       dwReserved[4];
} __attribute__((packed)) ATEMSYS_T_PHY_START_STOP_INFO;




typedef struct
{
    __u32                       dwIndex;                            /* [out]    Index of Mac in atemsys handling */
    __u32                       dwCmd;                              /* [out]    Id of the command */
#define ATEMSYS_IOMEM_CMD_MAP_PERMANENT   1
#define ATEMSYS_IOMEM_CMD_UNMAP_PERMANENT 2
#define ATEMSYS_IOMEM_CMD_READ            3
#define ATEMSYS_IOMEM_CMD_WRITE           4

    __u64                       qwPhys;                             /* [out]    physical memory address */
    __u32                       dwSize;                             /* [out]    size of the memory area */
    __u32                       dwOffset;                           /* [out]    memory offset for read and write command */
    __u32                       dwDataSize;                         /* [out]    data size for read and write command */
    __u32                       dwData[4];                          /* [in/out] data buffer for read and write command */
} __attribute__((packed)) ATEMSYS_T_IOMEM_CMD;


typedef struct
{
    __u32                       dwIndex;                            /* [out]    Index of Mac in atemsys handling */
    __u32                       dwChannelIdx;                       /* [out]    Index of the internal channel handling */
    __u32                       dwCmd;                              /* [out]    Id of the command */
#define ATEMSYS_CPSWG_CMD_CONFIG_TX  1
#define ATEMSYS_CPSWG_CMD_CONFIG_RX  2
#define ATEMSYS_CPSWG_CMD_ENABLE_TX  3
#define ATEMSYS_CPSWG_CMD_ENABLE_RX  4
#define ATEMSYS_CPSWG_CMD_DISABLE_TX 5
#define ATEMSYS_CPSWG_CMD_DISABLE_RX 6
#define ATEMSYS_CPSWG_CMD_RELEASE_TX 7
#define ATEMSYS_CPSWG_CMD_RELEASE_RX 8

    __u64                       qwRingDma;                          /* [in]     1. ring physical memory address */
    __u32                       dwRingSize;                         /* [in/out] 1. ring size / number of elements */
    __u32                       dwRingId;                           /* [in]     1. ring index */
    __u64                       qwRingFdqDma;                       /* [in]     2. ring physical memory address */
    __u32                       dwRingFdqSize;                      /* [in/put] 2. ring size / number of elements */
    __u32                       dwRingFdqId;                        /* [in]     2. ring index */
    __u32                       dwChanId;                           /* [in]     Channel index */
    __u32                       dwFlowIdBase;                       /* [in]     Flow index */
    __u32                       bRingFdqUsingRingMode;              /* [in/out] RingMode of RingFdq set to RING_MODE_RING */
    __u32                       dwReserved[31];
} __attribute__((packed)) ATEMSYS_T_CPSWG_CMD;

#endif  /* ATEMSYS_H */

