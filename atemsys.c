/*-----------------------------------------------------------------------------
 * atemsys.c
 * Copyright (c) 2009 - 2020 acontis technologies GmbH, Ravensburg, Germany
 * All rights reserved.
 *
 * This program is free software; you can redistribute  it and/or modify it
 * under  the terms of  the GNU General  Public License as published by the
 * Free Software Foundation;  either version 2 of the  License, or (at your
 * option) any later version.
 *
 * Response                  Paul Bussmann
 * Description               Provides usermode access to:
 *   - PCI configuration space
 *   - Device IO memory
 *   - Contiguous DMA memory
 *   - Single device interrupt
 *
 *
 * The driver should be used in the following way:
 *
 * - Make sure this driver's device node is present. I.e. call "mknod /dev/atemsys c 101 0"
 *
 * - open()
 *   Open driver (There can be more then one file descriptor active in parallel).
 *
 * - close()
 *   Close driver. Free resources, if any were allocated.
 *
 * - ioctl(ATEMSYS_IOCTL_PCI_FIND_DEVICE)
 *   Scan for PCI Devices.
 *   Input:  VendorID, DeviceID, InstanceNo
 *   Output: BusNo, DevNo, FuncNo
 *
 * - ioctl(ATEMSYS_IOCTL_PCI_CONF_DEVICE)
 *   Configures PCI device. This ioctl pins the given PCI device to the current filedescriptor.
 *   Input:  BusNo, DevNo, FuncNo
 *   Output: Physical IO base address, IO area length, IRQ number
 *   The device must be released explicitly in order to configure the next device. The ioctl gets
 *   errno EBUSY if the device is in use by another device driver.
 *
 * - ioctl(ATEMSYS_IOCTL_PCI_RELEASE_DEVICE)
 *   Release PCI device and free resources assigned to PCI device (interrupt, DMA memory, ...).
 *
 * - mmap(0, dwSize, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_LOCKED, fd, 0);
 *   Allocates and maps DMA memory of size dwSize. Note that the last parameter (offset) must be 0.
 *   Input:  Length in byte
 *   Output: Pointer to the allocated memory and DMA physical address. On success this address is
 *           written into the first 4 bytes of the allocated memory.
 *
 * - mmap(0, IOphysSize, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_LOCKED, fd, IOphysAddr);
 *   Maps IO memory of size IOphysSize.
 *   PCI device:
 *     First call ioctl(ATEMSYS_IOCTL_PCI_CONF_DEVICE). The IOphysAddr and IOphysSize
 *     parameter must corespond with the base IO address and size returned by
 *     ioctl(ATEMSYS_IOCTL_PCI_CONF_DEVICE), or the ioctl will fail.
 *   Non-PCI device:
 *     Don't call ioctl(ATEMSYS_IOCTL_PCI_CONF_DEVICE) before and just pass
 *     IOphysAddr and IOphysSize. There are no checks done.
 *   Input:  Phys.IO base address, IO area length in byte
 *   Output: Pointer to the mapped IO memory.
 *   The user should call dev_munmap() if the requested DMA memory is not needed anymore. In any cases
 *   the allocated / mapped memory is released / unmapped if the module is unloaded.
 *
 * - ioctl(ATEMSYS_IOCTL_INT_CONNECT)
 *   Connect an ISR to the device's interrupt.
 *   If the parameter is USE_PCI_INT, then the IRQ is taken from the selected PCI device.
 *   So in this case you have to call ioctl(ATEMSYS_IOCTL_PCI_CONF_DEVICE) first, or it will fail.
 *   Input:  IRQ-Number or USE_PCI_INT
 *   Output: none
 *   The device interrupt is active if this ioctl succeeds. The caller should do a read() on the file
 *   descriptor. The read call unblocks if an interrupt is received. If the read is unblocked, the
 *   interrupt is disabled on the (A)PIC and the caller must acknowledge the interrupt on the device
 *   (write to mmaped IO register). If the next read() is executed, the interrupt is enabled again
 *   on the (A)PIC. So a missing interrupt acknowledge will held the INT line active and interrupt
 *   trashing will happen (ISR is called again, read() unblocks, ...).
 *   Note that this ioctl will fail with errno EPERM if the interrupt line is shared.
 *   PCI device:
 *     The ioctl will try to use Message Signaled Interrupts (MSI) if supported
 *     by the PCI device. By definition, interrupts are never shared with MSI and MSI are mandatory
 *     for PCI-Express :).
 *
 * - ioctl(ATEMSYS_IOCTL_INT_DISCONNECT)
 *   Disconnect from device's interrupt.
 *
 * - ioctl(ATEMSYS_IOCTL_INT_INFO)
 *   Query used interrupt number.
 *
 * - read()
 *   see ioctl(ATEMSYS_IOCTL_INT_CONNECT)
 *
 *
 *  Changes see atemsys.h
 *
 *----------------------------------------------------------------------------*/

#define ATEMSYS_C

#include <linux/module.h>
#include "atemsys.h"
#include <linux/pci.h>

#if !(defined NO_IRQ) && (defined __aarch64__)
#define NO_IRQ   ((unsigned int)(-1))
#endif

#if (defined CONFIG_XENO_COBALT)
#include <rtdm/driver.h>
#else
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/interrupt.h>
#include <linux/semaphore.h>
#include <linux/mutex.h>
#include <linux/sched.h>
#include <linux/smp.h>
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,00))
#include <linux/sched/signal.h>
#endif
#include <linux/irq.h>
#include <linux/list.h>
#if (defined CONFIG_OF)
#include <linux/of_device.h>
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0))
#include <linux/uaccess.h>
#else
#include <asm/uaccess.h>
#endif

#include <asm/current.h>
#include <linux/compat.h>
#include <linux/slab.h>
#include <linux/device.h>
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0))
#include <linux/dma-direct.h>
#endif

#if ((defined CONFIG_OF) \
       && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,6,0) /* not tested */))
#define INCLUDE_ATEMSYS_DT_DRIVER    1
#include <linux/etherdevice.h>
#include <linux/clk.h>
#include <linux/phy.h>
#include <linux/clk/clk-conf.h>
#include <linux/pinctrl/consumer.h>
#include <linux/regulator/consumer.h>
#include <linux/pm_runtime.h>
#include <linux/of_mdio.h>
#include <linux/of_net.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/wait.h>
#include <asm/param.h>
#endif
#if ((defined CONFIG_PCI) \
       && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0) /* not tested */))
#define INCLUDE_ATEMSYS_PCI_DRIVER    1
#include <linux/aer.h>
#endif

#if (defined CONFIG_DTC)
#include <linux/of.h>
#include <linux/of_irq.h>
#endif /* CONFIG_DTC */
#endif /* CONFIG_XENO_COBALT */

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,4,1))
#define INCLUDE_IRQ_TO_DESC
#endif

/* legacy support */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,13,0))
#define wait_queue_entry_t wait_queue_t
#endif

#ifndef VM_RESERVED
#define VM_RESERVED (VM_DONTEXPAND | VM_DONTDUMP)
#endif


/* define this if IO memory should also be mapped into the kernel (for debugging only) */
#undef DEBUG_IOREMAP

MODULE_AUTHOR("acontis technologies GmbH <info@acontis.com>");
MODULE_DESCRIPTION("Generic usermode PCI driver");
MODULE_LICENSE("GPL");
MODULE_VERSION(ATEMSYS_VERSION_STR);

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18))
#error "At least kernel version 2.6.18 is needed to compile!"
#endif

#if (defined CONFIG_XENO_COBALT)
#define PRINTK(prio, str, ...) rtdm_printk(prio ATEMSYS_DEVICE_NAME ": " str,  ##__VA_ARGS__)
#else
#define PRINTK(prio, str, ...) printk(prio ATEMSYS_DEVICE_NAME ": " str,  ##__VA_ARGS__)
#endif /* CONFIG_XENO_COBALT */

/* Workaround for older kernels */
/* from 'linux/kern_levels.h' */
/* integer equivalents of KERN_<LEVEL> */
#ifndef LOGLEVEL_ERR
#define LOGLEVEL_ERR        3   /* error conditions */
#endif
#ifndef LOGLEVEL_WARNING
#define LOGLEVEL_WARNING    4   /* warning conditions */
#endif
#ifndef LOGLEVEL_INFO
#define LOGLEVEL_INFO       6   /* informational */
#endif
#ifndef LOGLEVEL_DEBUG
#define LOGLEVEL_DEBUG      7   /* debug-level messages */
#endif

static int loglevel = LOGLEVEL_INFO;
#define ERR(str, ...) (LOGLEVEL_ERR <= loglevel)?     PRINTK(KERN_ERR, str, ##__VA_ARGS__)     :0
#define WRN(str, ...) (LOGLEVEL_WARNING <= loglevel)? PRINTK(KERN_WARNING, str, ##__VA_ARGS__) :0
#define INF(str, ...) (LOGLEVEL_INFO <= loglevel)?    PRINTK(KERN_INFO, str, ##__VA_ARGS__)    :0
#define DBG(str, ...) (LOGLEVEL_DEBUG <= loglevel)?   PRINTK(KERN_INFO, str, ##__VA_ARGS__)   :0

module_param(loglevel, int, 0);
MODULE_PARM_DESC(loglevel, "Set log level default LOGLEVEL_INFO, see /include/linux/kern_levels.h");

#ifndef PAGE_UP
#define PAGE_UP(addr)   (((addr)+((PAGE_SIZE)-1))&(~((PAGE_SIZE)-1)))
#endif
#ifndef PAGE_DOWN
#define PAGE_DOWN(addr) ((addr)&(~((PAGE_SIZE)-1)))
#endif

/* Comments: for kernel 2.6.18 add DMA_BIT_MASK*/
#ifndef DMA_BIT_MASK
#define DMA_BIT_MASK(n) (((n) == 64) ? ~0ULL : ((1ULL<<(n))-1))
#endif

#ifndef HAVE_ACCESS_OK_TYPE
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,0,0))
#define HAVE_ACCESS_OK_TYPE 0
#else
#define HAVE_ACCESS_OK_TYPE 1
#endif
#endif

#if HAVE_ACCESS_OK_TYPE
#define ACCESS_OK(type, addr, size)     access_ok(type, addr, size)
#else
#define ACCESS_OK(type, addr, size)     access_ok(addr, size)
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,18,0))
#define OF_DMA_CONFIGURE(dev, of_node) of_dma_configure(dev, of_node, true)
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(3,16,0))
#define OF_DMA_CONFIGURE(dev, of_node) of_dma_configure(dev, of_node)
#else
#define OF_DMA_CONFIGURE(dev, of_node)
#endif

typedef struct _ATEMSYS_T_IRQ_DESC
{
    u32               irq;
    atomic_t          count;
    atomic_t          totalCount;
#if (defined CONFIG_XENO_COBALT)
    rtdm_irq_t        irq_handle;
    rtdm_event_t      irq_event;
#else
    atomic_t          irqStatus;
    wait_queue_head_t q;
#endif /* CONFIG_XENO_COBALT */
#if (defined INCLUDE_IRQ_TO_DESC)
    bool              irq_is_level;
#endif
} ATEMSYS_T_IRQ_DESC;

struct _ATEMSYS_T_PCI_DRV_DESC_PRIVATE;
struct _ATEMSYS_T_DRV_DESC_PRIVATE;
typedef struct _ATEMSYS_T_DEVICE_DESC
{
    struct list_head list;
#if (defined CONFIG_PCI)
    struct pci_dev  *pPcidev;
  #if (defined INCLUDE_ATEMSYS_PCI_DRIVER)
    struct _ATEMSYS_T_PCI_DRV_DESC_PRIVATE *pPciDrvDesc;
  #endif
#endif
#if (!defined CONFIG_XENO_COBALT)
    struct platform_device* pPlatformDev;
  #if (defined INCLUDE_ATEMSYS_DT_DRIVER)
    struct _ATEMSYS_T_DRV_DESC_PRIVATE *pDrvDesc;
  #endif
#endif

    ATEMSYS_T_IRQ_DESC  irqDesc;

    /* supported features */
    bool bSupport64BitDma;
} ATEMSYS_T_DEVICE_DESC;

typedef struct _ATEMSYS_T_MMAP_DESC
{
   struct list_head  list;
   ATEMSYS_T_DEVICE_DESC *pDevDesc;
   dma_addr_t        dmaAddr;
   void             *pVirtAddr;
   size_t            len;
} ATEMSYS_T_MMAP_DESC;

#if (defined CONFIG_OF)
#define ATEMSYS_DT_DRIVER_NAME "atemsys"
/* udev auto-loading support via DTB */
static const struct of_device_id atemsys_ids[] = {
    { .compatible = ATEMSYS_DT_DRIVER_NAME },
    { /* sentinel */ }
};
MODULE_DEVICE_TABLE(of, atemsys_ids);
#endif /* CONFIG_OF */


#define ATEMSYS_MAX_NUMBER_DRV_INSTANCES 10

#if (defined INCLUDE_ATEMSYS_PCI_DRIVER)
typedef struct _ATEMSYS_T_PCI_DRV_DESC_PRIVATE
{
    struct pci_dev*             pPciDev;

    int                         nPciDomain;
    int                         nPciBus;
    int                         nPciDev;
    int                         nPciFun;

    unsigned short              wVendorId;
    unsigned short              wDevice;
    unsigned short              wRevision;
    unsigned short              wSubsystem_vendor;
    unsigned short              wSubsystem_device;

    ATEMSYS_T_PCI_MEMBAR        aBars[ATEMSYS_PCI_MAXBAR];
    int                         nBarCnt;

    ATEMSYS_T_DEVICE_DESC*      pDevDesc;
    unsigned int                dwIndex;
} ATEMSYS_T_PCI_DRV_DESC_PRIVATE;

static ATEMSYS_T_PCI_DRV_DESC_PRIVATE*  S_apPciDrvDescPrivate[ATEMSYS_MAX_NUMBER_DRV_INSTANCES];
#endif

#if (defined INCLUDE_ATEMSYS_DT_DRIVER)
#define ATEMSYS_MAX_NUMBER_OF_CLOCKS 10

typedef struct _ATEMSYS_T_DRV_DESC_PRIVATE
{
    int                         nDev_id;
    struct net_device*          netdev;
    struct platform_device*     pPDev;
    struct device_node*         pDevNode;

    /* storage and identification */
    ATEMSYS_T_MAC_INFO          MacInfo;

    /* clocks */
    const char*                 clk_ids[ATEMSYS_MAX_NUMBER_OF_CLOCKS];
    struct clk*                 clks[ATEMSYS_MAX_NUMBER_OF_CLOCKS];
    int                         nCountClk;

    /* PHY */
    ATEMSYS_T_PHY_INFO          PhyInfo;
    phy_interface_t             PhyInterface;
    struct device_node*         pPhyNode;
    struct phy_device*          pPhyDev;
    struct regulator*           pPhyRegulator;
    struct task_struct*         etx_thread_StartPhy;
    struct task_struct*         etx_thread_StopPhy;

    /* mdio */
    ATEMSYS_T_MDIO_ORDER        MdioOrder;
    struct mii_bus*             pMdioBus;
    struct mutex                mdio_order_mutex;
    struct mutex                mdio_mutex;
    wait_queue_head_t           mdio_wait_queue;
    int                         mdio_wait_queue_cnt;

    /* frame descriptor of the EcMaster connection */
    ATEMSYS_T_DEVICE_DESC*      pDevDesc;

} ATEMSYS_T_DRV_DESC_PRIVATE;

static ATEMSYS_T_DRV_DESC_PRIVATE*  S_apDrvDescPrivate[ATEMSYS_MAX_NUMBER_DRV_INSTANCES];

static int StartPhyThread(void* pvData);
static int StopPhyThread(void* pvData);
static int CleanUpEthernetDriverOnRelease(ATEMSYS_T_DEVICE_DESC* pDevDesc);
static int GetMacInfoIoctl(ATEMSYS_T_DEVICE_DESC* pDevDesc, unsigned long ioctlParam);
static int PhyStartStopIoctl( unsigned long ioctlParam);
static int GetMdioOrderIoctl(unsigned long ioctlParam);
static int ReturnMdioOrderIoctl(unsigned long ioctlParam);
static int GetPhyInfoIoctl(unsigned long ioctlParam);
static int EthernetDriverRemove(struct platform_device *pPDev);
static int EthernetDriverProbe(struct platform_device *pPDev);
#endif /* INCLUDE_ATEMSYS_DT_DRIVER */


static void dev_munmap(struct vm_area_struct *vma);

#if (defined CONFIG_XENO_COBALT)
   static int dev_interrupt_handler(rtdm_irq_t *irq_handle);
#else
   static irqreturn_t dev_interrupt_handler(int nIrq, void *pParam);
#endif /* CONFIG_XENO_COBALT */

static struct vm_operations_struct mmap_vmop =
{
   .close = dev_munmap,
};

#if (!defined CONFIG_XENO_COBALT)
static DEFINE_MUTEX(S_mtx);
static ATEMSYS_T_DEVICE_DESC S_DevNode;
static struct class* S_pDevClass;
static struct device* S_pDev;
static struct platform_device* S_pPlatformDev = NULL;

static void dev_enable_irq(ATEMSYS_T_IRQ_DESC* pIrqDesc)
{
    /* enable/disable level type interrupts, not edge type interrupts */
#if (defined INCLUDE_IRQ_TO_DESC)
    if (pIrqDesc->irq_is_level)
#endif
    {
        atomic_inc(&pIrqDesc->irqStatus);
        enable_irq(pIrqDesc->irq);
    }
}

static void dev_disable_irq(ATEMSYS_T_IRQ_DESC* pIrqDesc)
{
    /* enable/disable level type interrupts, not edge type interrupts */
#if (defined INCLUDE_IRQ_TO_DESC)
    if (!pIrqDesc->irq_is_level) return;
#endif

    if (atomic_read(&pIrqDesc->irqStatus) > 0)
    {
        disable_irq_nosync(pIrqDesc->irq);
        atomic_dec(&pIrqDesc->irqStatus);
    }
}

static int dev_irq_disabled(ATEMSYS_T_IRQ_DESC* pIrqDesc)
{
    /* only level type interrupts get disabled */
#if (defined INCLUDE_IRQ_TO_DESC)
    if (!pIrqDesc->irq_is_level) return 0;
#endif

    if (atomic_read(&pIrqDesc->irqStatus) == 0)
    {
        return 1;
    }
    return 0;
}
#endif /* !CONFIG_XENO_COBALT */

#if (!defined __arm__) && (!defined __aarch64__)
static void * dev_dma_alloc(u32 dwLen, dma_addr_t *pDmaAddr)
{
   unsigned long virtAddr;
   unsigned long tmpAddr;
   u32 tmpSize;

   virtAddr =  __get_free_pages(GFP_KERNEL | GFP_DMA, get_order(dwLen));
   if (! virtAddr)
   {
      ERR("mmap: __get_free_pages failed\n");
      return NULL;
   }

   tmpAddr = virtAddr;
   tmpSize = dwLen;

   while (tmpSize > 0)
   {
     SetPageReserved( virt_to_page(tmpAddr) );
     tmpAddr += PAGE_SIZE;
     tmpSize -= PAGE_SIZE;
   }

   *pDmaAddr = virt_to_phys((void *) virtAddr);

   return (void *) virtAddr;
}

static void dev_dma_free(u32 dwLen, void *virtAddr)
{
   unsigned long tmpAddr = (unsigned long) virtAddr;
   u32 tmpSize = dwLen;

   while (tmpSize > 0)
   {
     ClearPageReserved( virt_to_page(tmpAddr) );
     tmpAddr += PAGE_SIZE;
     tmpSize -= PAGE_SIZE;
   }

   free_pages((unsigned long) virtAddr, get_order(dwLen));
}
#endif /* !__arm__ */

static void dev_munmap(struct vm_area_struct *vma)
{
   ATEMSYS_T_MMAP_DESC *pMmapDesc = (ATEMSYS_T_MMAP_DESC *) vma->vm_private_data;

   INF("dev_munmap: 0x%px -> 0x%px (%d)\n",
         (void *) pMmapDesc->pVirtAddr, (void *)(unsigned long)pMmapDesc->dmaAddr, (int) pMmapDesc->len);
    if (0 == pMmapDesc->dmaAddr) { INF("dev_munmap: 0 == pMmapDesc->dmaAddr!\n"); return; }
    if (NULL == pMmapDesc->pVirtAddr) { INF("dev_munmap: NULL == pMmapDesc->pVirtAddr!\n"); return; }

   /* free DMA memory */
#if (defined CONFIG_PCI)
   if (pMmapDesc->pDevDesc->pPcidev == NULL)
#endif
   {
#if (defined __arm__) || (defined __aarch64__)
      dmam_free_coherent(&pMmapDesc->pDevDesc->pPlatformDev->dev, pMmapDesc->len, pMmapDesc->pVirtAddr, pMmapDesc->dmaAddr);
#else
      dev_dma_free(pMmapDesc->len, pMmapDesc->pVirtAddr);
#endif
   }
#if (defined CONFIG_PCI)
   else
   {
#if ((defined __aarch64__) \
    || (LINUX_VERSION_CODE >= KERNEL_VERSION(5,0,0)) \
    || ((defined __arm__) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0))) \
    || ((defined __amd64__) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0))) )
      dma_free_coherent(&pMmapDesc->pDevDesc->pPcidev->dev, pMmapDesc->len, pMmapDesc->pVirtAddr, pMmapDesc->dmaAddr);
#else
      pci_free_consistent(pMmapDesc->pDevDesc->pPcidev, pMmapDesc->len, pMmapDesc->pVirtAddr, pMmapDesc->dmaAddr);
#endif /* __aarch64__ */
   }
#endif /* CONFIG_PCI */
   kfree(pMmapDesc);
}

#if (defined CONFIG_PCI)
/*
 * Lookup PCI device
 */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24))
struct pci_dev *pci_get_bus_and_slot(unsigned int bus, unsigned int devfn)
{
    struct pci_dev *dev = NULL;

    for_each_pci_dev(dev) {
        if (pci_domain_nr(dev->bus) == 0 &&
            (dev->bus->number == bus && dev->devfn == devfn))
            return dev;
    }
    return dev;
}
#endif

static int dev_pci_select_device(ATEMSYS_T_DEVICE_DESC* pDevDesc, ATEMSYS_T_PCI_SELECT_DESC* pciDesc, size_t size)
{
    int nRetval = -EFAULT;
    s32 nPciBus, nPciDev, nPciFun;
    s32 nPciDomain = 0;

    switch (size)
    {
    case sizeof(ATEMSYS_T_PCI_SELECT_DESC_v1_0_00):
    {
        ATEMSYS_T_PCI_SELECT_DESC_v1_0_00* pciDesc_v1_0_00 = (ATEMSYS_T_PCI_SELECT_DESC_v1_0_00*)pciDesc;
        get_user(nPciBus,   &pciDesc_v1_0_00->nPciBus);
        get_user(nPciDev,   &pciDesc_v1_0_00->nPciDev);
        get_user(nPciFun,   &pciDesc_v1_0_00->nPciFun);
    } break;
    case sizeof(ATEMSYS_T_PCI_SELECT_DESC_v1_3_05):
    {
        ATEMSYS_T_PCI_SELECT_DESC_v1_3_05* pciDesc_v1_3_05 = (ATEMSYS_T_PCI_SELECT_DESC_v1_3_05*)pciDesc;
        get_user(nPciBus,   &pciDesc_v1_3_05->nPciBus);
        get_user(nPciDev,   &pciDesc_v1_3_05->nPciDev);
        get_user(nPciFun,   &pciDesc_v1_3_05->nPciFun);
        get_user(nPciDomain,&pciDesc_v1_3_05->nPciDomain);
    } break;
    case sizeof(ATEMSYS_T_PCI_SELECT_DESC_v1_4_12):
    {
        ATEMSYS_T_PCI_SELECT_DESC_v1_4_12* pciDesc_v1_4_12 = (ATEMSYS_T_PCI_SELECT_DESC_v1_4_12*)pciDesc;
        get_user(nPciBus,   &pciDesc_v1_4_12->nPciBus);
        get_user(nPciDev,   &pciDesc_v1_4_12->nPciDev);
        get_user(nPciFun,   &pciDesc_v1_4_12->nPciFun);
        get_user(nPciDomain,&pciDesc_v1_4_12->nPciDomain);
    } break;
    default:
    {
        nRetval = -EFAULT;
        ERR("pci_conf: EFAULT\n");
        goto Exit;
    }
    }

    /* Lookup for pci_dev object */
    pDevDesc->pPcidev       = NULL;
#if (defined INCLUDE_ATEMSYS_PCI_DRIVER)
    pDevDesc->pPciDrvDesc   = NULL;
    {
        unsigned int i = 0;

        for (i = 0; i < ATEMSYS_MAX_NUMBER_DRV_INSTANCES; i++)
        {
            ATEMSYS_T_PCI_DRV_DESC_PRIVATE* pDrvInstance = S_apPciDrvDescPrivate[i];
            if (   (pDrvInstance                != NULL)
                && (pDrvInstance->nPciDomain    == nPciDomain)
                && (pDrvInstance->nPciBus       == nPciBus)
                && (pDrvInstance->nPciDev       == nPciDev)
                && (pDrvInstance->nPciFun       == nPciFun))
            {
                if (pDrvInstance->pDevDesc != NULL)
                {
                    ERR("dev_pci_select_device: device \"%s\" in use by another instance?\n", pci_name(pDrvInstance->pPciDev));
                    nRetval = -EBUSY;
                    goto Exit;
                }
                pDevDesc->pPcidev        = pDrvInstance->pPciDev;
                pDevDesc->pPciDrvDesc    = pDrvInstance;
                pDrvInstance->pDevDesc   = pDevDesc;
                INF("pci_select: from pci driver %04x:%02x:%02x.%x\n", (u32)nPciDomain, (u32)nPciBus, (u32)nPciDev, (u32)nPciFun);
                break;
            }
        }
    }
    if (pDevDesc->pPcidev == NULL)
#endif
    {
        pDevDesc->pPcidev = pci_get_domain_bus_and_slot(nPciDomain, nPciBus, PCI_DEVFN(nPciDev, nPciFun));
        INF("pci_select: %04x:%02x:%02x.%x\n", (u32)nPciDomain, (u32)nPciBus, (u32)nPciDev, (u32)nPciFun);
    }
    if (pDevDesc->pPcidev == NULL)
    {
        WRN("pci_select: PCI-Device  %04x:%02x:%02x.%x not found\n",
            (unsigned) nPciDomain, (unsigned) nPciBus, (unsigned) nPciDev, (unsigned) nPciFun);
        goto Exit;
    }

    nRetval = DRIVER_SUCCESS;

Exit:
    return nRetval;
}

static int DefaultPciSettings(struct pci_dev* pPciDev)
{
    int nRetval = -EIO;
    int nRes = -EIO;

    /* Turn on Memory-Write-Invalidate if it is supported by the device*/
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24))
    pci_set_mwi(pPciDev);
#else
    pci_try_set_mwi(pPciDev);
#endif

#if ((defined __aarch64__) && (defined(CONFIG_ARCH_HAS_SYNC_DMA_FOR_DEVICE) || \
        defined(CONFIG_ARCH_HAS_SYNC_DMA_FOR_CPU) || defined(CONFIG_ARCH_HAS_SYNC_DMA_FOR_CPU_ALL)))
    if (0 != pPciDev->dev.dma_coherent)
    {
        pPciDev->dev.dma_coherent = 0;
        INF("%s: DefaultPciSettings: Clear device dma_coherent bit!\n", pci_name(pPciDev));
    }
#endif

#if ((LINUX_VERSION_CODE < KERNEL_VERSION(5,10,0)) || !(defined __aarch64__))
    nRes = dma_set_mask_and_coherent(&pPciDev->dev, DMA_BIT_MASK(32));
    if (nRes)
#endif
    {
        nRes = dma_set_mask_and_coherent(&pPciDev->dev, DMA_BIT_MASK(64));
        if (nRes)
        {
            ERR("%s: DefaultPciSettings: dma_set_mask_and_coherent failed\n", pci_name(pPciDev));
            nRetval = nRes;
            goto Exit;
        }
    }
    pci_set_master(pPciDev);

    /* Try to enable MSI (Message Signaled Interrupts). MSI's are non shared, so we can
    * use interrupt mode, also if we have a non exclusive interrupt line with legacy
    * interrupts.
    */
    if (pci_enable_msi(pPciDev))
    {
        INF("%s: DefaultPciSettings: legacy INT configured\n", pci_name(pPciDev));
    }
    else
    {
        INF("%s: DefaultPciSettings: MSI configured\n", pci_name(pPciDev));
    }

    nRetval = 0;

Exit:
   return nRetval;
}

/*
 * See also kernel/Documentation/PCI/pci.txt for the recommended PCI initialization sequence
 */
static int ioctl_pci_configure_device(ATEMSYS_T_DEVICE_DESC* pDevDesc, unsigned long ioctlParam, size_t size)
{
    int nRetval = -EIO;
    int nRc;
    int i;
    unsigned long ioBase;
    u32 dwIOLen;
    s32 nBar = 0;
    u32 dwAtemsysApiVersion = 0x010000;
    ATEMSYS_T_PCI_SELECT_DESC_v1_4_12*  pPciDesc_v1_4_12 = NULL;
    ATEMSYS_T_PCI_SELECT_DESC_v1_3_05*  pPciDesc_v1_3_05 = NULL;
    ATEMSYS_T_PCI_SELECT_DESC_v1_0_00*  pPciDesc_v1_0_00= NULL;

    switch (size)
    {
    case sizeof(ATEMSYS_T_PCI_SELECT_DESC_v1_0_00):
    {
        dwAtemsysApiVersion = 0x010000;
        pPciDesc_v1_0_00 = (ATEMSYS_T_PCI_SELECT_DESC_v1_0_00*)ioctlParam;
        if (!ACCESS_OK(VERIFY_WRITE, pPciDesc_v1_0_00, sizeof(ATEMSYS_T_PCI_SELECT_DESC_v1_0_00)))
        {
            nRetval = -EFAULT;
        }
    } break;
    case sizeof(ATEMSYS_T_PCI_SELECT_DESC_v1_3_05):
    {
        dwAtemsysApiVersion = 0x010305;
        pPciDesc_v1_3_05 = (ATEMSYS_T_PCI_SELECT_DESC_v1_3_05*)ioctlParam;
        if (!ACCESS_OK(VERIFY_WRITE, pPciDesc_v1_3_05, sizeof(ATEMSYS_T_PCI_SELECT_DESC_v1_3_05)))
        {
            nRetval = -EFAULT;
        }
    } break;
    case sizeof(ATEMSYS_T_PCI_SELECT_DESC_v1_4_12):
    {
        dwAtemsysApiVersion = 0x01040c;
        pPciDesc_v1_4_12 = (ATEMSYS_T_PCI_SELECT_DESC_v1_4_12*)ioctlParam;
        if (!ACCESS_OK(VERIFY_WRITE, pPciDesc_v1_4_12, sizeof(ATEMSYS_T_PCI_SELECT_DESC_v1_4_12)))
        {
            nRetval = -EFAULT;
        }
    } break;
    default:
    {
        nRetval = -EFAULT;
    }
    }

    if (-EFAULT == nRetval)
    {
        ERR("pci_conf: EFAULT\n");
        goto Exit;
    }

    if (pDevDesc->pPcidev != NULL)
    {
        WRN("pci_conf: error call ioctl(ATEMSYS_IOCTL_PCI_RELEASE_DEVICE) first\n");
        goto Exit;
     }
    if (dev_pci_select_device(pDevDesc, (ATEMSYS_T_PCI_SELECT_DESC*)ioctlParam, size) != DRIVER_SUCCESS)
    {
        goto Exit;
    }

#if (defined INCLUDE_ATEMSYS_PCI_DRIVER)
    if (NULL != pDevDesc->pPciDrvDesc)
    {
        for (i = 0; i < pDevDesc->pPciDrvDesc->nBarCnt ; i++)
        {
            if ((0x01040c != dwAtemsysApiVersion) && (pDevDesc->pPciDrvDesc->aBars[i].qwIOMem > 0xFFFFFFFF))
            {
                ERR("pci_conf: 64-Bit IO address not supported\n");
                nRetval = -ENODEV;
                goto Exit;
            }

            switch (dwAtemsysApiVersion)
            {
            case 0x010000:
            {
                put_user((u32)pDevDesc->pPciDrvDesc->aBars[i].qwIOMem, &(pPciDesc_v1_0_00->aBar[i].dwIOMem));
                put_user(pDevDesc->pPciDrvDesc->aBars[i].dwIOLen,      &(pPciDesc_v1_0_00->aBar[i].dwIOLen));
            } break;
            case 0x010305:
            {
                put_user((u32)pDevDesc->pPciDrvDesc->aBars[i].qwIOMem, &(pPciDesc_v1_3_05->aBar[i].dwIOMem));
                put_user(pDevDesc->pPciDrvDesc->aBars[i].dwIOLen,      &(pPciDesc_v1_3_05->aBar[i].dwIOLen));
            } break;
            case 0x01040c:
            {
                put_user(pDevDesc->pPciDrvDesc->aBars[i].qwIOMem,      &(pPciDesc_v1_4_12->aBar[i].qwIOMem));
                put_user(pDevDesc->pPciDrvDesc->aBars[i].dwIOLen,      &(pPciDesc_v1_4_12->aBar[i].dwIOLen));
            } break;
            }
        }
        switch (dwAtemsysApiVersion)
        {
        case 0x010000:
        {
            put_user(pDevDesc->pPciDrvDesc->nBarCnt, &(pPciDesc_v1_0_00->nBarCnt));
            put_user((u32)pDevDesc->pPcidev->irq,    &(pPciDesc_v1_0_00->dwIrq));
        } break;
        case 0x010305:
        {
            put_user(pDevDesc->pPciDrvDesc->nBarCnt, &(pPciDesc_v1_3_05->nBarCnt));
            put_user((u32)pDevDesc->pPcidev->irq,    &(pPciDesc_v1_3_05->dwIrq));
        } break;
        case 0x01040c:
        {
            put_user(pDevDesc->pPciDrvDesc->nBarCnt, &(pPciDesc_v1_4_12->nBarCnt));
            put_user((u32)pDevDesc->pPcidev->irq,    &(pPciDesc_v1_4_12->dwIrq));
        } break;
        }
    }
    else
#endif
    {
        /* enable device */
        nRc = pci_enable_device(pDevDesc->pPcidev);
        if (nRc < 0)
        {
            ERR("pci_conf: pci_enable_device failed\n");
            pDevDesc->pPcidev = NULL;
            goto Exit;
        }

        /* Check if IO-memory is in use by another driver */
        nRc = pci_request_regions(pDevDesc->pPcidev, ATEMSYS_DEVICE_NAME);
        if (nRc < 0)
        {
            ERR("pci_conf: device \"%s\" in use by another driver?\n", pci_name(pDevDesc->pPcidev));
            pDevDesc->pPcidev = NULL;
            nRetval = -EBUSY;
            goto Exit;
        }

        /* find the memory BAR */
        for (i = 0; i < ATEMSYS_PCI_MAXBAR ; i++)
        {
            if (pci_resource_flags(pDevDesc->pPcidev, i) & IORESOURCE_MEM)
            {
                /* IO area address */
                ioBase = pci_resource_start(pDevDesc->pPcidev, i);

                if ((0x01040c != dwAtemsysApiVersion) && (ioBase > 0xFFFFFFFF))
                {
                    ERR("pci_conf: 64-Bit IO address not supported\n");
                    pci_release_regions(pDevDesc->pPcidev);
                    pDevDesc->pPcidev = NULL;
                    nRetval = -ENODEV;
                    goto Exit;
                }

                /* IO area length */
                dwIOLen = pci_resource_len(pDevDesc->pPcidev, i);

                switch (dwAtemsysApiVersion)
                {
                case 0x010000:
                {
                    put_user((u32)ioBase, &(pPciDesc_v1_0_00->aBar[nBar].dwIOMem));
                    put_user(dwIOLen,     &(pPciDesc_v1_0_00->aBar[nBar].dwIOLen));
                } break;
                case 0x010305:
                {
                    put_user((u32)ioBase, &(pPciDesc_v1_3_05->aBar[nBar].dwIOMem));
                    put_user(dwIOLen,     &(pPciDesc_v1_3_05->aBar[nBar].dwIOLen));
                } break;
                case 0x01040c:
                {
                    put_user((u64)ioBase, &(pPciDesc_v1_4_12->aBar[nBar].qwIOMem));
                    put_user(dwIOLen,     &(pPciDesc_v1_4_12->aBar[nBar].dwIOLen));
                } break;
                }

                nBar++;
            }
        }

        /* number of memory BARs */
        switch (dwAtemsysApiVersion)
        {
        case 0x010000:
        {
            put_user(nBar, &(pPciDesc_v1_0_00->nBarCnt));
        } break;
        case 0x010305:
        {
            put_user(nBar, &(pPciDesc_v1_3_05->nBarCnt));
        } break;
        case 0x01040c:
        {
            put_user(nBar, &(pPciDesc_v1_4_12->nBarCnt));
        } break;
        }

        nRc = DefaultPciSettings(pDevDesc->pPcidev);
        if (nRc)
        {
            pci_release_regions(pDevDesc->pPcidev);
            pDevDesc->pPcidev = NULL;
            goto Exit;
        }

        /* assigned IRQ */
        switch (dwAtemsysApiVersion)
        {
        case 0x010000:
        {
            put_user((u32)pDevDesc->pPcidev->irq, &(pPciDesc_v1_0_00->dwIrq));
        } break;
        case 0x010305:
        {
            put_user((u32)pDevDesc->pPcidev->irq, &(pPciDesc_v1_3_05->dwIrq));
        } break;
        case 0x01040c:
        {
            put_user((u32)pDevDesc->pPcidev->irq, &(pPciDesc_v1_4_12->dwIrq));
        } break;
        }
    }

#if defined(__arm__) && 0
   /*
    * This is required for TI's TMDXEVM8168 (Cortex A8) eval board
    * \sa TI "DM81xx AM38xx PCI Express Root Complex Driver User Guide"
    * "DM81xx RC supports maximum remote read request size (MRRQS) as 256 bytes"
    */
   pcie_set_readrq(pDevDesc->pPcidev, 256);
#endif

   nRetval = 0;

Exit:
   return nRetval;
}

static int ioctl_pci_finddevice(ATEMSYS_T_DEVICE_DESC* pDevDesc, unsigned long ioctlParam, size_t size)
{
    int nRetval = -EIO;
    struct pci_dev* pPciDev = NULL;
    s32 nVendor, nDevice, nInstance, nInstanceId;
    u32 dwAtemsysApiVersion = 0x010000;
    ATEMSYS_T_PCI_SELECT_DESC_v1_0_00* pPciDesc_v1_0_00 = NULL;
    ATEMSYS_T_PCI_SELECT_DESC_v1_3_05* pPciDesc_v1_3_05 = NULL;
    ATEMSYS_T_PCI_SELECT_DESC_v1_4_12* pPciDesc_v1_4_12 = NULL;

    switch (size)
    {
    case sizeof(ATEMSYS_T_PCI_SELECT_DESC_v1_0_00):
    {
        dwAtemsysApiVersion = 0x010000;
        pPciDesc_v1_0_00 = (ATEMSYS_T_PCI_SELECT_DESC_v1_0_00*)ioctlParam;
        if (!ACCESS_OK(VERIFY_WRITE, pPciDesc_v1_0_00, sizeof(ATEMSYS_T_PCI_SELECT_DESC_v1_0_00)))
        {
            nRetval = -EFAULT;
        }
    } break;
    case sizeof(ATEMSYS_T_PCI_SELECT_DESC_v1_3_05):
    {
        dwAtemsysApiVersion = 0x010305;
        pPciDesc_v1_3_05 = (ATEMSYS_T_PCI_SELECT_DESC_v1_3_05*)ioctlParam;
        if (!ACCESS_OK(VERIFY_WRITE, pPciDesc_v1_3_05, sizeof(ATEMSYS_T_PCI_SELECT_DESC_v1_3_05)))
        {
            nRetval = -EFAULT;
        }
    } break;
    case sizeof(ATEMSYS_T_PCI_SELECT_DESC_v1_4_12):
    {
        dwAtemsysApiVersion = 0x01040c;
        pPciDesc_v1_4_12 = (ATEMSYS_T_PCI_SELECT_DESC_v1_4_12*)ioctlParam;
        if (!ACCESS_OK(VERIFY_WRITE, pPciDesc_v1_4_12, sizeof(ATEMSYS_T_PCI_SELECT_DESC_v1_4_12)))
        {
            nRetval = -EFAULT;
        }
    } break;
    default:
    {
        nRetval = -EFAULT;
    }
    }

    if (-EFAULT == nRetval)
    {
        ERR("pci_find: EFAULT\n");
        nRetval = -EFAULT;
        goto Exit;
    }

    switch (dwAtemsysApiVersion)
    {
    case 0x010000:
    {
        get_user(nVendor,  &pPciDesc_v1_0_00->nVendID);
        get_user(nDevice,  &pPciDesc_v1_0_00->nDevID);
        get_user(nInstance,&pPciDesc_v1_0_00->nInstance);
    } break;
    case 0x010305:
    {
        get_user(nVendor,  &pPciDesc_v1_3_05->nVendID);
        get_user(nDevice,  &pPciDesc_v1_3_05->nDevID);
        get_user(nInstance,&pPciDesc_v1_3_05->nInstance);
    } break;
    case 0x01040c:
    {
        get_user(nVendor,  &pPciDesc_v1_4_12->nVendID);
        get_user(nDevice,  &pPciDesc_v1_4_12->nDevID);
        get_user(nInstance,&pPciDesc_v1_4_12->nInstance);
    } break;
    }

    INF("pci_find: ven 0x%x dev 0x%x nInstance %d\n", nVendor, nDevice, nInstance);

    for (nInstanceId = 0; nInstanceId <= nInstance; nInstanceId++ )
    {
        pPciDev = pci_get_device (nVendor, nDevice, pPciDev);
    }

    if (pPciDev == NULL)
    {
        WRN("pci_find: device 0x%x:0x%x:%d not found\n", nVendor, nDevice, nInstance);
        nRetval = -ENODEV;
        goto Exit;
    }

    INF("pci_find: found 0x%x:0x%x:%d -> %s\n",
       nVendor, nDevice, nInstance, pci_name(pPciDev));

    switch (dwAtemsysApiVersion)
    {
    case 0x010000:
    {
        put_user((s32)pPciDev->bus->number,         &pPciDesc_v1_0_00->nPciBus);
        put_user((s32)PCI_SLOT(pPciDev->devfn),     &pPciDesc_v1_0_00->nPciDev);
        put_user((s32)PCI_FUNC(pPciDev->devfn),     &pPciDesc_v1_0_00->nPciFun);
    } break;
    case 0x010305:
    {
        put_user((s32)pci_domain_nr(pPciDev->bus),  &pPciDesc_v1_3_05->nPciDomain);
        put_user((s32)pPciDev->bus->number,         &pPciDesc_v1_3_05->nPciBus);
        put_user((s32)PCI_SLOT(pPciDev->devfn),     &pPciDesc_v1_3_05->nPciDev);
        put_user((s32)PCI_FUNC(pPciDev->devfn),     &pPciDesc_v1_3_05->nPciFun);
    } break;
    case 0x01040c:
    {
        put_user((s32)pci_domain_nr(pPciDev->bus),  &pPciDesc_v1_4_12->nPciDomain);
        put_user((s32)pPciDev->bus->number,         &pPciDesc_v1_4_12->nPciBus);
        put_user((s32)PCI_SLOT(pPciDev->devfn),     &pPciDesc_v1_4_12->nPciDev);
        put_user((s32)PCI_FUNC(pPciDev->devfn),     &pPciDesc_v1_4_12->nPciFun);
    } break;
    }

    nRetval = 0;

Exit:
    return nRetval;
}
#endif /* CONFIG_PCI */

#if (defined CONFIG_DTC)
/*
 * Lookup Nth (0: first) compatible device tree node with "interrupts" property present.
 */
static struct device_node * atemsys_of_lookup_intnode(const char *compatible, int deviceIdx)
{
   struct device_node *device = NULL;
   struct device_node *child = NULL;
   struct device_node *tmp = NULL;
   int devCnt;

   /* Lookup Nth device tree node */
   devCnt = 0;
   for_each_compatible_node(tmp, NULL, compatible)
   {
      if (devCnt == deviceIdx)
      {
         device = tmp;
         break;
      }
      ++devCnt;
   }

   if (device == NULL) return NULL;

   if (of_get_property(device, "interrupts", NULL)) return device;

   /* i.e. vETSEC has 2 groups. Search them */
   for_each_child_of_node(device, child)
   {
      if (of_get_property(child, "interrupts", NULL)) return child;
   }

   return NULL;
}

/*
 * Map interrupt number taken from the OF Device Tree (\sa .dts file) into
 * virtual interrupt number which can be passed to request_irq().
 * The usual (device driver) way is to use the irq_of_parse_and_map() function.
 *
 * We search all device tree nodes which have the "compatible" property
 * equal to compatible. Search until the Nth device is found. Then
 * map the Nth interrupt (given by intIdx) with irq_of_parse_and_map().
 */
static unsigned atemsys_of_map_irq_to_virq(const char *compatible, int deviceIdx, int intIdx)
{
   unsigned virq;
   struct device_node *device = NULL;

   /* Lookup Nth device */
   device = atemsys_of_lookup_intnode(compatible, deviceIdx);
   if (! device)
   {
      INF("atemsys_of_map_irq_to_virq: device tree node '%s':%d not found.\n",
         compatible, deviceIdx);
      return NO_IRQ;
   }

   virq = irq_of_parse_and_map(device, intIdx);
   if (virq == NO_IRQ)
   {
      ERR("atemsys_of_map_irq_to_virq: irq_of_parse_and_map failed for"
          " device tree node '%s':%d, IntIdx %d.\n",
         compatible, deviceIdx, intIdx);
   }

   return virq;
}
#if (defined INCLUDE_ATEMSYS_DT_DRIVER)
static unsigned int atemsysDtDriver_of_map_irq_to_virq(ATEMSYS_T_DEVICE_DESC* pDevDesc, int nIdx)
{
    ATEMSYS_T_DRV_DESC_PRIVATE* pDrvDescPrivate = NULL;
    struct device_node*         device          = NULL;
    unsigned int                irq;
    unsigned int                i               = 0;

    /* get node from atemsys platform driver list */
    for (i = 0; i < ATEMSYS_MAX_NUMBER_DRV_INSTANCES; i++)
    {

        pDrvDescPrivate = S_apDrvDescPrivate[i];
        if (NULL == pDrvDescPrivate)
        {
            continue;
        }

        if (pDrvDescPrivate->pDevDesc == pDevDesc)
        {
            device = pDrvDescPrivate->pDevNode;
            break;
        }
    }
    if ((NULL == device) || (NULL == pDrvDescPrivate))
    {
        INF("atemsysDtDriver_of_map_irq_to_virq: Cannot find connected device tree node\n");
        return NO_IRQ;
    }

    /* get interrupt from node */
    irq = irq_of_parse_and_map(device, nIdx);
    if (NO_IRQ == irq)
    {
        ERR("atemsysDtDriver_of_map_irq_to_virq: irq_of_parse_and_map failed for"
            " device tree node Interrupt index %d\n",
            nIdx);
    }

    return irq;
}
#endif /* INCLUDE_ATEMSYS_DT_DRIVER) */
#endif /* CONFIG_DTC */

#if (defined INCLUDE_IRQ_TO_DESC)
static bool atemsys_irq_is_level(unsigned int irq_id)
{
     bool irq_is_level = true;
     struct irq_data *irq_data = NULL;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,11,1))
    {
        irq_data = irq_get_irq_data(irq_id);
    }
#else
    {
        struct irq_desc *desc;
        desc = irq_to_desc(irq_id);
        if (desc)
        {
            irq_data = &desc->irq_data;
        }
    }
#endif
    if (irq_data)
    {
        irq_is_level = irqd_is_level_type(irq_data);
    }

    return irq_is_level;
}
#endif /* INCLUDE_IRQ_TO_DESC */

static int ioctl_int_connect(ATEMSYS_T_DEVICE_DESC* pDevDesc, unsigned long ioctlParam)
{
    int nRetval = -EIO;
    int nRc;
    ATEMSYS_T_IRQ_DESC *pIrqDesc = NULL;
    unsigned int irq = 0;

#if (defined CONFIG_PCI)
    if (ioctlParam == USE_PCI_INT)
    {
        /* Use IRQ number from selected PCI device */

        if (pDevDesc->pPcidev == NULL)
        {
            WRN("intcon: error call ioctl(ATEMSYS_IOCTL_PCI_CONF_DEVICE) first\n");
            goto Exit;
        }

        irq = pDevDesc->pPcidev->irq;
        INF("intcon: Use IRQ (%d) from PCI config\n", irq);
    }
    else
#endif /* CONFIG_PCI */
    {
#if (defined CONFIG_DTC)
        /* The ioctlParam is the Nth compatible device in the OF device tree (0: first, 1: second, ...)
         * TODO "compatible string" and "interrupt index" should be provided by usermode as IOCTL param
         */
        if ( /* Use interrupt number at idx 1 (Rx-Interrupt) for TSEC / eTSEC */
             ((irq = atemsys_of_map_irq_to_virq("fsl,etsec2", ioctlParam, 1)) == NO_IRQ) /* PPC, eTSEC */
          && ((irq = atemsys_of_map_irq_to_virq("gianfar", ioctlParam, 1)) == NO_IRQ) /* PPC, eTSEC */
          /* PRU-ICSS for am572x, am335x */
          && ((irq = atemsys_of_map_irq_to_virq("acontis,device", 0, ioctlParam)) == NO_IRQ)
          /* Use interrupt number at idx 0 (Catch-All-Interrupt) for GEM */
          && ((irq = atemsys_of_map_irq_to_virq("xlnx,ps7-ethernet-1.00.a", ioctlParam, 0)) == NO_IRQ) /* ARM, Xilinx Zynq */
           )
        {
#if (defined INCLUDE_ATEMSYS_DT_DRIVER)
            /* Get Interrupt from binded device tree node */
            if ((irq = atemsysDtDriver_of_map_irq_to_virq(pDevDesc, ioctlParam)) == NO_IRQ)
#endif
            {
                nRetval = -EPERM;
                goto Exit;
            }
        }

#else
        /* Use IRQ number passed as ioctl argument */
        irq = ioctlParam;
        INF("intcon: Use IRQ (%d) passed by user\n", irq);
#endif
    }

    pIrqDesc = &pDevDesc->irqDesc;
    if (pIrqDesc->irq)
    {
        WRN("intcon: error IRQ %u already connected. Call ioctl(ATEMSYS_IOCTL_INT_DISCONNECT) first\n",
            (unsigned) pIrqDesc->irq);
        goto Exit;
    }

    /* Setup some data which is needed during Interrupt handling */
    memset(pIrqDesc, 0, sizeof(ATEMSYS_T_IRQ_DESC));
    atomic_set(&pIrqDesc->count, 0);
    atomic_set(&pIrqDesc->totalCount, 0);

#if (defined CONFIG_XENO_COBALT)
    rtdm_event_init(&pIrqDesc->irq_event, 0);
    nRc = rtdm_irq_request(&pIrqDesc->irq_handle, irq, dev_interrupt_handler, 0, ATEMSYS_DEVICE_NAME, pDevDesc);
    if (nRc)
    {
        ERR("ioctl_int_connect: rtdm_irq_request() for IRQ %d returned error: %d\n", irq, nRc);
        nRetval = nRc;
        goto Exit;
    }
    nRc = rtdm_irq_enable(&pIrqDesc->irq_handle);
    if (nRc)
    {
        ERR("ioctl_int_connect: rtdm_irq_enable() for IRQ %d returned error: %d\n", irq, nRc);
        nRetval = nRc;
        goto Exit;
    }
#else
    init_waitqueue_head(&pIrqDesc->q);
    atomic_set(&pIrqDesc->irqStatus, 1); /* IRQ enabled */

    /* Setup non shared IRQ */
    nRc = request_irq(irq, dev_interrupt_handler, 0, ATEMSYS_DEVICE_NAME, pDevDesc);
    if (nRc)
    {
        ERR("ioctl_int_connect: request_irq (IRQ %d) failed. Err %d\n", irq, nRc);
        nRetval = -EPERM;
        goto Exit;
    }
#endif /* CONFIG_XENO_COBALT */

    pIrqDesc->irq = irq;
#if (defined INCLUDE_IRQ_TO_DESC)
    pIrqDesc->irq_is_level = atemsys_irq_is_level(irq);
#endif

#if (defined INCLUDE_IRQ_TO_DESC)
    INF("intcon: IRQ %d connected, irq_is_level = %d\n", irq, pIrqDesc->irq_is_level);
#else
    INF("intcon: IRQ %d connected\n", irq);
#endif

    nRetval = 0;
Exit:
    return nRetval;
}

static int ioctl_intinfo(ATEMSYS_T_DEVICE_DESC* pDevDesc, unsigned long ioctlParam)
{
   int nRetval = -EIO;
   ATEMSYS_T_INT_INFO *pIntInfo = (ATEMSYS_T_INT_INFO *) ioctlParam;

#if (defined CONFIG_XENO_COBALT)
   struct rtdm_fd* fd = rtdm_private_to_fd(pDevDesc);
   if (rtdm_fd_is_user(fd))
   {
      nRetval = rtdm_safe_copy_to_user(fd, &pIntInfo->dwInterrupt, &pDevDesc->irqDesc.irq, sizeof(__u32));
      if (nRetval)
      {
          ERR("ioctl_intinfo failed: %d\n", nRetval);
          goto Exit;
      }
   }
#else
   if (!ACCESS_OK(VERIFY_WRITE, pIntInfo, sizeof(ATEMSYS_T_INT_INFO)))
   {
      ERR("ioctl_intinfo: EFAULT\n");
      nRetval = -EFAULT;
      goto Exit;
   }

   nRetval = put_user(pDevDesc->irqDesc.irq, &pIntInfo->dwInterrupt);
#endif /* CONFIG_XENO_COBALT */

Exit:
   return nRetval;
}


static int dev_int_disconnect(ATEMSYS_T_DEVICE_DESC* pDevDesc)
{
   int nRetval = -EIO;
   int nCnt;
   ATEMSYS_T_IRQ_DESC *pIrqDesc = &(pDevDesc->irqDesc);

#if (defined CONFIG_XENO_COBALT)
      int nRc;
      if (pIrqDesc->irq)
      {
         nRc = rtdm_irq_disable(&pIrqDesc->irq_handle);
         if (nRc)
         {
            ERR("dev_int_disconnect: rtdm_irq_disable() for IRQ %d returned error: %d\n", (u32) pIrqDesc->irq, nRc);
            nRetval = nRc;
            goto Exit;
         }

         nRc = rtdm_irq_free(&pIrqDesc->irq_handle);
         if (nRc)
         {
            ERR("dev_int_disconnect: rtdm_irq_free() for IRQ %d returned error: %d\n", (u32) pIrqDesc->irq, nRc);
            nRetval = nRc;
            goto Exit;
         }

         nCnt = atomic_read(&pIrqDesc->totalCount);
         INF("pci_intdcon: IRQ %u disconnected. %d interrupts rcvd\n", (u32) pIrqDesc->irq, nCnt);

         pIrqDesc->irq = 0;
         rtdm_event_signal(&pIrqDesc->irq_event);
      }
#else
      if (pIrqDesc->irq)
      {
         /* Disable INT line. We can call this, because we only allow exclusive interrupts */
         disable_irq_nosync(pIrqDesc->irq);

         /* Unregister INT routine.This will block until all pending interrupts are handled */
         free_irq(pIrqDesc->irq, pDevDesc);

         nCnt = atomic_read(&pIrqDesc->totalCount);
         INF("pci_intdcon: IRQ %u disconnected. %d interrupts rcvd\n", (u32) pIrqDesc->irq, nCnt);

         pIrqDesc->irq = 0;

         /* Wakeup sleeping threads -> read() */
         wake_up(&pIrqDesc->q);
      }
#endif /* CONFIG_XENO_COBALT */
   nRetval = 0;

#if (defined CONFIG_XENO_COBALT)
Exit:
#endif
   return nRetval;
}

#if (defined CONFIG_PCI)
static void dev_pci_release(ATEMSYS_T_DEVICE_DESC* pDevDesc)
{
#if (defined INCLUDE_ATEMSYS_PCI_DRIVER)
    if (NULL != pDevDesc->pPciDrvDesc)
    {
        INF("pci_release: Disconnect from PCI device driver %s \n", pci_name(pDevDesc->pPcidev));
        pDevDesc->pPciDrvDesc->pDevDesc = NULL;
        pDevDesc->pPcidev               = NULL;
        pDevDesc->pPciDrvDesc           = NULL;
    }
#endif

   if (pDevDesc->pPcidev)
   {
      pci_disable_device(pDevDesc->pPcidev);

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,29))
      /* Make sure bus master DMA is disabled if the DMA buffers are finally released */
      pci_clear_master(pDevDesc->pPcidev);
#endif
      pci_release_regions(pDevDesc->pPcidev);

      pci_disable_msi(pDevDesc->pPcidev);

      INF("pci_release: PCI device %s released\n", pci_name(pDevDesc->pPcidev));

      pDevDesc->pPcidev = NULL;
   }
}
#endif /* CONFIG_PCI */

#if (defined CONFIG_XENO_COBALT)
static int dev_interrupt_handler(rtdm_irq_t *irq_handle)
{
    ATEMSYS_T_DEVICE_DESC* pDevDesc = rtdm_irq_get_arg(irq_handle, ATEMSYS_T_DEVICE_DESC);
    ATEMSYS_T_IRQ_DESC* pIrqDesc = NULL;

    if (pDevDesc != NULL)
    {
        pIrqDesc = &(pDevDesc->irqDesc);
        if (pIrqDesc != NULL)
        {
            atomic_inc(&pIrqDesc->count);
            atomic_inc(&pIrqDesc->totalCount);
            rtdm_event_signal(&pIrqDesc->irq_event);
        }
    }
    return RTDM_IRQ_HANDLED;
}
#else
static irqreturn_t dev_interrupt_handler(int nIrq, void *pParam)
{
   ATEMSYS_T_DEVICE_DESC* pDevDesc = (ATEMSYS_T_DEVICE_DESC *) pParam;
   ATEMSYS_T_IRQ_DESC* pIrqDesc = &(pDevDesc->irqDesc);

   /* Disable IRQ on (A)PIC to prevent interrupt trashing if the ISR is left.
    * In usermode the IRQ must be acknowledged on the device (IO register).
    * The IRQ is enabled again in the read() handler!
    * Just disabling the IRQ here doesn't work with shared IRQs!
    */
   dev_disable_irq(pIrqDesc);

   atomic_inc(&pIrqDesc->count);
   atomic_inc(&pIrqDesc->totalCount);

   /* Wakeup sleeping threads -> read() */
   wake_up(&pIrqDesc->q);

   return IRQ_HANDLED;
}
#endif /* CONFIG_XENO_COBALT */

/*
 * This is called whenever a process attempts to open the device file
 */
#if (defined CONFIG_XENO_COBALT)
static int device_open(struct rtdm_fd * fd, int oflags)
{
   ATEMSYS_T_DEVICE_DESC* pDevDesc = (ATEMSYS_T_DEVICE_DESC *) rtdm_fd_to_private(fd);
   memset(pDevDesc, 0, sizeof(ATEMSYS_T_DEVICE_DESC));
   rtdm_event_init(&pDevDesc->irqDesc.irq_event, 0);
   INF("device_open %s\n", rtdm_fd_device(fd)->label);
#else
static int device_open(struct inode *inode, struct file *file)
{
   ATEMSYS_T_DEVICE_DESC* pDevDesc;

   INF("device_open(0x%px)\n", file);

   /* create device descriptor */
   pDevDesc = (ATEMSYS_T_DEVICE_DESC *) kzalloc(sizeof(ATEMSYS_T_DEVICE_DESC), GFP_KERNEL);
   if (pDevDesc == NULL)
   {
      return -ENOMEM;
   }

   file->private_data = (void *) pDevDesc;

   /* use module's platform device for memory maping and allocation */
   pDevDesc->pPlatformDev = S_pPlatformDev;

   /* Add descriptor to descriptor list */
   mutex_lock(&S_mtx);
   list_add(&pDevDesc->list, &S_DevNode.list);
   mutex_unlock(&S_mtx);
   try_module_get(THIS_MODULE);
#endif /* CONFIG_XENO_COBALT */

   return DRIVER_SUCCESS;
}

#if (defined CONFIG_XENO_COBALT)
static void device_release(struct rtdm_fd * fd)
{
    ATEMSYS_T_DEVICE_DESC* pDevDesc = (ATEMSYS_T_DEVICE_DESC *) rtdm_fd_to_private(fd);
    ATEMSYS_T_IRQ_DESC* pIrqDesc = NULL;
#else
static int device_release(struct inode *inode, struct file *file)
{
   ATEMSYS_T_DEVICE_DESC* pDevDesc = file->private_data;
#endif /* CONFIG_XENO_COBALT */

   /* release device descriptor */
   if (pDevDesc != NULL )
   {
       INF("device_release, pDevDesc = 0x%px\n", pDevDesc);

       /* Try to tear down interrupts if they are on */
       dev_int_disconnect(pDevDesc);

#if (defined INCLUDE_ATEMSYS_DT_DRIVER)
       CleanUpEthernetDriverOnRelease(pDevDesc);
#endif

#if (defined CONFIG_PCI)
       /* Try to release PCI resources */
       dev_pci_release(pDevDesc);
#endif

#if (defined CONFIG_XENO_COBALT)
       pIrqDesc = &(pDevDesc->irqDesc);

       if (pIrqDesc != NULL )
       {
          rtdm_event_clear(&pIrqDesc->irq_event);
          rtdm_event_destroy(&pIrqDesc->irq_event);
       }
    }
    return;
#else
       /* Remove descriptor from descriptor list */
       mutex_lock(&S_mtx);

       list_del(&pDevDesc->list);

       mutex_unlock(&S_mtx);

       kfree(pDevDesc);
   }

   module_put(THIS_MODULE);

   return DRIVER_SUCCESS;
#endif /* CONFIG_XENO_COBALT */
}

/*
 * This function is called whenever a process which has already opened the
 * device file attempts to read from it.
 */
 #if (defined CONFIG_XENO_COBALT)
static ssize_t device_read(struct rtdm_fd * fd, void *bufp, size_t len)
{
   ATEMSYS_T_DEVICE_DESC*   pDevDesc = (ATEMSYS_T_DEVICE_DESC *) rtdm_fd_to_private(fd);
   ATEMSYS_T_IRQ_DESC*      pIrqDesc = NULL;
   s32 nPending;
   int ret=0;

   if (! pDevDesc)
   {
      return -EINVAL;
   }

   pIrqDesc = &(pDevDesc->irqDesc);
   if (! pIrqDesc)
   {
      return -EINVAL;
   }

   if (len < sizeof(u32))
   {
      return -EINVAL;
   }

   if (rtdm_in_rt_context() == false)
   {
       return -EINVAL;
   }

   if (rtdm_fd_is_user(fd) == false)
   {
       return -EINVAL;
   }

   ret = rtdm_event_wait(&pIrqDesc->irq_event);
   if (ret)
   {
       return ret;
   }

   nPending = atomic_read(&pIrqDesc->count);

   ret = rtdm_safe_copy_to_user(fd, bufp, &nPending, sizeof(nPending));

   if (ret)
   {
       ERR("device_read: rtdm_safe_copy_to_user() returned error: %d\n", ret);
       return ret;
   }

   atomic_sub(nPending, &pIrqDesc->count);

   return sizeof(nPending);
}
#else
static ssize_t device_read(
      struct file *filp,   /* see include/linux/fs.h   */
      char __user *bufp,   /* buffer to be filled with data */
      size_t       len,    /* length of the buffer     */
      loff_t      *ppos)
{

   ATEMSYS_T_DEVICE_DESC*   pDevDesc = (ATEMSYS_T_DEVICE_DESC *) filp->private_data;
   ATEMSYS_T_IRQ_DESC*      pIrqDesc = NULL;
   s32 nPending;
   wait_queue_entry_t wait;

   if (! pDevDesc)
   {
      return -EINVAL;
   }

   pIrqDesc = &(pDevDesc->irqDesc);

   /* DBG("device_read...(0x%px,0x%px,%d)\n", filp, bufp, len); */

   init_wait(&wait);

   if (len < sizeof(u32))
   {
      return -EINVAL;
   }

   if (pIrqDesc->irq == 0) /* IRQ already disabled */
   {
      return -EINVAL;
   }

   nPending = atomic_read(&pIrqDesc->count);
   if (nPending == 0)
   {
      if (dev_irq_disabled(pIrqDesc))
      {
         dev_enable_irq(pIrqDesc);
      }
      if (filp->f_flags & O_NONBLOCK)
      {
         return -EWOULDBLOCK;
      }
   }

   while (nPending == 0)
   {
      prepare_to_wait(&pIrqDesc->q, &wait, TASK_INTERRUPTIBLE);
      nPending = atomic_read(&pIrqDesc->count);
      if (nPending == 0)
      {
         schedule();
      }
      finish_wait(&pIrqDesc->q, &wait);
      if (pIrqDesc->irq == 0) /* IRQ disabled while waiting for IRQ */
      {
         return -EINVAL;
      }
      if (signal_pending(current))
      {
         return -ERESTARTSYS;
      }
   }

   if (copy_to_user(bufp, &nPending, sizeof(nPending)))
   {
      return -EFAULT;
   }

   *ppos += sizeof(nPending);
   atomic_sub(nPending, &pIrqDesc->count);

   return sizeof(nPending);
}
#endif /* CONFIG_XENO_COBALT */

/*
 * character device mmap method
 */
#if (defined CONFIG_XENO_COBALT)
static int device_mmap(struct rtdm_fd * fd, struct vm_area_struct *vma)
{
   ATEMSYS_T_DEVICE_DESC*   pDevDesc = (ATEMSYS_T_DEVICE_DESC *) rtdm_fd_to_private(fd);
#else
static int device_mmap(struct file *filp, struct vm_area_struct *vma)
{
   ATEMSYS_T_DEVICE_DESC*   pDevDesc = filp->private_data;
#endif /* CONFIG_XENO_COBALT */

   int         nRet = -EIO;
   u32         dwLen;
   void       *pVa = NULL;
   dma_addr_t  dmaAddr;
   ATEMSYS_T_MMAP_DESC  *pMmapNode;
#if (defined CONFIG_PCI)
   int         i;
   unsigned long ioBase;
   u32 dwIOLen, dwPageOffset;
#endif

   DBG("mmap: vm_pgoff 0x%px vm_start = 0x%px vm_end = 0x%px\n",
         (void *) vma->vm_pgoff, (void *) vma->vm_start, (void *) vma->vm_end);

   if (pDevDesc == NULL)
   {
      ERR("mmap: Invalid device dtor\n");
      goto Exit;
   }

   dwLen = PAGE_UP(vma->vm_end - vma->vm_start);

   vma->vm_flags |= VM_RESERVED | VM_LOCKED | VM_DONTCOPY;

   if (vma->vm_pgoff != 0)
   {
      /* map device IO memory */
#if (defined CONFIG_PCI)
      if (pDevDesc->pPcidev != NULL)
      {
         INF("mmap: Doing PCI device sanity check\n");

         /* sanity check. Make sure that the offset parameter of the mmap() call in userspace
          * corresponds with the PCI base IO address.
          * Make sure the user doesn't map more IO memory than the device provides.
          */
         for (i = 0; i < ATEMSYS_PCI_MAXBAR; i++)
         {
            if (pci_resource_flags(pDevDesc->pPcidev, i) & IORESOURCE_MEM)
            {
               /* IO area address */
               ioBase = PAGE_DOWN( pci_resource_start(pDevDesc->pPcidev, i) );

               dwPageOffset = pci_resource_start(pDevDesc->pPcidev, i) - ioBase;

               /* IO area length */
               dwIOLen = PAGE_UP( pci_resource_len(pDevDesc->pPcidev, i) + dwPageOffset );

               if (    ((vma->vm_pgoff << PAGE_SHIFT) >= ioBase)
                    && (((vma->vm_pgoff << PAGE_SHIFT) + dwLen) <= (ioBase + dwIOLen))
                  )
               {
                  /* for systems where physical address is in x64 space, high dword is not passes from user io
                   * use correct address from pci_resource_start */
                  resource_size_t res_start = pci_resource_start(pDevDesc->pPcidev, i);
                  unsigned long pgoff_new = (res_start>>PAGE_SHIFT);
                  if (pgoff_new != vma->vm_pgoff)
                  {
                      INF("mmap: Correcting page offset from 0x%lx to 0x%lx, for Phys address 0x%llx",
                              vma->vm_pgoff, pgoff_new, (u64)res_start);
                      vma->vm_pgoff =  pgoff_new;
                  }

                  break;
               }
            }
         }

         /* IO bar not found? */
         if (i == ATEMSYS_PCI_MAXBAR)
         {
            ERR("mmap: Invalid arguments\n");
            nRet = -EINVAL;
            goto Exit;
         }
      }
#endif /* CONFIG_PCI */

      /* avoid swapping, request IO memory */
      vma->vm_flags |= VM_IO;

      /*
       * avoid caching (this is at least needed for POWERPC,
       * or machine will lock on first IO access)
       */
      vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);

      if ((nRet = remap_pfn_range(vma,
                                 vma->vm_start,
                                 vma->vm_pgoff,
                                 dwLen,
                                 vma->vm_page_prot)) < 0)
      {
         ERR("mmap: remap_pfn_range failed\n");
         goto Exit;
      }

      INF("mmap: mapped IO memory, Phys:0x%llx UVirt:0x%px Size:%u\n",
           (u64) (((u64)vma->vm_pgoff) << PAGE_SHIFT), (void *) vma->vm_start, dwLen);

#if (defined DEBUG_IOREMAP)
      {
        volatile unsigned char *ioaddr;
        unsigned long ioBase = vma->vm_pgoff << PAGE_SHIFT;
        INF("try to remap %p\n", (void *)ioBase);
        /* DEBUG Map device's IO memory into kernel space pagetables */
        ioaddr = (volatile unsigned char *) ioremap_nocache(ioBase, dwLen);
        if (ioaddr == NULL)
        {
          ERR("ioremap_nocache failed\n");
          goto Exit;
        }
        INF("io_base %p, *io_base[0]: %08x\n", ioaddr, readl(ioaddr));
      }
#endif /* DEBUG_IOREMAP */
   }
   else
   {
      /* allocated and map DMA memory */
#if (defined CONFIG_PCI)
      if (pDevDesc->pPcidev != NULL)
      {
#if ((defined __aarch64__) \
    || (LINUX_VERSION_CODE >= KERNEL_VERSION(5,0,0)) \
    || ((defined __arm__) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0))) \
    || ((defined __amd64__) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0))) )
         pVa = dma_alloc_coherent(&pDevDesc->pPcidev->dev, dwLen, &dmaAddr, GFP_KERNEL);
         if (NULL == pVa)
         {
            ERR("mmap: dma_alloc_coherent failed\n");
            nRet = -ENOMEM;
            goto Exit;
         }
#else
         pVa = pci_alloc_consistent(pDevDesc->pPcidev, dwLen, &dmaAddr);
         if (NULL == pVa)
         {
            ERR("mmap: pci_alloc_consistent failed\n");
            nRet = -ENOMEM;
            goto Exit;
         }
#endif
      }
      else
#endif /* CONFIG_PCI */
      {
#if (defined __arm__) || (defined __aarch64__)
 #if (defined CONFIG_OF)
         OF_DMA_CONFIGURE(&pDevDesc->pPlatformDev->dev,pDevDesc->pPlatformDev->dev.of_node);
 #endif
         /* dma_alloc_coherent() is currently not tested on PPC.
          * TODO test this and remove legacy dev_dma_alloc()
          */
         pVa = dmam_alloc_coherent(&pDevDesc->pPlatformDev->dev, dwLen, &dmaAddr, GFP_KERNEL);
         if (NULL == pVa)
         {
            ERR("mmap: dmam_alloc_coherent failed\n");
            nRet = -ENOMEM;
            goto Exit;
         }
#else
         pVa = dev_dma_alloc(dwLen, &dmaAddr);
         if (NULL == pVa)
         {
            ERR("mmap: dev_dma_alloc failed\n");
            nRet = -ENOMEM;
            goto Exit;
         }
#endif
      }

      if ((dmaAddr > 0xFFFFFFFF) && !pDevDesc->bSupport64BitDma)
      {
         ERR("mmap: Can't handle 64-Bit DMA address\n");
         INF("mmap: Update LinkLayer for 64-Bit DMA support!\n");
         nRet = -ENOMEM;
         goto ExitAndFree;
      }

      /* zero memory for security reasons */
      memset(pVa, 0, dwLen);

      /* Always use noncached DMA memory for ARM. Otherwise cache invaliation/sync
       * would be necessary from usermode.
       * Can't do that without a kernel call because this OP's are privileged.
       */

      /* map the whole physically contiguous area in one piece */
      {
         unsigned int dwDmaPfn = 0;

#if (defined __arm__) || (defined __aarch64__)
         dwDmaPfn = (dmaAddr >> PAGE_SHIFT);
 #if (defined CONFIG_PCI)
  #if (LINUX_VERSION_CODE < KERNEL_VERSION(5,10,0))
         if ((NULL != pDevDesc->pPcidev) && (0 != pDevDesc->pPcidev->dev.dma_pfn_offset))
         {
            dwDmaPfn = dwDmaPfn + pDevDesc->pPcidev->dev.dma_pfn_offset;
            INF("mmap: remap_pfn_range dma pfn 0x%x, offset pfn 0x%x\n",
                        dwDmaPfn, (u32)pDevDesc->pPcidev->dev.dma_pfn_offset);
         }
  #else
         if ((NULL != pDevDesc->pPcidev) && (NULL != pDevDesc->pPcidev->dev.dma_range_map))
         {
            const struct bus_dma_region *map = pDevDesc->pPcidev->dev.dma_range_map;
            unsigned long dma_pfn_offset = ((map->offset) >> PAGE_SHIFT);
            dwDmaPfn = dwDmaPfn + dma_pfn_offset;
            INF("mmap: remap_pfn_range dma pfn 0x%x, offset pfn 0x%x\n",
                        dwDmaPfn, (u32)dma_pfn_offset);
         }
  #endif /* (LINUX_VERSION_CODE < KERNEL_VERSION(5,10,0))*/
  #if (defined __arm__)
         else
  #endif
 #endif /* (defined CONFIG_PCI) */
         {
            vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
         }
#elif (defined __PPC__)
         dwDmaPfn = (dmaAddr >> PAGE_SHIFT);
#else /* x86 / x86_64 */
         dwDmaPfn = virt_to_phys((void*)pVa) >> PAGE_SHIFT;
#endif
         nRet = remap_pfn_range(vma,               /* user space mapping */
                                vma->vm_start,     /* User space virtual addr */
                                dwDmaPfn,          /* physical page frame number */
                                dwLen,             /* size in bytes */
                                vma->vm_page_prot);
         if (nRet < 0)
         {
            ERR("remap_pfn_range failed\n");
            goto ExitAndFree;
         }
      }

      /* Write the physical DMA address into the first 4 bytes of allocated memory */
      /* If there is 64 bit DMA support write upper part into the the next 4 byte  */
      if (pDevDesc->bSupport64BitDma)
      {
         ((u32 *) pVa)[0] = (u32)((u64)dmaAddr & 0xFFFFFFFF);
         ((u32 *) pVa)[1] = (u32)(((u64)dmaAddr >> 32) & 0xFFFFFFFF);
      }
      else
      {
         *((u32 *) pVa) = (u32) dmaAddr;
      }

      /* Some housekeeping to be able to cleanup the allocated memory later */
      pMmapNode = kzalloc(sizeof(ATEMSYS_T_MMAP_DESC), GFP_KERNEL);
      if (! pMmapNode)
      {
         ERR("mmap: kmalloc() failed\n");
         nRet = -ENOMEM;
         goto ExitAndFree;
      }

      pMmapNode->pDevDesc = pDevDesc;
      pMmapNode->dmaAddr = dmaAddr;
      pMmapNode->pVirtAddr = pVa;
      pMmapNode->len = dwLen;

      /* Setup close callback -> deallocates DMA memory if region is unmapped by the system */
      vma->vm_ops = &mmap_vmop;
      vma->vm_private_data = pMmapNode;

      INF("mmap: mapped DMA memory, Phys:0x%px KVirt:0x%px UVirt:0x%px Size:0x%x\n",
             (void *)(unsigned long)dmaAddr, (void *)pVa, (void *)vma->vm_start, dwLen);
   }

   nRet = 0;

   goto Exit;

ExitAndFree:

   if (pVa == NULL) goto Exit;

#if (defined CONFIG_PCI)
   if (pDevDesc->pPcidev != NULL)
   {
#if ((defined __aarch64__) \
    || (LINUX_VERSION_CODE >= KERNEL_VERSION(5,0,0)) \
    || ((defined __arm__) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0))) \
    || ((defined __amd64__) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0))) )
      dma_free_coherent(&pDevDesc->pPcidev->dev, dwLen, pVa, dmaAddr);
#else
      pci_free_consistent(pDevDesc->pPcidev, dwLen, pVa, dmaAddr);
#endif
   }
   else
#endif
   {
#if (defined __arm__) || (defined __aarch64__)
      dmam_free_coherent(&pDevDesc->pPlatformDev->dev, dwLen, pVa, dmaAddr);
#else
      dev_dma_free(dwLen, pVa);
#endif
   }

Exit:
   return nRet;
}

#if (defined(__GNUC__) && (defined(__ARM__) || defined(__arm__) || defined(__aarch64__)))
static void ioctl_enableCycleCount(void* arg)
{
   __u32 dwEnableUserMode = *(__u32*)arg;
   /* Make CCNT accessible from usermode */
#if !defined(__aarch64__)
   __asm__ __volatile__("mcr p15, 0, %0, c9, c14, 0" :: "r"(dwEnableUserMode));
#else
   /* aarch32: PMUSERENR => aarch64: PMUSERENR_EL0 */
   __asm__ __volatile__("msr PMUSERENR_EL0, %0" :: "r"(dwEnableUserMode));
#endif

   if (dwEnableUserMode)
   {
#if !defined(__aarch64__)
      /* Disable counter flow interrupt */
      __asm__ volatile ("mcr p15, 0, %0, c9, c14, 2" :: "r"(0x8000000f));
      /* Initialize CCNT */
      __asm__ volatile ("mcr p15, 0, %0, c9, c12, 0" :: "r"(5));
      /* Start CCNT */
      __asm__ volatile ("mcr p15, 0, %0, c9, c12, 1" :: "r"(0x80000000));
#else
      /* Disable counter flow interrupt */  /* aarch32:PMINTENCLR => aarch64:PMINTENCLR_EL1 */
      __asm__ volatile ("msr PMINTENCLR_EL1, %0" :: "r"(0x8000000f));
      /* Initialize CCNT */  /* aarch32:PMCR       => aarch64:PMCR_EL0*/
      __asm__ volatile ("msr PMCR_EL0, %0" :: "r"(5));
      /* Start CCNT */  /*  aarch32:PMCNTENSET => aarch64:PMCNTENSET_EL0 */
      __asm__ volatile ("msr PMCNTENSET_EL0, %0" :: "r"(0x80000000));
#endif
   }
   else
   {
#if !defined(__aarch64__)
      __asm__ volatile ("mcr p15, 0, %0, c9, c12, 0" :: "r"(0));
#else
      /* aarch32:PMCR       => aarch64:PMCR_EL0 */
      __asm__ volatile ("msr PMCR_EL0, %0" :: "r"(0));
#endif
   }
}
#endif

/*
 * This function is called whenever a process tries to do an ioctl on our
 * device file.
 *
 * If the ioctl is write or read/write (meaning output is returned to the
 * calling process), the ioctl call returns the output of this function.
 *
 */
#if (defined CONFIG_XENO_COBALT)
static int atemsys_ioctl(struct rtdm_fd * fd, unsigned int cmd, void __user *user_arg)
{
   ATEMSYS_T_DEVICE_DESC*   pDevDesc = (ATEMSYS_T_DEVICE_DESC *) rtdm_fd_to_private(fd);
   unsigned long   arg = (unsigned long) user_arg;
#else
static long atemsys_ioctl(
      struct file *file,
      unsigned int cmd,
      unsigned long arg)
{
   ATEMSYS_T_DEVICE_DESC*   pDevDesc = file->private_data;
#endif /* CONFIG_XENO_COBALT */

   int              nRetval = -EFAULT;

   if (pDevDesc == NULL)
   {
      ERR("ioctl: Invalid device dtor\n");
      goto Exit;
   }

   /*
    * Switch according to the ioctl called
    */
   switch (cmd)
   {
#if (defined CONFIG_PCI)
      case ATEMSYS_IOCTL_PCI_FIND_DEVICE_v1_0_00:
      case ATEMSYS_IOCTL_PCI_FIND_DEVICE_v1_3_05:
      case ATEMSYS_IOCTL_PCI_FIND_DEVICE_v1_4_12:
      {
         nRetval = ioctl_pci_finddevice(pDevDesc, arg, _IOC_SIZE(cmd)); /* size determines version */
         if (0 != nRetval)
         {
           /* be quiet. ioctl may fail */
           goto Exit;
         }
      } break;
      case ATEMSYS_IOCTL_PCI_CONF_DEVICE_v1_0_00:
      case ATEMSYS_IOCTL_PCI_CONF_DEVICE_v1_3_05:
      case ATEMSYS_IOCTL_PCI_CONF_DEVICE_v1_4_12:
      {
         nRetval = ioctl_pci_configure_device(pDevDesc, arg, _IOC_SIZE(cmd)); /* size determines version */
         if (0 != nRetval)
         {
            ERR("ioctl ATEMSYS_IOCTL_PCI_CONF_DEVICE failed: %d\n", nRetval);
            goto Exit;
         }
      } break;

      case ATEMSYS_IOCTL_PCI_RELEASE_DEVICE:
      {
         if (pDevDesc->pPcidev == NULL)
         {
            DBG("pci_release: No PCI device selected. Call ioctl(ATEMSYS_IOCTL_PCI_CONF_DEVICE) first\n");
            goto Exit;
         }
         /* do nothing */
         /* see device_release() -> dev_pci_release(pDevDesc)*/
      } break;
#endif
      case ATEMSYS_IOCTL_INT_CONNECT:
      {
         nRetval = ioctl_int_connect(pDevDesc, arg);
         if (0 != nRetval)
         {
            ERR("ioctl ATEMSYS_IOCTL_INT_CONNECT failed: %d\n", nRetval);
            goto Exit;
         }
      } break;

      case ATEMSYS_IOCTL_INT_DISCONNECT:
      {
         nRetval = dev_int_disconnect(pDevDesc);
         if (0 != nRetval)
         {
            /* be quiet. ioctl may fail */
            goto Exit;
         }
      } break;

      case ATEMSYS_IOCTL_INT_INFO:
      {
         nRetval = ioctl_intinfo(pDevDesc, arg);
         if (0 != nRetval)
         {
            ERR("ioctl ATEMSYS_IOCTL_INT_INFO failed: %d\n", nRetval);
            goto Exit;
         }
      } break;

      case ATEMSYS_IOCTL_MOD_GETVERSION:
      {
         char aVersion[3] = {ATEMSYS_VERSION_NUM};
         __u32 dwVersion = ((aVersion[0] << 2 * 8) | (aVersion[1] << 1 * 8) | (aVersion[2] << 0 * 8));

#if (defined CONFIG_XENO_COBALT)
         nRetval = rtdm_safe_copy_to_user(fd, user_arg, &dwVersion, sizeof(__u32));
#else
         nRetval = put_user(dwVersion, (__u32*)arg);
#endif /* CONFIG_XENO_COBALT */

         if (0 != nRetval)
         {
            ERR("ioctl ATEMSYS_IOCTL_MOD_GETVERSION failed: %d\n", nRetval);
            goto Exit;
         }
      } break;

      case ATEMSYS_IOCTL_MOD_SET_API_VERSION:
      {
         __u32 dwApiVersion = 0;

#if (defined CONFIG_XENO_COBALT)
         nRetval = rtdm_safe_copy_from_user(fd, &dwApiVersion, user_arg, sizeof(__u32));
#else
         nRetval = get_user(dwApiVersion, (__u32*)arg);
#endif

         /* activate supported features */
         if (dwApiVersion >= EC_MAKEVERSION(1,4,14,0))
         {
            pDevDesc->bSupport64BitDma = true;
         }

         if (0 != nRetval)
         {
            ERR("ioctl ATEMSYS_IOCTL_MOD_SETVERSION failed: %d\n", nRetval);
            goto Exit;
         }
      } break;

      case ATEMSYS_IOCTL_CPU_ENABLE_CYCLE_COUNT:
      {
#if (defined(__GNUC__) && (defined(__ARM__) || defined(__arm__) || defined(__aarch64__)))
         __u32 dwEnableUserMode = 0;

#if (defined CONFIG_XENO_COBALT)
         nRetval = rtdm_safe_copy_from_user(fd, &dwEnableUserMode, user_arg, sizeof(__u32));
#else
         nRetval = get_user(dwEnableUserMode, (__u32*)arg);
#endif
         if (0 != nRetval)
         {
            ERR("ioctl ATEMSYS_IOCTL_CPU_ENABLE_CYCLE_COUNT failed: %d\n", nRetval);
            goto Exit;
         }

         on_each_cpu(ioctl_enableCycleCount, &dwEnableUserMode, 1);
#else
         nRetval = -ENODEV;
         goto Exit;
#endif
      } break;

#if (defined INCLUDE_ATEMSYS_DT_DRIVER)
    case ATEMSYS_IOCTL_GET_MAC_INFO:
    {
        nRetval = GetMacInfoIoctl(pDevDesc, arg);
        if (0 != nRetval)
        {
            ERR("ioctl ATEMSYS_IOCTL_GET_MAC_INFO failed: 0x%x\n", nRetval);
            goto Exit;
        }
    } break;
    case ATEMSYS_IOCTL_PHY_START_STOP:
    {
        nRetval = PhyStartStopIoctl(arg);
        if (0 != nRetval)
        {
            ERR("ioctl ATEMSYS_IOCTL_PHY_START_STOP failed: %d\n", nRetval);
            goto Exit;
        }
    } break;
    case ATEMSYS_IOCTL_GET_MDIO_ORDER:
    {
        nRetval = GetMdioOrderIoctl(arg);
        if (0 != nRetval)
        {
            ERR("ioctl ATEMSYS_IOCTL_GET_MDIO_ORDER failed: %d\n", nRetval);
            goto Exit;
        }
    } break;
    case ATEMSYS_IOCTL_RETURN_MDIO_ORDER:
    {
        nRetval = ReturnMdioOrderIoctl(arg);
        if (0 != nRetval)
        {
            ERR("ioctl ATEMSYS_IOCTL_RETURN_MDIO_ORDER failed: %d\n", nRetval);
            goto Exit;
        }
    } break;
    case ATEMSYS_IOCTL_GET_PHY_INFO:
    {
        nRetval = GetPhyInfoIoctl(arg);
        if (0 != nRetval)
        {
            ERR("ioctl ATEMSYS_IOCTL_GET_PHY_INFO failed: %d\n", nRetval);
            goto Exit;
        }
      } break;
#endif /* INCLUDE_ATEMSYS_DT_DRIVER */

      default:
      {
         nRetval = -EOPNOTSUPP;
         goto Exit;
      } /* no break */
   }

   nRetval = DRIVER_SUCCESS;

Exit:
   return nRetval;
}

#if (defined CONFIG_COMPAT) && !(defined CONFIG_XENO_COBALT)
/*
 * ioctl processing for 32 bit process on 64 bit system
 */
static long atemsys_compat_ioctl(
      struct file *file,
      unsigned int cmd,
      unsigned long arg)
{
   return atemsys_ioctl(file, cmd, (unsigned long) compat_ptr(arg));
}
#endif /* CONFIG_COMPAT && !CONFIG_XENO_COBALT */

/* Module Declarations */

/*
 * This structure will hold the functions to be called
 * when a process does something to the device we
 * created. Since a pointer to this structure is kept in
 * the devices table, it can't be local to
 * module_init. NULL is for unimplemented functions.
 */

#if (defined CONFIG_XENO_COBALT)
static struct rtdm_driver driver = {
        .profile_info = RTDM_PROFILE_INFO(atemsys, RTDM_CLASS_EXPERIMENTAL, MAJOR_NUM, 1),
        .device_flags = RTDM_NAMED_DEVICE,
        .device_count = 1,
        .context_size = sizeof(ATEMSYS_T_DEVICE_DESC),

        .ops = {
        .open = device_open,
        .close = device_release,
        .read_rt = device_read,
        .ioctl_rt = atemsys_ioctl,
        .ioctl_nrt = atemsys_ioctl,
        .mmap = device_mmap,
    },
};

static struct rtdm_device device = {
        .driver = &driver,
        .label = ATEMSYS_DEVICE_NAME,
};
#else /* !CONFIG_XENO_COBALT */
struct file_operations Fops = {
   .read = device_read,
   .unlocked_ioctl = atemsys_ioctl,
#if (defined CONFIG_COMPAT)
   .compat_ioctl = atemsys_compat_ioctl, /* ioctl processing for 32 bit process on 64 bit system */
#endif
   .open = device_open,
   .mmap = device_mmap,
   .release = device_release,   /* a.k.a. close */
};
#endif /* !CONFIG_XENO_COBALT */


#if (defined INCLUDE_ATEMSYS_DT_DRIVER)
static int GetMacInfoIoctl(ATEMSYS_T_DEVICE_DESC* pDevDesc, unsigned long ioctlParam)
{
    ATEMSYS_T_MAC_INFO* pInfoUserSpace = (ATEMSYS_T_MAC_INFO *)ioctlParam;
    ATEMSYS_T_MAC_INFO Info;
    ATEMSYS_T_DRV_DESC_PRIVATE* pDrvDescPrivate  = NULL;
    unsigned int dwRetVal = 0;
    int nRetVal = -1;
    int nRes = -1;
    unsigned int i = 0;

    for (i = 0; i < EC_LINKOS_IDENT_MAX_LEN; i++)
    {
        nRes = get_user(Info.szIdent[i], &pInfoUserSpace->szIdent[i]);
        if (0 != nRes) { nRetVal = nRes; goto Exit; }
    }
    nRes = get_user(Info.dwInstance, &pInfoUserSpace->dwInstance);
    if (0 != nRes) { nRetVal = nRes; goto Exit; }

    for (i = 0; i < ATEMSYS_MAX_NUMBER_DRV_INSTANCES; i++)
    {
        if (NULL == S_apDrvDescPrivate[i])
        {
            continue;
        }
        if ((0 == strcmp(S_apDrvDescPrivate[i]->MacInfo.szIdent, Info.szIdent)) &&
            (S_apDrvDescPrivate[i]->MacInfo.dwInstance == Info.dwInstance))
        {
            pDrvDescPrivate = S_apDrvDescPrivate[i];
            break;
        }
    }

    if (NULL != pDrvDescPrivate)
    {
        if (pDrvDescPrivate->pDevDesc != NULL)
        {
            ERR("GetMacInfoIoctl: device \"%s\" in use by another instance?\n", pDrvDescPrivate->pPDev->name);
            nRetVal = -EBUSY;
            goto Exit;
        }

        nRes = put_user(pDrvDescPrivate->MacInfo.qwRegAddr,  &pInfoUserSpace->qwRegAddr);
        if (0 != nRes) { nRetVal = nRes; goto Exit; }

        nRes = put_user(pDrvDescPrivate->MacInfo.dwRegSize,  &pInfoUserSpace->dwRegSize);
        if (0 != nRes) { nRetVal = nRes; goto Exit; }

        nRes |= put_user(pDrvDescPrivate->MacInfo.dwStatus,  &pInfoUserSpace->dwStatus);
        if (0 != nRes) { nRetVal = nRes; goto Exit; }

        nRes |= put_user(pDrvDescPrivate->MacInfo.ePhyMode,  &pInfoUserSpace->ePhyMode);
        if (0 != nRes) { nRetVal = nRes; goto Exit; }

        nRes |= put_user(pDrvDescPrivate->MacInfo.dwIndex,   &pInfoUserSpace->dwIndex);
        if (0 != nRes) { nRetVal = nRes; goto Exit; }

        nRes |= put_user(pDrvDescPrivate->MacInfo.bNoMdioBus,&pInfoUserSpace->bNoMdioBus);
        if (0 != nRes) { nRetVal = nRes; goto Exit; }

        nRes |= put_user(pDrvDescPrivate->MacInfo.dwPhyAddr, &pInfoUserSpace->dwPhyAddr);
        if (0 != nRes) { nRetVal = nRes; goto Exit; }

        /* save descriptor of callee for cleanup on device_release */
        pDrvDescPrivate->pDevDesc = pDevDesc;

        /* add driver's platfrom device to device descriptor of callee for memory mapping and allocation */
        pDevDesc->pPlatformDev    = pDrvDescPrivate->pPDev;
        pDevDesc->pDrvDesc        = pDrvDescPrivate;
        dwRetVal = 0; /* EC_E_NOERROR */
    }
    else
    {
        dwRetVal = 0x9811000C; /* EC_E_NOTFOUND */
    }
    nRetVal = 0;

Exit:
    if (0 == nRetVal)
    {
        put_user(dwRetVal ,&pInfoUserSpace->dwErrorCode);
    }
    else
    {
        put_user(0x98110000 /* EC_E_ERROR */ ,&pInfoUserSpace->dwErrorCode);
    }

    return nRetVal;
}

static int PhyStartStopIoctl( unsigned long ioctlParam)
{
    ATEMSYS_T_PHY_START_STOP_INFO* pPhyStartStopInfoUserSpace = (ATEMSYS_T_PHY_START_STOP_INFO *)ioctlParam;
    ATEMSYS_T_PHY_START_STOP_INFO PhyStartStopInfo;
    ATEMSYS_T_DRV_DESC_PRIVATE* pDrvDescPrivate = NULL;
    unsigned int dwRetVal = 0;
    int nRetVal = -1;
    int nRes = -1;


    nRes =  get_user(PhyStartStopInfo.dwIndex, &pPhyStartStopInfoUserSpace->dwIndex);
    if (0 != nRes) { nRetVal = nRes; goto Exit; }

    nRes = get_user(PhyStartStopInfo.bStart,  &pPhyStartStopInfoUserSpace->bStart);
    if (0 != nRes) { nRetVal = nRes; goto Exit; }

    if ((PhyStartStopInfo.dwIndex >= ATEMSYS_MAX_NUMBER_DRV_INSTANCES))
    {
        PhyStartStopInfo.dwErrorCode = 0x98110002; /* EC_E_INVALIDINDEX */
        nRetVal = 0;
        goto Exit;
    }
    pDrvDescPrivate = S_apDrvDescPrivate[PhyStartStopInfo.dwIndex];
    if (NULL == S_apDrvDescPrivate[PhyStartStopInfo.dwIndex])
    {
        dwRetVal = 0x9811000C; /* EC_E_NOTFOUND*/
        nRetVal = 0;
        goto Exit;
    }

    if (PhyStartStopInfo.bStart)
    {
        pDrvDescPrivate->etx_thread_StartPhy = kthread_create(StartPhyThread,(void*)pDrvDescPrivate->pPDev,"StartPhyThread");
        if(NULL == pDrvDescPrivate->etx_thread_StartPhy)
        {
            ERR("Cannot create kthread for StartPhyThread\n");
            nRetVal = -EAGAIN;
            goto Exit;
        }
        wake_up_process(pDrvDescPrivate->etx_thread_StartPhy);
        dwRetVal = 0; /* EC_E_NOERROR */
    }
    else
    {
        pDrvDescPrivate->etx_thread_StopPhy = kthread_create(StopPhyThread,(void*)pDrvDescPrivate->pPDev,"StopPhyThread");
        if(NULL == pDrvDescPrivate->etx_thread_StopPhy)
        {
            ERR("Cannot create kthread for StopPhyThread\n");
            nRetVal = -EAGAIN;
            goto Exit;
        }
        wake_up_process(pDrvDescPrivate->etx_thread_StopPhy);
        dwRetVal = 0; /* EC_E_NOERROR */
    }

    nRetVal = 0;
Exit:
    if (0 == nRetVal)
    {
        put_user(dwRetVal, &pPhyStartStopInfoUserSpace->dwErrorCode);
    }
    else
    {
        put_user(0x98110000 /* EC_E_ERROR */, &pPhyStartStopInfoUserSpace->dwErrorCode);
    }

    return nRetVal;
}


static int GetMdioOrderIoctl( unsigned long ioctlParam)
{
    ATEMSYS_T_DRV_DESC_PRIVATE* pDrvDescPrivate = NULL;
    ATEMSYS_T_MDIO_ORDER* pOrderUserSpace = (ATEMSYS_T_MDIO_ORDER*)ioctlParam;
    unsigned int dwIndex = 0;
    bool bLocked = false;
    unsigned int dwRetVal = 0;
    int nRetVal = -1;
    int nRes = -1;


    nRes = get_user(dwIndex, &pOrderUserSpace->dwIndex);
    if (0 != nRes) { nRetVal = nRes; goto Exit; }

    if (dwIndex >= ATEMSYS_MAX_NUMBER_DRV_INSTANCES)
    {
        dwRetVal = 0x98110002; /* EC_E_INVALIDINDEX */
        nRetVal = 0;
        goto Exit;
    }
    pDrvDescPrivate = S_apDrvDescPrivate[dwIndex];
    if (NULL == pDrvDescPrivate)
    {
        dwRetVal = 0x9811000C; /* EC_E_NOTFOUND*/
        nRetVal = 0;
        goto Exit;
    }

    if (mutex_trylock(&pDrvDescPrivate->mdio_order_mutex))
    {
        bLocked = true;
        if ((pDrvDescPrivate->MdioOrder.bInUse) && (pDrvDescPrivate->MdioOrder.bInUseByIoctl))
        {
            nRes = put_user(pDrvDescPrivate->MdioOrder.bInUse, &pOrderUserSpace->bInUse);
            if (0 != nRes) { nRetVal = nRes; goto Exit; }

            nRes = put_user(pDrvDescPrivate->MdioOrder.bInUseByIoctl,&pOrderUserSpace->bInUseByIoctl);
            if (0 != nRes) { nRetVal = nRes; goto Exit; }

            nRes = put_user(pDrvDescPrivate->MdioOrder.bWriteOrder, &pOrderUserSpace->bWriteOrder);
            if (0 != nRes) { nRetVal = nRes; goto Exit; }

            nRes = put_user(pDrvDescPrivate->MdioOrder.wMdioAddr, &pOrderUserSpace->wMdioAddr);
            if (0 != nRes) { nRetVal = nRes; goto Exit; }

            nRes = put_user(pDrvDescPrivate->MdioOrder.wReg, &pOrderUserSpace->wReg);
            if (0 != nRes) { nRetVal = nRes; goto Exit; }

            nRes = put_user(pDrvDescPrivate->MdioOrder.wValue, &pOrderUserSpace->wValue);
            if (0 != nRes) { nRetVal = nRes; goto Exit; }
        }
    }
    dwRetVal = 0; /* EC_E_NOERROR*/
    nRetVal = 0;

Exit:
    if (bLocked)
    {
        mutex_unlock(&pDrvDescPrivate->mdio_order_mutex);
    }
    if (0 == nRetVal)
    {
        put_user(dwRetVal, &pOrderUserSpace->dwErrorCode);
    }
    else
    {
        put_user(0x98110000 /* EC_E_ERROR */, &pOrderUserSpace->dwErrorCode);
    }

    return nRetVal;
}

static int ReturnMdioOrderIoctl( unsigned long ioctlParam)
{
    ATEMSYS_T_DRV_DESC_PRIVATE* pDrvDescPrivate = NULL;
    ATEMSYS_T_MDIO_ORDER* pOrderUserSpace = (ATEMSYS_T_MDIO_ORDER*)ioctlParam;
    unsigned int dwIndex = 0;
    __u16 wValue = 0;
    unsigned int dwRetVal = 0;
    int nRetVal = -1;
    int nRes = -1;

    nRes = get_user(dwIndex, &pOrderUserSpace->dwIndex);
    if (0 != nRes) { nRetVal = nRes; goto Exit; }

    if (dwIndex >= ATEMSYS_MAX_NUMBER_DRV_INSTANCES)
    {
        dwRetVal =  0x98110002; /* EC_E_INVALIDINDEX */
        nRetVal = 0;
        goto Exit;
    }
    pDrvDescPrivate = S_apDrvDescPrivate[dwIndex];
    if (NULL == pDrvDescPrivate)
    {
        dwRetVal = 0x9811000C; /* EC_E_NOTFOUND*/
        nRetVal = 0;
        goto Exit;
    }

    nRes = get_user(wValue, &pOrderUserSpace->wValue);
    if (0 != nRes) { nRetVal = nRes; goto Exit; }

    mutex_lock(&pDrvDescPrivate->mdio_order_mutex);
    pDrvDescPrivate->MdioOrder.wValue = wValue;
    pDrvDescPrivate->MdioOrder.bInUseByIoctl = false;
    mutex_unlock(&pDrvDescPrivate->mdio_order_mutex);

    /* wake MdioRead or MdioWrite */
    pDrvDescPrivate->mdio_wait_queue_cnt = 1;
    wake_up_interruptible(&pDrvDescPrivate->mdio_wait_queue);

    dwRetVal = 0 /* EC_E_NOERROR*/;
    nRetVal = 0;

Exit:
    if (0 == nRetVal)
    {
        put_user(dwRetVal, &pOrderUserSpace->dwErrorCode);
    }
    else
    {
        put_user(0x98110000 /* EC_E_ERROR */, &pOrderUserSpace->dwErrorCode);
    }

    return nRetVal;
}

static int GetPhyInfoIoctl(unsigned long ioctlParam)
{
    ATEMSYS_T_DRV_DESC_PRIVATE* pDrvDescPrivate  = NULL;
    ATEMSYS_T_PHY_INFO* pStatusUserSpace = (ATEMSYS_T_PHY_INFO *)ioctlParam;
    unsigned int dwIndex = 0;
    unsigned int dwRetVal = 0;
    int nRetVal = -1;
    int nRes = -1;

    nRes = get_user(dwIndex, &pStatusUserSpace->dwIndex);
    if (0 != nRes) { nRetVal = nRes; goto Exit; }

    if (dwIndex >= ATEMSYS_MAX_NUMBER_DRV_INSTANCES)
    {
        dwRetVal = 0x98110002; /* EC_E_INVALIDINDEX */
        nRetVal = 0;
        goto Exit;
    }
    pDrvDescPrivate = S_apDrvDescPrivate[dwIndex];
    if (NULL == pDrvDescPrivate)
    {
        dwRetVal = 0x9811000C; /* EC_E_NOTFOUND*/
        nRetVal = 0;
        goto Exit;
    }

    nRes = put_user(pDrvDescPrivate->PhyInfo.dwLink, &pStatusUserSpace->dwLink);
    if (0 != nRes) { nRetVal = nRes; goto Exit; }

    nRes = put_user(pDrvDescPrivate->PhyInfo.dwDuplex, &pStatusUserSpace->dwDuplex);
    if (0 != nRes) { nRetVal = nRes; goto Exit; }

    nRes = put_user(pDrvDescPrivate->PhyInfo.dwSpeed, &pStatusUserSpace->dwSpeed);
    if (0 != nRes) { nRetVal = nRes; goto Exit; }

    nRes = put_user(pDrvDescPrivate->PhyInfo.bPhyReady, &pStatusUserSpace->bPhyReady);
    if (0 != nRes) { nRetVal = nRes; goto Exit; }

    dwRetVal = 0; /* EC_E_NOERROR */
    nRetVal = 0;

Exit:
    if (0 == nRetVal)
    {
        put_user(dwRetVal, &pStatusUserSpace->dwErrorCode);
    }
    else
    {
        put_user(0x98110000 /* EC_E_ERROR */, &pStatusUserSpace->dwErrorCode);
    }

    return nRetVal;
}

static void UpdatePhyInfoByLinuxPhyDriver(struct net_device *ndev)
{
    struct phy_device* phy_dev = ndev->phydev;
    ATEMSYS_T_DRV_DESC_PRIVATE* pDrvDescPrivate = netdev_priv(ndev);

    if (LOGLEVEL_DEBUG <= loglevel)
    {
        phy_print_status(phy_dev);
    }

    pDrvDescPrivate->PhyInfo.dwLink = phy_dev->link;
    pDrvDescPrivate->PhyInfo.dwDuplex = phy_dev->duplex;
    pDrvDescPrivate->PhyInfo.dwSpeed = phy_dev->speed;
    pDrvDescPrivate->PhyInfo.bPhyReady = true;
}

static int MdioProbe(struct net_device *ndev)
{
    ATEMSYS_T_DRV_DESC_PRIVATE* pDrvDescPrivate = netdev_priv(ndev);
    struct phy_device* pPhyDev = NULL;
    char mdio_bus_id[MII_BUS_ID_SIZE];
    char phy_name[MII_BUS_ID_SIZE + 3];
    int nPhy_id = 0;

    if (NULL != pDrvDescPrivate->pPhyNode)
    {
        pPhyDev = of_phy_connect(ndev, pDrvDescPrivate->pPhyNode,
                     &UpdatePhyInfoByLinuxPhyDriver, 0,
                     pDrvDescPrivate->PhyInterface);
    }
    else if (NULL != pDrvDescPrivate->pMdioBus)
    {
        int nDev_id = pDrvDescPrivate->nDev_id;
        /* check for attached phy */
        for (nPhy_id = 0; (nPhy_id < PHY_MAX_ADDR); nPhy_id++)
        {
            if (!mdiobus_is_registered_device(pDrvDescPrivate->pMdioBus, nPhy_id))
            {
                continue;
            }
            if (0 != nDev_id--)
            {
                continue;
            }
            strlcpy(mdio_bus_id, pDrvDescPrivate->pMdioBus->id, MII_BUS_ID_SIZE);
            break;
        }

        if (nPhy_id >= PHY_MAX_ADDR)
        {
            INF("%s: no PHY, assuming direct connection to switch\n", pDrvDescPrivate->pPDev->name);
            strlcpy(mdio_bus_id, "fixed-0", MII_BUS_ID_SIZE);
            nPhy_id = 0;
        }

        snprintf(phy_name, sizeof(phy_name), PHY_ID_FMT, mdio_bus_id, nPhy_id);
        pPhyDev = phy_connect(ndev, phy_name, &UpdatePhyInfoByLinuxPhyDriver, pDrvDescPrivate->PhyInterface);
    }

    if ((NULL == pPhyDev) || IS_ERR(pPhyDev))
    {
        ERR("%s: Could not attach to PHY (pPhyDev %p)\n", pDrvDescPrivate->pPDev->name, pPhyDev);
        return -ENODEV;
    }

    /* adjust maximal link speed */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,0,0))
    phy_set_max_speed(pPhyDev, 100);
#else
    pPhyDev->supported &= PHY_BASIC_FEATURES;
    pPhyDev->advertising = pPhyDev->supported;
#endif
    if (LOGLEVEL_INFO <= loglevel)
    {
        phy_attached_info(pPhyDev);
    }

    pDrvDescPrivate->pPhyDev = pPhyDev;
    pDrvDescPrivate->PhyInfo.dwLink = 0;
    pDrvDescPrivate->PhyInfo.dwDuplex = 0;
    pDrvDescPrivate->PhyInfo.dwSpeed = 0;

    return 0;
}

static int MdioRead(struct mii_bus *pBus, int mii_id, int regnum)
{
    ATEMSYS_T_DRV_DESC_PRIVATE* pDrvDescPrivate = pBus->priv;
    int nRetVal = -1;
    int nRes = -1;

    nRes = pm_runtime_get_sync(&pDrvDescPrivate->pPDev->dev);
    if (0 > nRes)
    {
        return nRes;
    }

    /* get lock for the Mdio bus only one MdioRead or MdioWrite*/
    mutex_lock(&pDrvDescPrivate->mdio_mutex);

    mutex_lock(&pDrvDescPrivate->mdio_order_mutex);
    memset(&pDrvDescPrivate->MdioOrder, 0, sizeof(ATEMSYS_T_MDIO_ORDER));
    pDrvDescPrivate->MdioOrder.bInUse = true;
    pDrvDescPrivate->MdioOrder.bInUseByIoctl = true;
    pDrvDescPrivate->MdioOrder.bWriteOrder = false;
    pDrvDescPrivate->MdioOrder.wMdioAddr = (__u16)mii_id;
    pDrvDescPrivate->MdioOrder.wReg = (__u16)regnum;
    mutex_unlock(&pDrvDescPrivate->mdio_order_mutex);

    /* wait for result */
    wait_event_interruptible(pDrvDescPrivate->mdio_wait_queue, pDrvDescPrivate->mdio_wait_queue_cnt != 0);
    pDrvDescPrivate->mdio_wait_queue_cnt = pDrvDescPrivate->mdio_wait_queue_cnt - 1;

    nRetVal = pDrvDescPrivate->MdioOrder.wValue;

    mutex_lock(&pDrvDescPrivate->mdio_order_mutex);
    pDrvDescPrivate->MdioOrder.bInUse = false;
    pDrvDescPrivate->MdioOrder.bInUseByIoctl = false;
    mutex_unlock(&pDrvDescPrivate->mdio_order_mutex);

    pm_runtime_mark_last_busy(&pDrvDescPrivate->pPDev->dev);
    pm_runtime_put_autosuspend(&pDrvDescPrivate->pPDev->dev);

    mutex_unlock(&pDrvDescPrivate->mdio_mutex);

    return nRetVal;
}

static int MdioWrite(struct mii_bus *pBus, int mii_id, int regnum, u16 value)
{
    ATEMSYS_T_DRV_DESC_PRIVATE* pDrvDescPrivate = pBus->priv;
    int nRetVal;

    nRetVal = pm_runtime_get_sync(&pDrvDescPrivate->pPDev->dev);
    if (0 > nRetVal)
    {
        return nRetVal;
    }

    /* get lock for the Mdio bus only one MdioRead or MdioWrite*/
    mutex_lock(&pDrvDescPrivate->mdio_mutex);

    mutex_lock(&pDrvDescPrivate->mdio_order_mutex);
    memset(&pDrvDescPrivate->MdioOrder, 0, sizeof(ATEMSYS_T_MDIO_ORDER));
    pDrvDescPrivate->MdioOrder.bInUse = true;
    pDrvDescPrivate->MdioOrder.bInUseByIoctl = true;
    pDrvDescPrivate->MdioOrder.bWriteOrder = true;
    pDrvDescPrivate->MdioOrder.wMdioAddr = (__u16)mii_id;
    pDrvDescPrivate->MdioOrder.wReg = (__u16)regnum;
    pDrvDescPrivate->MdioOrder.wValue = (__u16)value;
    mutex_unlock(&pDrvDescPrivate->mdio_order_mutex);

    /* wait for result */
    wait_event_interruptible(pDrvDescPrivate->mdio_wait_queue, pDrvDescPrivate->mdio_wait_queue_cnt != 0);
    pDrvDescPrivate->mdio_wait_queue_cnt = pDrvDescPrivate->mdio_wait_queue_cnt - 1;

    nRetVal = 0;

    mutex_lock(&pDrvDescPrivate->mdio_order_mutex);
    pDrvDescPrivate->MdioOrder.bInUse = false;
    pDrvDescPrivate->MdioOrder.bInUseByIoctl = false;
    mutex_unlock(&pDrvDescPrivate->mdio_order_mutex);

    pm_runtime_mark_last_busy(&pDrvDescPrivate->pPDev->dev);
    pm_runtime_put_autosuspend(&pDrvDescPrivate->pPDev->dev);

    mutex_unlock(&pDrvDescPrivate->mdio_mutex);

    return nRetVal;
}

static int MdioInit(struct platform_device *pPDev)
{
    struct net_device* pNDev = platform_get_drvdata(pPDev);
    ATEMSYS_T_DRV_DESC_PRIVATE* pDrvDescPrivate = netdev_priv(pNDev);
    struct device_node* pDevNode;
    int nRes = -ENXIO;

    if (pDrvDescPrivate->MacInfo.bNoMdioBus)
    {
        pDrvDescPrivate->pMdioBus = NULL;
        nRes = 0;
        goto Exit;
    }

    pDrvDescPrivate->pMdioBus = mdiobus_alloc();
    if (NULL == pDrvDescPrivate->pMdioBus)
    {
        nRes = -ENOMEM;
        goto Exit;
    }

    pDrvDescPrivate->pMdioBus->name = "atemsys_mdio_bus";
    pDrvDescPrivate->pMdioBus->read = &MdioRead;
    pDrvDescPrivate->pMdioBus->write = &MdioWrite;
    snprintf(pDrvDescPrivate->pMdioBus->id, MII_BUS_ID_SIZE, "%s-%x", pPDev->name, pDrvDescPrivate->nDev_id + 1);
    pDrvDescPrivate->pMdioBus->priv = pDrvDescPrivate;
    pDrvDescPrivate->pMdioBus->parent = &pPDev->dev;

    pDevNode = of_get_child_by_name(pDrvDescPrivate->pDevNode, "mdio");
    if (NULL == pDevNode) {pDevNode = of_get_child_by_name(pDrvDescPrivate->pDevNode, "mdio0");}
    if (NULL == pDevNode) {pDevNode = of_get_child_by_name(pDrvDescPrivate->pDevNode, "phy");}
    if (NULL == pDevNode) {pDevNode = of_get_child_by_name(pDrvDescPrivate->pDevNode, "ethernet-phy");}
    if (NULL != pDevNode)
    {
        nRes = of_mdiobus_register(pDrvDescPrivate->pMdioBus, pDevNode);
        of_node_put(pDevNode);
    }
    else
    {
        if (NULL == pDrvDescPrivate->pPhyNode)
        {
            nRes = mdiobus_register(pDrvDescPrivate->pMdioBus);
        }
        else
        {
            /* no Mdio sub-node use main node */
            nRes = of_mdiobus_register(pDrvDescPrivate->pMdioBus, pDrvDescPrivate->pDevNode);
        }
    }
    if (0 != nRes)
    {
        mdiobus_free(pDrvDescPrivate->pMdioBus);
    }

Exit:
    return nRes;
}


static int StopPhy(struct platform_device *pPDev)
{
    struct net_device* pNDev = platform_get_drvdata(pPDev);
    ATEMSYS_T_DRV_DESC_PRIVATE* pDrvDescPrivate = netdev_priv(pNDev);

    /* phy */
    if (NULL != pDrvDescPrivate->pPhyDev)
    {
        phy_stop(pDrvDescPrivate->pPhyDev);
        phy_disconnect(pDrvDescPrivate->pPhyDev);
        pDrvDescPrivate->pPhyDev = NULL;
    }

    /* mdio bus */
    if (NULL != pDrvDescPrivate->pMdioBus)
    {
        mdiobus_unregister(pDrvDescPrivate->pMdioBus);
        mdiobus_free(pDrvDescPrivate->pMdioBus);
        pDrvDescPrivate->pMdioBus = NULL;
    }

    pDrvDescPrivate->PhyInfo.bPhyReady = false;
    pDrvDescPrivate->mdio_wait_queue_cnt = 0;

    return 0;
}

static int StartPhy(struct platform_device *pPDev)
{
    struct net_device* pNDev = platform_get_drvdata(pPDev);
    ATEMSYS_T_DRV_DESC_PRIVATE* pDrvDescPrivate = netdev_priv(pNDev);
    int nRes = -1;

    if ((NULL != pDrvDescPrivate->pPhyDev) || (NULL != pDrvDescPrivate->pMdioBus))
    {
        StopPhy(pPDev);
    }

    /* mdio bus */
    nRes = MdioInit(pPDev);
    if (0 != nRes)
    {
        pDrvDescPrivate->pMdioBus = NULL;
    }
    nRes = MdioProbe(pNDev);
    if (0 != nRes)
    {
        return nRes;
    }
    /* phy */
    phy_start(pDrvDescPrivate->pPhyDev);
    phy_start_aneg(pDrvDescPrivate->pPhyDev);

    return 0;
}

static int StartPhyThread(void *data)
{
    struct platform_device *pPDev = (struct platform_device *)data;

    StartPhy(pPDev);

    return 0;
}

static int StopPhyThread(void *data)
{
    struct platform_device *pPDev = (struct platform_device *)data;

    StopPhy(pPDev);

    return 0;
}

static int StopPhyWithoutIoctlMdioHandling(struct platform_device *pPDev)
{
    struct net_device* pNDev = platform_get_drvdata(pPDev);
    ATEMSYS_T_DRV_DESC_PRIVATE* pDrvDescPrivate = netdev_priv(pNDev);

    /* start StopPhy as thread */
    pDrvDescPrivate->etx_thread_StopPhy = kthread_create(StopPhyThread,(void*)pDrvDescPrivate->pPDev,"StopPhyThread");
    if(NULL == pDrvDescPrivate->etx_thread_StopPhy)
    {
        ERR("Cannot create kthread for StopPhyThread\n");
        return -1;
    }
    wake_up_process(pDrvDescPrivate->etx_thread_StopPhy);

    /* trigger event to continue MdioRead and MdioWrite */
    /* MdioRead returns always 0 */
    pDrvDescPrivate->mdio_wait_queue_cnt = 1000; // wait will be skipped 1000 times
    wake_up_interruptible(&pDrvDescPrivate->mdio_wait_queue);

    return 0;
}

static struct device_node * findDeviceTreeNode(struct platform_device *pPDev)
{
    int                    nTimeout;
    unsigned int           dwRegAddr32;
    long long unsigned int qwRegAddr64;
    char                   aBuff[32] = {0};
    struct device_node     *pDevNode;

    pDevNode = NULL;
    nTimeout = 100;
    while(0 < nTimeout)
    {
        pDevNode = of_find_node_by_name(pDevNode, "ethernet");
        if (NULL == pDevNode)
            break;

        of_property_read_u32(pDevNode, "reg", &dwRegAddr32);
        of_property_read_u64(pDevNode, "reg", &qwRegAddr64);

        sprintf(aBuff, "%x.ethernet", dwRegAddr32);
        if (strcmp(pPDev->name, aBuff) == 0) break;

        sprintf(aBuff, "%x.ethernet", (unsigned int)qwRegAddr64);
        if (strcmp(pPDev->name, aBuff) == 0) break;

        nTimeout--;
    }
    if (0 == nTimeout)
        pDevNode = NULL;

    return pDevNode;
}

static int EthernetDriverProbe(struct platform_device *pPDev)
{
    ATEMSYS_T_DRV_DESC_PRIVATE* pDrvDescPrivate = NULL;
    struct net_device* pNDev = NULL;
    const struct of_device_id* pOf_id = NULL;
    static int nDev_id = 0;
    unsigned int dwIndex = 0;
    int nRes = 0;
    struct device_node* pDevNode = NULL;

    INF("Atemsys: Probe device: %s\n", pPDev->name);

    pDevNode = pPDev->dev.of_node;
    if (NULL == pDevNode)
    {
        struct device_node* pDevNodeNew = NULL;
        WRN("%s: Device node empty\n", pPDev->name);

        pDevNodeNew = findDeviceTreeNode(pPDev);
        if (NULL == pDevNodeNew)
        {
            ERR("%s: Device node not found\n", pPDev->name);
            return -ENODATA;
        }
        else
        {
            pDevNode = pDevNodeNew;
        }
    }

    /* Init network device */
    pNDev = alloc_etherdev_mqs(sizeof(ATEMSYS_T_DRV_DESC_PRIVATE), 1 , 1); /* No TX and RX queues requiered */
    if (NULL == pNDev)
    {
        return -ENOMEM;
    }
    SET_NETDEV_DEV(pNDev, &pPDev->dev);

    /* setup board info structure */
    pOf_id = of_match_device(atemsys_ids, &pPDev->dev);
    if (NULL != pOf_id)
    {
        pPDev->id_entry = pOf_id->data;
    }

    pDrvDescPrivate = netdev_priv(pNDev);
    memset(pDrvDescPrivate, 0, sizeof(ATEMSYS_T_DRV_DESC_PRIVATE));
    pDrvDescPrivate->pPDev = pPDev;
    pDrvDescPrivate->nDev_id  = nDev_id++;
    platform_set_drvdata(pPDev, pNDev);
    pDrvDescPrivate->netdev = pNDev;
    pDrvDescPrivate->pDevNode = pDevNode;

    /* Select default pin state */
    pinctrl_pm_select_default_state(&pPDev->dev);

    /* enable clock */
    pDrvDescPrivate->nCountClk = of_property_count_strings(pDevNode,"clock-names");
    if (0 > pDrvDescPrivate->nCountClk)
    {
        pDrvDescPrivate->nCountClk = 0;
    }
    DBG("%s: found %d Clocks\n", pPDev->name , pDrvDescPrivate->nCountClk);

    for (dwIndex = 0; dwIndex < pDrvDescPrivate->nCountClk; dwIndex++)
    {
        if(!of_property_read_string_index(pDevNode, "clock-names", dwIndex, &pDrvDescPrivate->clk_ids[dwIndex]))
        {
            pDrvDescPrivate->clks[dwIndex] = devm_clk_get(&pPDev->dev, pDrvDescPrivate->clk_ids[dwIndex]);
            if (!IS_ERR(pDrvDescPrivate->clks[dwIndex]))
            {
                clk_prepare_enable(pDrvDescPrivate->clks[dwIndex]);
                DBG("%s: Clock %s enabled\n", pPDev->name, pDrvDescPrivate->clk_ids[dwIndex]);
            }
            else
            {
                pDrvDescPrivate->clks[dwIndex] = NULL;
            }
        }
    }

    /* enable PHY regulator*/
    pDrvDescPrivate->pPhyRegulator = devm_regulator_get(&pPDev->dev, "phy");
    if (!IS_ERR(pDrvDescPrivate->pPhyRegulator))
    {
        if (regulator_enable(pDrvDescPrivate->pPhyRegulator))
        {
            WRN("%s: can't enable PHY regulator!\n", pPDev->name);
        }
    }
    else
    {
        pDrvDescPrivate->pPhyRegulator = NULL;
    }

    /* Device run-time power management */
    pm_runtime_dont_use_autosuspend(&pPDev->dev);
    pm_runtime_get_noresume(&pPDev->dev);
    pm_runtime_set_active(&pPDev->dev);
    pm_runtime_enable(&pPDev->dev);

    /* get prepare data for atemsys and print some data to kernel log */
    {
        unsigned int    dwTemp          = 0;
        const char     *szTempString    = NULL;
        unsigned int    adwTempValues[6];

        /* get identification */
        nRes = of_property_read_string(pDevNode, "atemsys-Ident", &szTempString);
        if ((0 == nRes) && (NULL != szTempString))
        {
            INF("%s: atemsys-Ident: %s\n", pPDev->name, szTempString);
            memcpy(pDrvDescPrivate->MacInfo.szIdent,szTempString, EC_LINKOS_IDENT_MAX_LEN);
        }
        else
        {
            INF("%s: Missing atemsys-Ident in the Device Tree\n", pPDev->name);
        }

        /* get instance number */
        nRes = of_property_read_u32(pDevNode, "atemsys-Instance", &dwTemp);
        if (0 == nRes)
        {
            INF("%s: atemsys-Instance: %d\n", pPDev->name , dwTemp);
            pDrvDescPrivate->MacInfo.dwInstance = dwTemp;
        }
        else
        {
            pDrvDescPrivate->MacInfo.dwInstance = 0;
            INF("%s: Missing atemsys-Instance in the Device Tree\n", pPDev->name);
        }

        /* status */
        szTempString = NULL;
        nRes = of_property_read_string(pDevNode, "status", &szTempString);
        if ((0 == nRes) && (NULL != szTempString))
        {
            DBG("%s: status: %s\n", pPDev->name , szTempString);
            pDrvDescPrivate->MacInfo.dwStatus = (strcmp(szTempString, "okay")==0)? 1:0;
        }

        /* interrupt-parent */
        nRes = of_property_read_u32(pDevNode, "interrupt-parent", &dwTemp);
        if (0 == nRes)
        {
            DBG("%s: interrupt-parent: %d\n", pPDev->name , dwTemp);
        }

        /* interrupts */
        nRes = of_property_read_u32_array(pDevNode, "interrupts", adwTempValues, 6);
        if (0 == nRes)
        {
            DBG("%s: interrupts: 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x\n", pPDev->name ,
                adwTempValues[0], adwTempValues[1], adwTempValues[2], adwTempValues[3], adwTempValues[4], adwTempValues[5]);
        }

        /* reg */
#if (defined __arm__)
        nRes = of_property_read_u32_array(pDevNode, "reg", adwTempValues, 2);
        if (0 == nRes)
        {
            DBG("%s: reg: 0x%x 0x%x\n", pPDev->name , adwTempValues[0], adwTempValues[1]);
            pDrvDescPrivate->MacInfo.qwRegAddr = adwTempValues[0];
            pDrvDescPrivate->MacInfo.dwRegSize = adwTempValues[1];
        }
#endif

        /* get phy-mode */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,5,0))
        nRes = of_get_phy_mode(pPDev->dev.of_node, &pDrvDescPrivate->PhyInterface);
#else
        pDrvDescPrivate->PhyInterface = of_get_phy_mode(pPDev->dev.of_node);
#endif
        switch (pDrvDescPrivate->PhyInterface)
        {
            case PHY_INTERFACE_MODE_MII:
            {
                INF("%s: phy-mode: MII\n", pPDev->name);
                pDrvDescPrivate->MacInfo.ePhyMode = eATEMSYS_PHY_MII;
            } break;
            case PHY_INTERFACE_MODE_RMII:
            {
                INF("%s: phy-mode: RMII\n", pPDev->name);
                pDrvDescPrivate->MacInfo.ePhyMode = eATEMSYS_PHY_RMII;
            } break;
            case PHY_INTERFACE_MODE_GMII:
            {
                INF("%s: phy-mode: GMII\n", pPDev->name);
                pDrvDescPrivate->MacInfo.ePhyMode = eATEMSYS_PHY_GMII;
            } break;
            case PHY_INTERFACE_MODE_SGMII:
            {
                INF("%s: phy-mode: SGMII\n", pPDev->name);
                pDrvDescPrivate->MacInfo.ePhyMode = eATEMSYS_PHY_SGMII;
            } break;
            case PHY_INTERFACE_MODE_RGMII_ID:
            case PHY_INTERFACE_MODE_RGMII_RXID:
            case PHY_INTERFACE_MODE_RGMII_TXID:
            case PHY_INTERFACE_MODE_RGMII:
            {
                INF("%s: phy-mode: RGMII\n", pPDev->name);
                pDrvDescPrivate->MacInfo.ePhyMode = eATEMSYS_PHY_RGMII;
            } break;
            default:
            {
                pDrvDescPrivate->MacInfo.ePhyMode = eATEMSYS_PHY_RGMII;
                pDrvDescPrivate->PhyInterface = PHY_INTERFACE_MODE_RGMII;
                WRN("%s: Missing phy-mode in the Device Tree, using RGMII\n", pPDev->name);
            }
        }

        /* pinctrl-names */
        szTempString = NULL;
        nRes = of_property_read_string(pDevNode, "pinctrl-names", &szTempString);
        if ((0 == nRes) && (NULL != szTempString))
        {
            DBG("%s: pinctrl-names: %s\n", pPDev->name , szTempString);
        }

        /* PHY address*/
        pDrvDescPrivate->MacInfo.dwPhyAddr = PHY_AUTO_ADDR;
        pDrvDescPrivate->pPhyNode = of_parse_phandle(pDevNode, "phy-handle", 0);
        if (NULL != pDrvDescPrivate->pPhyNode)
        {
            nRes = of_property_read_u32(pDrvDescPrivate->pPhyNode, "reg", &dwTemp);
            if (0 == nRes)
            {
                INF("%s: PHY mdio addr: %d\n", pPDev->name , dwTemp);
                pDrvDescPrivate->MacInfo.dwPhyAddr = dwTemp;
            }
        }
        else
        {
            INF("%s: Missing phy-handle in the Device Tree\n", pPDev->name);
        }

        /* look for mdio node */
        if ((NULL == of_get_child_by_name(pDevNode, "mdio"))    &&
            (NULL == of_get_child_by_name(pDevNode, "mdio0"))   &&
            (NULL == of_get_child_by_name(pDevNode, "phy"))     &&
            (NULL == of_get_child_by_name(pDevNode, "ethernet-phy")))
        {
            if (NULL != pDrvDescPrivate->pPhyNode)
            {
                /* mdio bus owned by another mac instance */
                pDrvDescPrivate->MacInfo.bNoMdioBus = true;
                INF("%s: mac has no mdio bus, uses mdio bus of other instance.\n", pPDev->name );
            }
            else
            {
                /* legacy mode: no node for mdio bus in device tree defined */
                pDrvDescPrivate->MacInfo.bNoMdioBus = false;
                INF("%s: handle mdio bus without device tree node.\n", pPDev->name );
            }
        }
        else
        {
            /* mdio bus is owned by current mac instance */
            pDrvDescPrivate->MacInfo.bNoMdioBus = false;
            DBG("%s: mac has mdio bus.\n", pPDev->name );
        }
    }

    /* insert device to array */
    for (dwIndex = 0; dwIndex < ATEMSYS_MAX_NUMBER_DRV_INSTANCES; dwIndex++)
    {
        if (NULL == S_apDrvDescPrivate[dwIndex])
        {
            S_apDrvDescPrivate[dwIndex] = pDrvDescPrivate;
            pDrvDescPrivate->MacInfo.dwIndex =  dwIndex;
            break;
        }
    }
    if (dwIndex >= ATEMSYS_MAX_NUMBER_DRV_INSTANCES)
    {
        ERR("%s: Maximum number of instances exceeded!\n", pPDev->name);
        return EthernetDriverRemove(pPDev);
    }

    /* start drivers of sub-nodes */
    if (strcmp(pDrvDescPrivate->MacInfo.szIdent, "CPSW") == 0
       || strcmp(pDrvDescPrivate->MacInfo.szIdent, "ICSS") == 0)
    {
        of_platform_populate(pDevNode, NULL, NULL, &pPDev->dev);
        DBG("%s: start drivers of sub-nodes.\n", pPDev->name );
    }

    /* prepare mutex for mdio */
    mutex_init(&pDrvDescPrivate->mdio_mutex);
    mutex_init(&pDrvDescPrivate->mdio_order_mutex);
    init_waitqueue_head(&pDrvDescPrivate->mdio_wait_queue);
    pDrvDescPrivate->mdio_wait_queue_cnt = 0;

    return 0;
}


static int EthernetDriverRemove(struct platform_device *pPDev)
{
    struct net_device* pNDev = platform_get_drvdata(pPDev);
    ATEMSYS_T_DRV_DESC_PRIVATE* pDrvDescPrivate = netdev_priv(pNDev);
    unsigned int i = 0;

    if ((NULL != pDrvDescPrivate->pPhyDev) || (NULL != pDrvDescPrivate->pMdioBus))
    {
        ERR("%s: EthernetDriverRemove: PHY driver is still active!\n", pPDev->name);
    }

    if (NULL != pDrvDescPrivate->pPhyRegulator)
    {
        regulator_disable(pDrvDescPrivate->pPhyRegulator);
    }

    /* Decrement refcount */
    of_node_put(pDrvDescPrivate->pPhyNode);

    pm_runtime_put(&pPDev->dev);
    pm_runtime_disable(&pPDev->dev);

    for (i = 0; i < ATEMSYS_MAX_NUMBER_OF_CLOCKS; i++)
    {
        if (NULL != pDrvDescPrivate->clk_ids[i])
        {
            clk_disable_unprepare(pDrvDescPrivate->clks[i]);
            DBG("%s: Clock %s unprepared\n", pPDev->name, pDrvDescPrivate->clk_ids[i]);
        }
    }

    pinctrl_pm_select_sleep_state(&pPDev->dev);

    free_netdev(pNDev);

    INF("%s: atemsys driver removed: %s Instance %d\n", pPDev->name, pDrvDescPrivate->MacInfo.szIdent, pDrvDescPrivate->MacInfo.dwInstance);

    S_apDrvDescPrivate[pDrvDescPrivate->MacInfo.dwIndex] = NULL;

    if (NULL != pDrvDescPrivate->pDevDesc)
    {
        pDrvDescPrivate->pDevDesc->pPlatformDev = NULL;
        pDrvDescPrivate->pDevDesc->pDrvDesc     = NULL;
        pDrvDescPrivate->pDevDesc               = NULL;
    }

    return 0;
}

static int CleanUpEthernetDriverOnRelease(ATEMSYS_T_DEVICE_DESC* pDevDesc)
{
    ATEMSYS_T_DRV_DESC_PRIVATE* pDrvDescPrivate = NULL;
    unsigned int i = 0;

    if (pDevDesc == NULL)
    {
        return 0;
    }

    for (i = 0; i < ATEMSYS_MAX_NUMBER_DRV_INSTANCES; i++)
    {

        pDrvDescPrivate = S_apDrvDescPrivate[i];
        if (NULL == pDrvDescPrivate)
        {
            continue;
        }

        if (pDrvDescPrivate->pDevDesc == pDevDesc)
        {
            INF("%s: Cleanup: pDevDesc = 0x%px\n", pDrvDescPrivate->pPDev->name, pDevDesc);

            /* ensure mdio bus and PHY are down */
            if ((NULL != pDrvDescPrivate->pPhyDev) || (NULL != pDrvDescPrivate->pMdioBus))
            {
                StopPhyWithoutIoctlMdioHandling(pDrvDescPrivate->pPDev);
            }
            /* clean descriptor */
            pDrvDescPrivate->pDevDesc = NULL;
            pDevDesc->pPlatformDev    = NULL;
            pDevDesc->pDrvDesc        = NULL;
        }
    }

    return 0;
}

static struct platform_device_id mac_devtype[] = {
    {
        .name = ATEMSYS_DT_DRIVER_NAME,
        .driver_data = 0,
    }, {
        /* sentinel */
    }
};


MODULE_DEVICE_TABLE(platform, mac_devtype);

static struct platform_driver mac_driver = {
    .driver    = {
        .name           = ATEMSYS_DT_DRIVER_NAME,
        .of_match_table = atemsys_ids,
    },
    .id_table  = mac_devtype,
    .probe     = EthernetDriverProbe,
    .remove    = EthernetDriverRemove,
};
#endif /* INCLUDE_ATEMSYS_DT_DRIVER */


#if (defined INCLUDE_ATEMSYS_PCI_DRIVER)
#define ATEMSYS_PCI_DRIVER_NAME "atemsys_pci"
#define PCI_VENDOR_ID_BECKHOFF  0x15EC

static void PciDriverRemove(struct pci_dev *pPciDev)
{
    ATEMSYS_T_PCI_DRV_DESC_PRIVATE *pPciDrvDescPrivate = (ATEMSYS_T_PCI_DRV_DESC_PRIVATE *)pci_get_drvdata(pPciDev);

    if (NULL != pPciDrvDescPrivate)
    {
        /* remove references to the device */
        if (NULL != pPciDrvDescPrivate->pDevDesc)
        {
            pPciDrvDescPrivate->pDevDesc->pPcidev = NULL;
            pPciDrvDescPrivate->pDevDesc->pPciDrvDesc = NULL;
            pPciDrvDescPrivate->pDevDesc = NULL;
        }
        S_apPciDrvDescPrivate[pPciDrvDescPrivate->dwIndex] = NULL;

        kfree(pPciDrvDescPrivate);
    }

    /* disable device */
    pci_disable_msi(pPciDev);
    pci_release_regions(pPciDev);
    pci_disable_pcie_error_reporting(pPciDev);
    pci_disable_device(pPciDev);

    INF("%s: %s: disconnected\n", pci_name(pPciDev), ATEMSYS_PCI_DRIVER_NAME);
}

static int PciDriverProbe(struct pci_dev *pPciDev, const struct pci_device_id *id)
{
    ATEMSYS_T_PCI_DRV_DESC_PRIVATE *pPciDrvDescPrivate = NULL;
    int nRes = -1;
    int dwIndex = 0;

    /* check if Ethernet device */
    if ((PCI_BASE_CLASS_NETWORK != ((pPciDev->class >> 16) & 0xFF)) &&
        (PCI_VENDOR_ID_BECKHOFF != pPciDev->vendor))
    {
        ERR("%s: PciDriverProbe: No Ethenet device!\n", pci_name(pPciDev));
        /* don't attach driver */
        return -1;
    }

    /* setup pci device */
    nRes = pci_enable_device_mem(pPciDev);
    if (nRes)
    {
        ERR("%s: PciDriverProbe: pci_enable_device_mem failed!\n", pci_name(pPciDev));
        goto Exit;
    }

    nRes = DefaultPciSettings(pPciDev);
    if (nRes)
    {
        ERR("%s: PciDriverProbe: DefaultPciSettings failed\n", pci_name(pPciDev));
        goto Exit;
    }
    pci_save_state(pPciDev);
    pci_enable_pcie_error_reporting(pPciDev);
    nRes = pci_request_regions(pPciDev, ATEMSYS_DEVICE_NAME);
    if (nRes < 0)
    {
        ERR("%s: PciDriverProbe: device in use by another driver?\n", pci_name(pPciDev));
        nRes = -EBUSY;
        goto Exit;
    }

    /* create private desc */
    pPciDrvDescPrivate = (ATEMSYS_T_PCI_DRV_DESC_PRIVATE*)kzalloc(sizeof(ATEMSYS_T_PCI_DRV_DESC_PRIVATE), GFP_KERNEL);
    if (NULL == pPciDrvDescPrivate)
    {
        nRes = -ENOMEM;
        goto Exit;
    }
    pPciDrvDescPrivate->pPciDev = pPciDev;

    /* get Pci Info */
    pPciDrvDescPrivate->wVendorId         = pPciDev->vendor;
    pPciDrvDescPrivate->wDevice           = pPciDev->device;
    pPciDrvDescPrivate->wRevision         = pPciDev->revision;
    pPciDrvDescPrivate->wSubsystem_vendor = pPciDev->subsystem_vendor;
    pPciDrvDescPrivate->wSubsystem_device = pPciDev->subsystem_device;
    pPciDrvDescPrivate->nPciBus           = pPciDev->bus->number;
    pPciDrvDescPrivate->nPciDomain        = pci_domain_nr(pPciDev->bus);
    pPciDrvDescPrivate->nPciDev           = PCI_SLOT(pPciDev->devfn);
    pPciDrvDescPrivate->nPciFun           = PCI_FUNC(pPciDev->devfn);

    INF("%s: %s: connected vendor:0x%04x device:0x%04x rev:0x%02x - sub_vendor:0x%04x sub_device:0x%04x\n", pci_name(pPciDev), ATEMSYS_PCI_DRIVER_NAME,
            pPciDev->vendor, pPciDev->device, pPciDev->revision,
            pPciDev->subsystem_vendor, pPciDev->subsystem_device);

    /* find the memory BAR */
    {
       unsigned long ioBase  = 0;
       unsigned int  dwIOLen = 0;
       int i    = 0;
       int nBar = 0;

       for (i = 0; i < ATEMSYS_PCI_MAXBAR ; i++)
       {
          if (pci_resource_flags(pPciDev, i) & IORESOURCE_MEM)
          {
             /* IO area address */
             ioBase = pci_resource_start(pPciDev, i);
             pPciDrvDescPrivate->aBars[nBar].qwIOMem = ioBase;

             /* IO area length */
             dwIOLen = pci_resource_len(pPciDev, i);
             pPciDrvDescPrivate->aBars[nBar].dwIOLen = dwIOLen;

             nBar++;
          }
       }

       if (nBar == 0)
       {
          WRN("%s: PciDriverProbe: No memory BAR found\n", pci_name(pPciDev));
       }

       pPciDrvDescPrivate->nBarCnt = nBar;
    }

    /* insert device to array */
    for (dwIndex = 0; dwIndex < ATEMSYS_MAX_NUMBER_DRV_INSTANCES; dwIndex++)
    {
        if (NULL == S_apPciDrvDescPrivate[dwIndex])
        {
            S_apPciDrvDescPrivate[dwIndex] = pPciDrvDescPrivate;
            pPciDrvDescPrivate->dwIndex =  dwIndex;
            break;
        }
    }
    if (ATEMSYS_MAX_NUMBER_DRV_INSTANCES <= dwIndex)
    {
        ERR("%s: PciDriverProbe: insert device to array failed\n", pci_name(pPciDev));
        nRes = -EBUSY;
        goto Exit;
    }

    pci_set_drvdata(pPciDev, pPciDrvDescPrivate);

    nRes = 0; /* OK */
Exit:
    if (nRes != 0 /* OK */)
    {
        if (NULL != pPciDrvDescPrivate)
        {
            kfree(pPciDrvDescPrivate);
        }
    }
    return nRes;
}

typedef struct _ATEMSYS_PCI_INFO {
} ATEMSYS_PCI_INFO;

static const struct _ATEMSYS_PCI_INFO oAtemsysPciInfo = {
};

#define ATEMSYS_DEVICE(vendor_id, dev_id, info) {  \
            PCI_VDEVICE(vendor_id, dev_id),        \
            .driver_data = (kernel_ulong_t)&info   \
            }

static const struct pci_device_id pci_devtype[] = {
    ATEMSYS_DEVICE(INTEL,    PCI_ANY_ID, oAtemsysPciInfo), /* all intel    */
    ATEMSYS_DEVICE(REALTEK,  PCI_ANY_ID, oAtemsysPciInfo), /* all realtek  */
    ATEMSYS_DEVICE(BECKHOFF, PCI_ANY_ID, oAtemsysPciInfo), /* all beckhoff */
    {}
};

MODULE_DEVICE_TABLE(pci, pci_devtype);
static struct pci_driver oPciDriver = {
    .name     = ATEMSYS_PCI_DRIVER_NAME,
    .id_table = pci_devtype,
    .probe    = PciDriverProbe,
    .remove   = PciDriverRemove,
};

#endif /* (defined INCLUDE_ATEMSYS_PCI_DRIVER) */


/*
 * Initialize the module - Register the character device
 */
int init_module(void)
{
#if (defined CONFIG_XENO_COBALT)

    int major = rtdm_dev_register(&device);
    if (major < 0)
    {
        INF("Failed to register %s (err: %d)\n", device.label, major);
        return major;
    }
#else

    /* Register the character device */
    int major = register_chrdev(MAJOR_NUM, ATEMSYS_DEVICE_NAME, &Fops);
    if (major < 0)
    {
        INF("Failed to register %s (err: %d)\n",
               ATEMSYS_DEVICE_NAME, major);
        return major;
    }

    /* Register Pci and Platform Driver */
#if (defined INCLUDE_ATEMSYS_DT_DRIVER)
    memset(S_apDrvDescPrivate ,0, ATEMSYS_MAX_NUMBER_DRV_INSTANCES * sizeof(ATEMSYS_T_DRV_DESC_PRIVATE*));
    platform_driver_register(&mac_driver);
#endif

#if (defined INCLUDE_ATEMSYS_PCI_DRIVER)
    memset(S_apPciDrvDescPrivate ,0, ATEMSYS_MAX_NUMBER_DRV_INSTANCES * sizeof(ATEMSYS_T_PCI_DRV_DESC_PRIVATE*));
    if (0 != pci_register_driver(&oPciDriver))
    {
        INF("Register Atemsys PCI driver failed!\n");
    }
#endif

    S_pDevClass = class_create(THIS_MODULE, ATEMSYS_DEVICE_NAME);
    if (IS_ERR(S_pDevClass))
    {
        INF("class_create failed\n");
        return -1;
    }

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24))
    S_pDev = class_device_create(S_pDevClass, NULL, MKDEV(MAJOR_NUM, 0), NULL, ATEMSYS_DEVICE_NAME);
#else
    S_pDev = device_create(S_pDevClass, NULL, MKDEV(MAJOR_NUM, 0), NULL, ATEMSYS_DEVICE_NAME);
#endif

#if (defined __arm__) || (defined __aarch64__)
    {
        int nRetval = 0;
        S_pPlatformDev = platform_device_alloc("atemsys_PDev", MKDEV(MAJOR_NUM, 0));
        S_pPlatformDev->dev.parent = S_pDev;

        nRetval = platform_device_add(S_pPlatformDev);
        if (nRetval != 0) {
            ERR("platform_device_add failed. return=%d\n", nRetval);
        }

 #if (defined __arm__) || (defined CONFIG_ZONE_DMA32)
        S_pPlatformDev->dev.coherent_dma_mask = DMA_BIT_MASK(32);
        if (!S_pPlatformDev->dev.dma_mask)
        {
            S_pPlatformDev->dev.dma_mask = &S_pPlatformDev->dev.coherent_dma_mask;
        }
 #endif
    }
#else
    S_pPlatformDev = NULL;
#endif

    if (IS_ERR(S_pDev))
    {
        INF("device_create failed\n");
        return -1;
    }

    S_pDev->coherent_dma_mask = DMA_BIT_MASK(32);
    if (!S_pDev->dma_mask)
    {
        S_pDev->dma_mask = &S_pDev->coherent_dma_mask;
    }

#if (defined CONFIG_OF)
    OF_DMA_CONFIGURE(S_pDev,S_pDev->of_node);
#endif

    INIT_LIST_HEAD(&S_DevNode.list);

#endif /* CONFIG_XENO_COBALT */
    INF("%s v%s loaded\n", ATEMSYS_DEVICE_NAME, ATEMSYS_VERSION_STR);
    return 0;
}

/*
 * Cleanup - unregister the appropriate file from /proc
 */
void cleanup_module(void)
{
   INF("%s v%s unloaded\n", ATEMSYS_DEVICE_NAME, ATEMSYS_VERSION_STR);

    /* Unregister Pci and Platform Driver */
#if (defined INCLUDE_ATEMSYS_DT_DRIVER)
    platform_driver_unregister(&mac_driver);
#endif

#if (defined INCLUDE_ATEMSYS_PCI_DRIVER)
    pci_unregister_driver(&oPciDriver);
#endif

#if (defined __arm__) || (defined __aarch64__)
    if (NULL != S_pPlatformDev)
    {
        platform_device_del(S_pPlatformDev);
        platform_device_put(S_pPlatformDev);
        S_pPlatformDev = NULL;
    }
#endif

#if (defined CONFIG_OF)
   device_release_driver(S_pDev); //see device_del() -> bus_remove_device()
#endif

#if (defined CONFIG_XENO_COBALT)
   rtdm_dev_unregister(&device);
#else
   device_destroy(S_pDevClass, MKDEV(MAJOR_NUM, 0));
   class_destroy(S_pDevClass);
   unregister_chrdev(MAJOR_NUM, ATEMSYS_DEVICE_NAME);
#endif /* CONFIG_XENO_COBALT */
}

