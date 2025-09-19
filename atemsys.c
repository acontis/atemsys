/*-----------------------------------------------------------------------------
 * atemsys.c
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
#include <linux/platform_device.h>

#if !(defined NO_IRQ) && ((defined __aarch64__) || (defined __riscv))
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

#if (defined CONFIG_DTC)
#include <linux/of.h>
#include <linux/of_irq.h>
#endif /* CONFIG_DTC */
#endif /* CONFIG_XENO_COBALT */

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
#include <linux/of_device.h>
#include <linux/of_irq.h>
#include <linux/of_net.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/wait.h>
#include <asm/param.h>
#include <linux/of_gpio.h>
#include <linux/reset.h>

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,5,0))
#include <linux/of_platform.h>
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,15,0) /* not tested */)
#define INCLUDE_ATEMSYS_DT_REGISTER_NETDEVICE    1
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
struct _ATEMSYS_T_DRV_DESC_PRIVATE;
int RegisterEthernetDriverAsNetDevice(struct device_node* pDevNode, struct _ATEMSYS_T_DRV_DESC_PRIVATE* pDrvDesc);
#endif

#endif /* CONFIG_OF */

#if ((defined CONFIG_PCI) \
       && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0) /* not tested */))
#define INCLUDE_ATEMSYS_PCI_DRIVER    1
#include <linux/aer.h>
#endif

#if !(defined HAVE_IRQ_TO_DESC) && !(defined CONFIG_HAVE_DOVETAIL) && !(defined CONFIG_IRQ_PIPELINE)
 #if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,4,1))
  #define INCLUDE_IRQ_TO_DESC
 #endif
#else
 #if HAVE_IRQ_TO_DESC
  #define INCLUDE_IRQ_TO_DESC
 #endif
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

static char* AllowedPciDevices = "PCI_ANY_ID";
module_param(AllowedPciDevices, charp, 0000);
MODULE_PARM_DESC(AllowedPciDevices, "Bind only pci devices in semicolon separated list e.g. AllowedPciDevices=\"0000:01:00.0\", empty string will turn off atemsys_pci driver.");

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
module_param(loglevel, int, 0);
MODULE_PARM_DESC(loglevel, "Set log level default LOGLEVEL_INFO, see /include/linux/kern_levels.h");

#ifdef INCLUDE_ATEMSYS_DT_REGISTER_NETDEVICE
static bool bRegisterDtbNetDevice = false;
module_param(bRegisterDtbNetDevice, bool, false);
MODULE_PARM_DESC(bRegisterDtbNetDevice, "Register netdevice on device tree nodes (dsa driver support)");
#endif

#if (defined CONFIG_XENO_COBALT) \
      && !((defined CONFIG_XENO_VERSION_MAJOR) && (defined CONFIG_XENO_VERSION_MINOR) \
      && (CONFIG_XENO_VERSION_MAJOR >= 3) &&  (CONFIG_XENO_VERSION_MINOR >= 3))
#define PRINTK(prio, str, ...) rtdm_printk(prio ATEMSYS_DEVICE_NAME ": " str,  ##__VA_ARGS__)
#else
#define PRINTK(prio, str, ...) printk(prio ATEMSYS_DEVICE_NAME ": " str,  ##__VA_ARGS__)
#endif /* CONFIG_XENO_COBALT */

#define ERR(str, ...) (LOGLEVEL_ERR <= loglevel)?     PRINTK(KERN_ERR, str, ##__VA_ARGS__)     :0
#define WRN(str, ...) (LOGLEVEL_WARNING <= loglevel)? PRINTK(KERN_WARNING, str, ##__VA_ARGS__) :0
#define INF(str, ...) (LOGLEVEL_INFO <= loglevel)?    PRINTK(KERN_INFO, str, ##__VA_ARGS__)    :0
#define DBG(str, ...) (LOGLEVEL_DEBUG <= loglevel)?   PRINTK(KERN_INFO, str, ##__VA_ARGS__)    :0


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

#if ((defined CONFIG_OF) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,18,0)) && !(defined CONFIG_XENO_COBALT))
  #define OF_DMA_CONFIGURE(dev, of_node) of_dma_configure(dev, of_node, true)
#elif ((defined CONFIG_OF) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,1,0)) && !(defined CONFIG_XENO_COBALT))
  #define OF_DMA_CONFIGURE(dev, of_node) of_dma_configure(dev, of_node)
#elif ((defined CONFIG_OF) && (LINUX_VERSION_CODE >= KERNEL_VERSION(3,16,0)) && !(defined CONFIG_XENO_COBALT))
 #define OF_DMA_CONFIGURE(dev, of_node) of_dma_configure(dev)
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
    struct pci_dev* pPcidev;
  #if (defined INCLUDE_ATEMSYS_PCI_DRIVER)
    struct _ATEMSYS_T_PCI_DRV_DESC_PRIVATE* pPciDrvDesc;
  #endif
#endif
    struct platform_device* pPlatformDev;
  #if (defined INCLUDE_ATEMSYS_DT_DRIVER)
    struct _ATEMSYS_T_DRV_DESC_PRIVATE* pDrvDesc;
  #endif

    ATEMSYS_T_IRQ_DESC  irqDesc;

    /* supported features */
    bool bSupport64BitDma;
} ATEMSYS_T_DEVICE_DESC;

typedef struct _ATEMSYS_T_MMAP_DESC
{
   struct list_head  list;
   ATEMSYS_T_DEVICE_DESC* pDevDesc;
   dma_addr_t        dmaAddr;
   void*             pVirtAddr;
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

typedef struct
{
    void __iomem*   pbyBase;
    __u64           qwPhys;
    __u32           dwSize;
} ATEMSYS_T_IOMEM;

typedef struct _ATEMSYS_T_DRV_DESC_PRIVATE
{
    int                         nDev_id;
    struct net_device*          netdev;
    struct platform_device*     pPDev;
    struct device_node*         pDevNode;

    /* storage and identification */
    ATEMSYS_T_MAC_INFO          MacInfo;

    /* powermanagement */
    struct reset_control*       pResetCtl;

    /* clocks */
    const char*                 clk_ids[ATEMSYS_MAX_NUMBER_OF_CLOCKS];
    struct clk*                 clks[ATEMSYS_MAX_NUMBER_OF_CLOCKS];
    int                         nCountClk;

    /* PHY */
    ATEMSYS_T_PHY_INFO          PhyInfo;
    phy_interface_t             PhyInterface;
    struct device_node*         pPhyNode;
    struct device_node*         pMdioNode;
    struct device_node*         pMdioDevNode; /* node for own mdio bus */
    struct phy_device*          pPhyDev;
    struct regulator*           pPhyRegulator;
    struct task_struct*         etx_thread_StartPhy;
    struct task_struct*         etx_thread_StopPhy;

    /* PHY reset*/
    int                         nPhyResetGpioPin;
    bool                        bPhyResetGpioPinOwner;
    bool                        bPhyResetGpioActiveHigh;
    int                         nPhyResetDuration;
    int                         nPhyResetPostDelay;

    /* mdio */
    ATEMSYS_T_MDIO_ORDER        MdioOrder;
    struct mii_bus*             pMdioBus;
    struct mutex                mdio_order_mutex;
    struct mutex                mdio_mutex;
    wait_queue_head_t           mdio_wait_queue;
    int                         mdio_wait_queue_cnt;

#ifdef CONFIG_TI_K3_UDMA
    /* Ti CPSWG Channel, Flow & Ring */
#define ATEMSYS_UDMA_CHANNELS 10
    void*                       apvTxChan[ATEMSYS_UDMA_CHANNELS];
    int                         anTxIrq[ATEMSYS_UDMA_CHANNELS];
    void*                       apvRxChan[ATEMSYS_UDMA_CHANNELS];
    int                         anRxIrq[ATEMSYS_UDMA_CHANNELS];
#endif /*#ifdef CONFIG_TI_K3_UDMA*/

#define IOMEMLIST_LENGTH 20
    ATEMSYS_T_IOMEM             oIoMemList[IOMEMLIST_LENGTH];

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
static int PhyResetIoctl(unsigned long ioctlParam);
static int ResetPhyViaGpio(ATEMSYS_T_DRV_DESC_PRIVATE* pDrvDescPrivate);
#if (LINUX_VERSION_CODE > KERNEL_VERSION(6,11,0))
static void EthernetDriverRemove(struct platform_device* pPDev);
#else
static int EthernetDriverRemove(struct platform_device* pPDev);
#endif
static int EthernetDriverProbe(struct platform_device* pPDev);

#if (defined CONFIG_XENO_COBALT)
static int StartPhy(struct platform_device* pPDev);
static int StopPhy(struct platform_device* pPDev);
typedef struct _ATEMSYS_T_WORKER_THREAD_DESC
{
    struct task_struct*     etx_thread;
    int (* pfNextTask)(void*);
    void*                   pNextTaskData;
    struct mutex            WorkerTask_mutex;
    bool                    bWorkerTaskShutdown;
    bool                    bWorkerTaskRunning;
} ATEMSYS_T_WORKER_THREAD_DESC;
static ATEMSYS_T_WORKER_THREAD_DESC S_oAtemsysWorkerThreadDesc;

static int AtemsysWorkerThread(void* data)
{
    void* pWorkerTaskData = NULL;
    int (* pfWorkerTask)(void*);
    pfWorkerTask = NULL;

    S_oAtemsysWorkerThreadDesc.bWorkerTaskRunning = true;

    for (;;)
    {
        mutex_lock(&S_oAtemsysWorkerThreadDesc.WorkerTask_mutex);
        if (S_oAtemsysWorkerThreadDesc.bWorkerTaskShutdown)
        {
            mutex_unlock(&S_oAtemsysWorkerThreadDesc.WorkerTask_mutex);
            break;
        }
        pfWorkerTask = S_oAtemsysWorkerThreadDesc.pfNextTask;
        pWorkerTaskData = S_oAtemsysWorkerThreadDesc.pNextTaskData;
        S_oAtemsysWorkerThreadDesc.pfNextTask = NULL;
        S_oAtemsysWorkerThreadDesc.pNextTaskData = NULL;
        mutex_unlock(&S_oAtemsysWorkerThreadDesc.WorkerTask_mutex);

        if ((NULL != pfWorkerTask) && (NULL != pWorkerTaskData))
        {
            pfWorkerTask(pWorkerTaskData);
        }
        msleep(100);
    }

    S_oAtemsysWorkerThreadDesc.bWorkerTaskRunning = false;

    return 0;
}
#endif /* #if (defined CONFIG_XENO_COBALT) */

#endif /* INCLUDE_ATEMSYS_DT_DRIVER */


static void dev_munmap(struct vm_area_struct* vma);

#if (defined CONFIG_XENO_COBALT)
   static int dev_interrupt_handler(rtdm_irq_t* irq_handle);
#else
   static irqreturn_t dev_interrupt_handler(int nIrq, void* pParam);
#endif /* CONFIG_XENO_COBALT */

static struct vm_operations_struct mmap_vmop =
{
   .close = dev_munmap,
};

static DEFINE_MUTEX(S_mtx);
static ATEMSYS_T_DEVICE_DESC S_DevNode;
static struct class* S_pDevClass;
static struct device* S_pDev;
static struct platform_device* S_pPlatformDev = NULL;

#if !(defined CONFIG_XENO_COBALT)
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

#if (!defined __arm__) && !((defined __aarch64__) || (defined __riscv))
static void* dev_dma_alloc(u32 dwLen, dma_addr_t* pDmaAddr)
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

   *pDmaAddr = virt_to_phys((void*) virtAddr);

   return (void*) virtAddr;
}

static void dev_dma_free(u32 dwLen, void* virtAddr)
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

static void dev_munmap(struct vm_area_struct* vma)
{
   ATEMSYS_T_MMAP_DESC* pMmapDesc = (ATEMSYS_T_MMAP_DESC*) vma->vm_private_data;

   INF("dev_munmap: 0x%px -> 0x%px (%d)\n",
         (void*) pMmapDesc->pVirtAddr, (void*)(unsigned long)pMmapDesc->dmaAddr, (int) pMmapDesc->len);
    if (0 == pMmapDesc->dmaAddr) { INF("dev_munmap: 0 == pMmapDesc->dmaAddr!\n"); return; }
    if (NULL == pMmapDesc->pVirtAddr) { INF("dev_munmap: NULL == pMmapDesc->pVirtAddr!\n"); return; }

   /* free DMA memory */
#if (defined CONFIG_PCI)
   if (pMmapDesc->pDevDesc->pPcidev == NULL)
#endif
   {
#if (defined __arm__) || (defined __aarch64__) || (defined __riscv)
      dmam_free_coherent(&pMmapDesc->pDevDesc->pPlatformDev->dev, pMmapDesc->len, pMmapDesc->pVirtAddr, pMmapDesc->dmaAddr);
#else
      dev_dma_free(pMmapDesc->len, pMmapDesc->pVirtAddr);
#endif
   }
#if (defined CONFIG_PCI)
   else
   {
#if ((defined __aarch64__) || (defined __riscv) \
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
    struct pci_dev* dev = NULL;

    for_each_pci_dev(dev) {
        if (pci_domain_nr(dev->bus) == 0 &&
            (dev->bus->number == bus && dev->devfn == devfn))
            return dev;
    }
    return dev;
}
#endif

static int dev_pci_select_device(ATEMSYS_T_DEVICE_DESC* pDevDesc, ATEMSYS_T_PCI_SELECT_DESC* pPciDesc, size_t size)
{
    int nRetVal = -EFAULT;
    s32 nPciBus, nPciDev, nPciFun, nPciDomain;

    switch (size)
    {
    case sizeof(ATEMSYS_T_PCI_SELECT_DESC_v1_0_00):
    {
        ATEMSYS_T_PCI_SELECT_DESC_v1_0_00 oPciDesc_v1_0_00;
        nRetVal = copy_from_user(&oPciDesc_v1_0_00, (ATEMSYS_T_PCI_SELECT_DESC_v1_0_00*)pPciDesc, sizeof(ATEMSYS_T_PCI_SELECT_DESC_v1_0_00));
        if (0 != nRetVal)
        {
            ERR("dev_pci_select_device failed: %d\n", nRetVal);
            goto Exit;
        }
        nPciBus    = oPciDesc_v1_0_00.nPciBus;
        nPciDev    = oPciDesc_v1_0_00.nPciDev;
        nPciFun    = oPciDesc_v1_0_00.nPciFun;
        nPciDomain = 0;
    } break;
    case sizeof(ATEMSYS_T_PCI_SELECT_DESC_v1_3_05):
    {
        ATEMSYS_T_PCI_SELECT_DESC_v1_3_05 oPciDesc_v1_3_05;
        nRetVal = copy_from_user(&oPciDesc_v1_3_05, (ATEMSYS_T_PCI_SELECT_DESC_v1_3_05*)pPciDesc, sizeof(ATEMSYS_T_PCI_SELECT_DESC_v1_3_05));
        if (0 != nRetVal)
        {
            ERR("dev_pci_select_device failed: %d\n", nRetVal);
            goto Exit;
        }
        nPciBus    = oPciDesc_v1_3_05.nPciBus;
        nPciDev    = oPciDesc_v1_3_05.nPciDev;
        nPciFun    = oPciDesc_v1_3_05.nPciFun;
        nPciDomain = oPciDesc_v1_3_05.nPciDomain;
    } break;
    case sizeof(ATEMSYS_T_PCI_SELECT_DESC_v1_4_12):
    {
        ATEMSYS_T_PCI_SELECT_DESC_v1_4_12 oPciDesc_v1_4_12;
        nRetVal = copy_from_user(&oPciDesc_v1_4_12, (ATEMSYS_T_PCI_SELECT_DESC_v1_4_12*)pPciDesc, sizeof(ATEMSYS_T_PCI_SELECT_DESC_v1_4_12));
        if (0 != nRetVal)
        {
            ERR("dev_pci_select_device failed: %d\n", nRetVal);
            goto Exit;
        }
        nPciBus    = oPciDesc_v1_4_12.nPciBus;
        nPciDev    = oPciDesc_v1_4_12.nPciDev;
        nPciFun    = oPciDesc_v1_4_12.nPciFun;
        nPciDomain = oPciDesc_v1_4_12.nPciDomain;
    } break;
    default:
    {
        nRetVal = -EFAULT;
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
                    nRetVal = -EBUSY;
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

    nRetVal = DRIVER_SUCCESS;

Exit:
    return nRetVal;
}

static int DefaultPciSettings(struct pci_dev* pPciDev)
{
    int nRetVal = -EIO;
    int nRes = -EIO;

    /* Turn on Memory-Write-Invalidate if it is supported by the device*/
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24))
    pci_set_mwi(pPciDev);
#else
    pci_try_set_mwi(pPciDev);
#endif

    /* remove wrong dma_coherent bit on ARM systems */
#if ((defined __aarch64__) || (defined __arm__) || (defined __riscv))
 #if (LINUX_VERSION_CODE < KERNEL_VERSION(5,4,0))
  #if (defined CONFIG_PHYS_ADDR_T_64BIT)
    if (is_device_dma_coherent(&pPciDev->dev))
    {
        pPciDev->dev.archdata.dma_coherent = false;
        INF("%s: DefaultPciSettings: Clear device.archdata dma_coherent bit!\n", pci_name(pPciDev));
    }
  #endif
 #endif
 #if (LINUX_VERSION_CODE > KERNEL_VERSION(5,0,0))
  #if ((defined(CONFIG_ARCH_HAS_SYNC_DMA_FOR_DEVICE) || defined(CONFIG_ARCH_HAS_SYNC_DMA_FOR_CPU) || defined(CONFIG_ARCH_HAS_SYNC_DMA_FOR_CPU_ALL)))
    if (0 != pPciDev->dev.dma_coherent)
    {
        pPciDev->dev.dma_coherent = 0;
        INF("%s: DefaultPciSettings: Clear device dma_coherent bit!\n", pci_name(pPciDev));
    }
  #endif
 #endif
#endif

#if ((LINUX_VERSION_CODE < KERNEL_VERSION(5,10,0)) || !((defined __aarch64__) || (defined __riscv)))
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,12,55))
    nRes = dma_set_coherent_mask(&pPciDev->dev, DMA_BIT_MASK(32));
#else
    nRes = dma_set_mask_and_coherent(&pPciDev->dev, DMA_BIT_MASK(32));
#endif
    if (nRes)
#endif
    {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,12,55))
        nRes = dma_set_coherent_mask(&pPciDev->dev, DMA_BIT_MASK(64));
#else
        nRes = dma_set_mask_and_coherent(&pPciDev->dev, DMA_BIT_MASK(64));
#endif
        if (nRes)
        {
            ERR("%s: DefaultPciSettings: dma_set_mask_and_coherent failed\n", pci_name(pPciDev));
            nRetVal = nRes;
            goto Exit;
        }
    }
    pci_set_master(pPciDev);

    /* Try to enable MSI (Message Signaled Interrupts). MSI's are non shared, so we can
    * use interrupt mode, also if we have a non exclusive interrupt line with legacy
    * interrupts.
    */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,0,0))
    if (!pci_msi_enabled())
#else
    if (pci_enable_msi(pPciDev))
#endif
    {
        INF("%s: DefaultPciSettings: legacy INT configured\n", pci_name(pPciDev));
    }
    else
    {
        INF("%s: DefaultPciSettings: MSI configured\n", pci_name(pPciDev));
    }

    nRetVal = 0;

Exit:
   return nRetVal;
}

/*
 * See also kernel/Documentation/PCI/pci.txt for the recommended PCI initialization sequence
 */
static int ioctl_pci_configure_device(ATEMSYS_T_DEVICE_DESC* pDevDesc, unsigned long ioctlParam, size_t size)
{
    int nRetVal = -EIO;
    int nRc;
    int i;
    unsigned long ioBase;
    s32 nBar = 0;
    u32 dwAtemsysApiVersion = EC_ATEMSYSVERSION(1,0,0);
    ATEMSYS_T_PCI_SELECT_DESC_v1_4_12 oPciDesc;
    memset(&oPciDesc, 0, sizeof(ATEMSYS_T_PCI_SELECT_DESC_v1_4_12));
    switch (size)
    {
    case sizeof(ATEMSYS_T_PCI_SELECT_DESC_v1_0_00):
    {
        dwAtemsysApiVersion = EC_ATEMSYSVERSION(1,0,0);
    } break;
    case sizeof(ATEMSYS_T_PCI_SELECT_DESC_v1_3_05):
    {
        dwAtemsysApiVersion = EC_ATEMSYSVERSION(1,3,5);
    } break;
    case sizeof(ATEMSYS_T_PCI_SELECT_DESC_v1_4_12):
    {
        dwAtemsysApiVersion = EC_ATEMSYSVERSION(1,4,12);
    } break;
    default:
    {
        nRetVal = -EIO;
        ERR("pci_conf: Invalid parameter\n");
        goto Exit;
    }
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
            if ((EC_ATEMSYSVERSION(1,4,12) != dwAtemsysApiVersion) && (pDevDesc->pPciDrvDesc->aBars[i].qwIOMem > 0xFFFFFFFF))
            {
                ERR("pci_conf: 64-Bit IO address not supported\n");
                INF("pci_conf: Update LinkLayer for 64-Bit IO address support!\n");
                nRetVal = -ENODEV;
                goto Exit;
            }

            oPciDesc.aBar[i].qwIOMem = pDevDesc->pPciDrvDesc->aBars[i].qwIOMem;
            oPciDesc.aBar[i].dwIOLen = pDevDesc->pPciDrvDesc->aBars[i].dwIOLen;
        }

        oPciDesc.nBarCnt = pDevDesc->pPciDrvDesc->nBarCnt;
        oPciDesc.dwIrq   = (u32)pDevDesc->pPcidev->irq;
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
            nRetVal = -EBUSY;
            goto Exit;
        }

        /* find the memory BAR */
        for (i = 0; i < ATEMSYS_PCI_MAXBAR ; i++)
        {
            if (pci_resource_flags(pDevDesc->pPcidev, i) & IORESOURCE_MEM)
            {
                /* IO area address */
                ioBase = pci_resource_start(pDevDesc->pPcidev, i);

                if ((EC_ATEMSYSVERSION(1,4,12) != dwAtemsysApiVersion) && (ioBase > 0xFFFFFFFF))
                {
                    ERR("pci_conf: 64-Bit IO address not supported\n");
                    pci_release_regions(pDevDesc->pPcidev);
                    pDevDesc->pPcidev = NULL;
                    nRetVal = -ENODEV;
                    goto Exit;
                }

                /* IO area length */
                oPciDesc.aBar[nBar].dwIOLen = pci_resource_len(pDevDesc->pPcidev, i);
                oPciDesc.aBar[nBar].qwIOMem = ioBase;

                nBar++;
            }
        }

        nRc = DefaultPciSettings(pDevDesc->pPcidev);
        if (nRc)
        {
            pci_release_regions(pDevDesc->pPcidev);
            pDevDesc->pPcidev = NULL;
            goto Exit;
        }

        /* number of memory BARs */
        /* assigned IRQ */
        oPciDesc.nBarCnt = nBar;
        oPciDesc.dwIrq   = pDevDesc->pPcidev->irq;
    }

#if defined(__arm__) && 0
   /*
    * This is required for TI's TMDXEVM8168 (Cortex A8) eval board
    * \sa TI "DM81xx AM38xx PCI Express Root Complex Driver User Guide"
    * "DM81xx RC supports maximum remote read request size (MRRQS) as 256 bytes"
    */
   pcie_set_readrq(pDevDesc->pPcidev, 256);
#endif

    switch (dwAtemsysApiVersion)
    {
    case EC_ATEMSYSVERSION(1,0,0):
    {
        ATEMSYS_T_PCI_SELECT_DESC_v1_0_00 oPciDesc_v1_0_00;
        memset(&oPciDesc_v1_0_00, 0, sizeof(ATEMSYS_T_PCI_SELECT_DESC_v1_0_00));
        if (!ACCESS_OK(VERIFY_WRITE, (ATEMSYS_T_PCI_SELECT_DESC_v1_0_00*)ioctlParam, sizeof(ATEMSYS_T_PCI_SELECT_DESC_v1_0_00)))
        {
            nRetVal = -EFAULT;
            ERR("pci_conf: EFAULT\n");
            goto Exit;
        }
        oPciDesc_v1_0_00.nBarCnt = oPciDesc.nBarCnt;
        oPciDesc_v1_0_00.dwIrq   = oPciDesc.dwIrq;
        for (i = 0; i < oPciDesc_v1_0_00.nBarCnt ; i++)
        {
            oPciDesc_v1_0_00.aBar[i].dwIOLen = oPciDesc.aBar[i].dwIOLen;
            oPciDesc_v1_0_00.aBar[i].dwIOMem = (u32)oPciDesc.aBar[i].qwIOMem;
        }
        nRetVal = copy_to_user((ATEMSYS_T_PCI_SELECT_DESC_v1_0_00*)ioctlParam, &oPciDesc_v1_0_00, sizeof(ATEMSYS_T_PCI_SELECT_DESC_v1_0_00));
        if (0 != nRetVal)
        {
            ERR("ioctl_pci_configure_device failed: %d\n", nRetVal);
            goto Exit;
        }
    } break;
    case EC_ATEMSYSVERSION(1,3,5):
    {
        ATEMSYS_T_PCI_SELECT_DESC_v1_3_05 oPciDesc_v1_3_05;
        memset(&oPciDesc_v1_3_05, 0, sizeof(ATEMSYS_T_PCI_SELECT_DESC_v1_3_05));
        if (!ACCESS_OK(VERIFY_WRITE, (ATEMSYS_T_PCI_SELECT_DESC_v1_3_05*)ioctlParam, sizeof(ATEMSYS_T_PCI_SELECT_DESC_v1_3_05)))
        {
            nRetVal = -EFAULT;
            ERR("pci_conf: EFAULT\n");
            goto Exit;
        }
        oPciDesc_v1_3_05.nBarCnt = oPciDesc.nBarCnt;
        oPciDesc_v1_3_05.dwIrq   = oPciDesc.dwIrq;
        for (i = 0; i < oPciDesc_v1_3_05.nBarCnt ; i++)
        {
            oPciDesc_v1_3_05.aBar[i].dwIOLen = oPciDesc.aBar[i].dwIOLen;
            oPciDesc_v1_3_05.aBar[i].dwIOMem = (u32)oPciDesc.aBar[i].qwIOMem;
        }
        nRetVal = copy_to_user((ATEMSYS_T_PCI_SELECT_DESC_v1_3_05*)ioctlParam, &oPciDesc_v1_3_05, sizeof(ATEMSYS_T_PCI_SELECT_DESC_v1_3_05));
        if (0 != nRetVal)
        {
            ERR("ioctl_pci_configure_device failed: %d\n", nRetVal);
            goto Exit;
        }
    } break;
    case EC_ATEMSYSVERSION(1,4,12):
    {
        if (!ACCESS_OK(VERIFY_WRITE, (ATEMSYS_T_PCI_SELECT_DESC_v1_4_12*)ioctlParam, sizeof(ATEMSYS_T_PCI_SELECT_DESC_v1_4_12)))
        {
            nRetVal = -EFAULT;
            ERR("pci_conf: EFAULT\n");
            goto Exit;
        }
        nRetVal = copy_to_user((ATEMSYS_T_PCI_SELECT_DESC_v1_4_12*)ioctlParam, &oPciDesc, sizeof(ATEMSYS_T_PCI_SELECT_DESC_v1_4_12));
        if (0 != nRetVal)
        {
            ERR("ioctl_pci_configure_device failed: %d\n", nRetVal);
            goto Exit;
        }
    } break;
    default:
    {
        nRetVal = -EFAULT;
        goto Exit;
    }
    }

   nRetVal = 0;

Exit:
   return nRetVal;
}

static int ioctl_pci_finddevice(ATEMSYS_T_DEVICE_DESC* pDevDesc, unsigned long ioctlParam, size_t size)
{
    int nRetVal = -EIO;
    struct pci_dev* pPciDev = NULL;
    s32 nVendor, nDevice, nInstance, nInstanceId;
    u32 dwAtemsysApiVersion = EC_ATEMSYSVERSION(1,0,0);
    ATEMSYS_T_PCI_SELECT_DESC_v1_0_00 oPciDesc_v1_0_00;
    ATEMSYS_T_PCI_SELECT_DESC_v1_3_05 oPciDesc_v1_3_05;
    ATEMSYS_T_PCI_SELECT_DESC_v1_4_12 oPciDesc_v1_4_12;

    switch (size)
    {
    case sizeof(ATEMSYS_T_PCI_SELECT_DESC_v1_0_00):
    {
        dwAtemsysApiVersion = EC_ATEMSYSVERSION(1,0,0);
        memset(&oPciDesc_v1_0_00, 0, sizeof(ATEMSYS_T_PCI_SELECT_DESC_v1_0_00));
        if (!ACCESS_OK(VERIFY_WRITE, (ATEMSYS_T_PCI_SELECT_DESC_v1_0_00*)ioctlParam, sizeof(ATEMSYS_T_PCI_SELECT_DESC_v1_0_00)))
        {
            nRetVal = -EFAULT;
        }
        nRetVal = copy_from_user(&oPciDesc_v1_0_00, (ATEMSYS_T_PCI_SELECT_DESC_v1_0_00*)ioctlParam, sizeof(ATEMSYS_T_PCI_SELECT_DESC_v1_0_00));
        if (0 != nRetVal)
        {
            ERR("ioctl_pci_finddevice failed: %d\n", nRetVal);
            goto Exit;
        }
        nVendor   = oPciDesc_v1_0_00.nVendID;
        nDevice   = oPciDesc_v1_0_00.nDevID;
        nInstance = oPciDesc_v1_0_00.nInstance;
    } break;
    case sizeof(ATEMSYS_T_PCI_SELECT_DESC_v1_3_05):
    {
        dwAtemsysApiVersion = EC_ATEMSYSVERSION(1,3,5);
        memset(&oPciDesc_v1_3_05, 0, sizeof(ATEMSYS_T_PCI_SELECT_DESC_v1_3_05));
        if (!ACCESS_OK(VERIFY_WRITE, (ATEMSYS_T_PCI_SELECT_DESC_v1_3_05*)ioctlParam, sizeof(ATEMSYS_T_PCI_SELECT_DESC_v1_3_05)))
        {
            nRetVal = -EFAULT;
        }
        nRetVal = copy_from_user(&oPciDesc_v1_3_05, (ATEMSYS_T_PCI_SELECT_DESC_v1_3_05*)ioctlParam, sizeof(ATEMSYS_T_PCI_SELECT_DESC_v1_3_05));
        if (0 != nRetVal)
        {
            ERR("ioctl_pci_finddevice failed: %d\n", nRetVal);
            goto Exit;
        }
        nVendor   = oPciDesc_v1_3_05.nVendID;
        nDevice   = oPciDesc_v1_3_05.nDevID;
        nInstance = oPciDesc_v1_3_05.nInstance;
    } break;
    case sizeof(ATEMSYS_T_PCI_SELECT_DESC_v1_4_12):
    {
        dwAtemsysApiVersion = EC_ATEMSYSVERSION(1,4,12);
        memset(&oPciDesc_v1_4_12, 0, sizeof(ATEMSYS_T_PCI_SELECT_DESC_v1_4_12));
        if (!ACCESS_OK(VERIFY_WRITE, (ATEMSYS_T_PCI_SELECT_DESC_v1_4_12*)ioctlParam, sizeof(ATEMSYS_T_PCI_SELECT_DESC_v1_4_12)))
        {
            nRetVal = -EFAULT;
        }
        nRetVal = copy_from_user(&oPciDesc_v1_4_12, (ATEMSYS_T_PCI_SELECT_DESC_v1_4_12*)ioctlParam, sizeof(ATEMSYS_T_PCI_SELECT_DESC_v1_4_12));
        if (0 != nRetVal)
        {
            ERR("ioctl_pci_finddevice failed: %d\n", nRetVal);
            goto Exit;
        }
        nVendor   = oPciDesc_v1_4_12.nVendID;
        nDevice   = oPciDesc_v1_4_12.nDevID;
        nInstance = oPciDesc_v1_4_12.nInstance;
    } break;
    default:
    {
        nRetVal = -EIO;
        ERR("pci_conf: Invalid parameter\n");
        goto Exit;
    }
    }

    if (-EFAULT == nRetVal)
    {
        ERR("pci_find: EFAULT\n");
        nRetVal = -EFAULT;
        goto Exit;
    }

    INF("pci_find: ven 0x%x dev 0x%x nInstance %d\n", nVendor, nDevice, nInstance);

    for (nInstanceId = 0; nInstanceId <= nInstance; nInstanceId++ )
    {
        pPciDev = pci_get_device (nVendor, nDevice, pPciDev);
    }

    if (pPciDev == NULL)
    {
        WRN("pci_find: device 0x%x:0x%x:%d not found\n", nVendor, nDevice, nInstance);
        nRetVal = -ENODEV;
        goto Exit;
    }

    INF("pci_find: found 0x%x:0x%x:%d -> %s\n",
       nVendor, nDevice, nInstance, pci_name(pPciDev));

    switch (dwAtemsysApiVersion)
    {
    case EC_ATEMSYSVERSION(1,0,0):
    {
        oPciDesc_v1_0_00.nPciBus = (s32)pPciDev->bus->number;
        oPciDesc_v1_0_00.nPciDev = (s32)PCI_SLOT(pPciDev->devfn);
        oPciDesc_v1_0_00.nPciFun = (s32)PCI_FUNC(pPciDev->devfn);

        nRetVal = copy_to_user((ATEMSYS_T_PCI_SELECT_DESC_v1_0_00*)ioctlParam, &oPciDesc_v1_0_00, sizeof(ATEMSYS_T_PCI_SELECT_DESC_v1_0_00));
        if (0 != nRetVal)
        {
            ERR("ioctl_pci_finddevice failed: %d\n", nRetVal);
            goto Exit;
        }
    } break;
    case EC_ATEMSYSVERSION(1,3,5):
    {
        oPciDesc_v1_3_05.nPciDomain = (s32)pci_domain_nr(pPciDev->bus);
        oPciDesc_v1_3_05.nPciBus    = (s32)pPciDev->bus->number;
        oPciDesc_v1_3_05.nPciDev    = (s32)PCI_SLOT(pPciDev->devfn);
        oPciDesc_v1_3_05.nPciFun    = (s32)PCI_FUNC(pPciDev->devfn);

        nRetVal = copy_to_user((ATEMSYS_T_PCI_SELECT_DESC_v1_3_05*)ioctlParam, &oPciDesc_v1_3_05, sizeof(ATEMSYS_T_PCI_SELECT_DESC_v1_3_05));
        if (0 != nRetVal)
        {
            ERR("ioctl_pci_finddevice failed: %d\n", nRetVal);
            goto Exit;
        }
    } break;
    case EC_ATEMSYSVERSION(1,4,12):
    {
        oPciDesc_v1_4_12.nPciDomain = (s32)pci_domain_nr(pPciDev->bus);
        oPciDesc_v1_4_12.nPciBus    = (s32)pPciDev->bus->number;
        oPciDesc_v1_4_12.nPciDev    = (s32)PCI_SLOT(pPciDev->devfn);
        oPciDesc_v1_4_12.nPciFun    = (s32)PCI_FUNC(pPciDev->devfn);

        nRetVal = copy_to_user((ATEMSYS_T_PCI_SELECT_DESC_v1_4_12*)ioctlParam, &oPciDesc_v1_4_12, sizeof(ATEMSYS_T_PCI_SELECT_DESC_v1_4_12));
        if (0 != nRetVal)
        {
            ERR("ioctl_pci_finddevice failed: %d\n", nRetVal);
            goto Exit;
        }
    } break;
    }

    nRetVal = 0;

Exit:
    return nRetVal;
}
#endif /* CONFIG_PCI */

#if (defined CONFIG_DTC)
/*
 * Lookup Nth (0: first) compatible device tree node with "interrupts" property present.
 */
static struct device_node * atemsys_of_lookup_intnode(const char* compatible, int deviceIdx)
{
   struct device_node* device = NULL;
   struct device_node* child = NULL;
   struct device_node* tmp = NULL;
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
static unsigned atemsys_of_map_irq_to_virq(const char* compatible, int deviceIdx, int intIdx)
{
   unsigned virq;
   struct device_node* device = NULL;

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
     struct irq_data* irq_data = NULL;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,11,1))
    {
        irq_data = irq_get_irq_data(irq_id);
    }
#else
    {
        struct irq_desc* desc;
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
    int nRetVal = -EIO;
    int nRc;
    ATEMSYS_T_IRQ_DESC* pIrqDesc = NULL;
    unsigned int irq = 0;

#if (defined CONFIG_PCI)
    if (ioctlParam == ATEMSYS_USE_PCI_INT)
    {
        /* Use IRQ number from selected PCI device */

        if (pDevDesc->pPcidev == NULL)
        {
            WRN("intcon: error call ioctl(ATEMSYS_IOCTL_PCI_CONF_DEVICE) first\n");
            goto Exit;
        }
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,0,0))
        nRc = pci_alloc_irq_vectors(pDevDesc->pPcidev, 1, 1, PCI_IRQ_ALL_TYPES);
        if (nRc < 0)
        {
            nRetVal = nRc;
            ERR("intcon: pci_alloc_irq_vectors failed\n");
            goto Exit;
        }

        irq = pci_irq_vector(pDevDesc->pPcidev, 0);
        INF("intcon: Use IRQ (%d) from pci_alloc_irq_vectors\n", irq);
#else
        irq = pDevDesc->pPcidev->irq;
        INF("intcon: Use IRQ (%d) from PCI config\n", irq);
#endif
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
                nRetVal = -EPERM;
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
        nRetVal = nRc;
        goto Exit;
    }
    nRc = rtdm_irq_enable(&pIrqDesc->irq_handle);
    if (nRc)
    {
        ERR("ioctl_int_connect: rtdm_irq_enable() for IRQ %d returned error: %d\n", irq, nRc);
        nRetVal = nRc;
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
        nRetVal = -EPERM;
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

    nRetVal = 0;
Exit:
    return nRetVal;
}

static int ioctl_intinfo(ATEMSYS_T_DEVICE_DESC* pDevDesc, unsigned long ioctlParam)
{
   int nRetVal = -EIO;
#if (defined CONFIG_XENO_COBALT)
   ATEMSYS_T_INT_INFO* pIntInfo = (ATEMSYS_T_INT_INFO*) ioctlParam;
   struct rtdm_fd* fd = rtdm_private_to_fd(pDevDesc);
   if (rtdm_fd_is_user(fd))
   {
      nRetVal = rtdm_safe_copy_to_user(fd, &pIntInfo->dwInterrupt, &pDevDesc->irqDesc.irq, sizeof(__u32));
      if (nRetVal)
      {
         ERR("ioctl_intinfo failed: %d\n", nRetVal);
         goto Exit;
      }
   }
#else
   ATEMSYS_T_INT_INFO oIntInfo;
   memset(&oIntInfo, 0, sizeof(ATEMSYS_T_INT_INFO));
   if (!ACCESS_OK(VERIFY_WRITE, (ATEMSYS_T_INT_INFO*)ioctlParam, sizeof(ATEMSYS_T_INT_INFO)))
   {
      ERR("ioctl_intinfo: EFAULT\n");
      nRetVal = -EFAULT;
      goto Exit;
   }
   oIntInfo.dwInterrupt = pDevDesc->irqDesc.irq;
   nRetVal = copy_to_user((ATEMSYS_T_INT_INFO*)ioctlParam, &oIntInfo, sizeof(ATEMSYS_T_INT_INFO));
   if (0 != nRetVal)
   {
      ERR("ioctl_intinfo failed: %d\n", nRetVal);
      goto Exit;
   }
#endif /* CONFIG_XENO_COBALT */

Exit:
    return nRetVal;
}


static int dev_int_disconnect(ATEMSYS_T_DEVICE_DESC* pDevDesc)
{
   int nRetVal = -EIO;
   int nCnt;
   ATEMSYS_T_IRQ_DESC* pIrqDesc = &(pDevDesc->irqDesc);

#if (defined CONFIG_XENO_COBALT)
      int nRc;
      if (pIrqDesc->irq)
      {
         nRc = rtdm_irq_disable(&pIrqDesc->irq_handle);
         if (nRc)
         {
            ERR("dev_int_disconnect: rtdm_irq_disable() for IRQ %d returned error: %d\n", (u32) pIrqDesc->irq, nRc);
            nRetVal = nRc;
            goto Exit;
         }

         nRc = rtdm_irq_free(&pIrqDesc->irq_handle);
         if (nRc)
         {
            ERR("dev_int_disconnect: rtdm_irq_free() for IRQ %d returned error: %d\n", (u32) pIrqDesc->irq, nRc);
            nRetVal = nRc;
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

#if (defined CONFIG_PCI) && (LINUX_VERSION_CODE >= KERNEL_VERSION(6,0,0))
         if (NULL != pDevDesc->pPcidev)
         {
            pci_free_irq_vectors(pDevDesc->pPcidev);
         }
#endif
         pIrqDesc->irq = 0;

         /* Wakeup sleeping threads -> read() */
         wake_up(&pIrqDesc->q);
      }
#endif /* CONFIG_XENO_COBALT */
   nRetVal = 0;

#if (defined CONFIG_XENO_COBALT)
Exit:
#endif
   return nRetVal;
}

#if (defined INCLUDE_ATEMSYS_DT_DRIVER)
#ifdef CONFIG_TI_K3_UDMA

#if (LINUX_VERSION_CODE > KERNEL_VERSION(6,12,0))
 #ifndef CPSWG_STRUCT_VERSION
  #define CPSWG_STRUCT_VERSION 3
 #endif
#elif (LINUX_VERSION_CODE > KERNEL_VERSION(5,10,0))
 #ifndef CPSWG_STRUCT_VERSION
  #define CPSWG_STRUCT_VERSION 2
 #endif
#endif

#include <linux/soc/ti/k3-ringacc.h>
#include <linux/soc/ti/ti_sci_protocol.h>
#include <linux/soc/ti/ti_sci_protocol.h>

/* from */
struct k3_ring_state {
    u32 free;
    u32 occ;
    u32 windex;
    u32 rindex;
#ifdef CPSWG_STRUCT_VERSION
    u32 tdown_complete:1;
#endif
};

struct k3_ring {
    struct k3_ring_rt_regs __iomem *rt;
#if ((defined CPSWG_STRUCT_VERSION) && (3 == CPSWG_STRUCT_VERSION))
    struct k3_ring_cfg_regs __iomem *cfg;
    struct k3_ring_intr_regs __iomem *intr;
#endif
    struct k3_ring_fifo_regs __iomem *fifos;
    struct k3_ringacc_proxy_target_regs  __iomem *proxy;
    dma_addr_t  ring_mem_dma;
    void        *ring_mem_virt;
#if ((defined CPSWG_STRUCT_VERSION) && (3 == CPSWG_STRUCT_VERSION))
    const struct k3_ring_ops *ops;
#else
    struct k3_ring_ops *ops;
#endif
    u32     size;
    enum k3_ring_size elm_size;
    enum k3_ring_mode mode;
    u32     flags;
#define K3_RING_FLAG_BUSY   BIT(1)
#define K3_RING_FLAG_SHARED BIT(2)
#ifdef CPSWG_STRUCT_VERSION
 #define K3_RING_FLAG_REVERSE BIT(3)
#endif
    struct k3_ring_state state;
    u32     ring_id;
    struct k3_ringacc   *parent;
    u32     use_count;
    int     proxy_id;
#ifdef CPSWG_STRUCT_VERSION
    struct device   *dma_dev;
    u32     asel;
#define K3_ADDRESS_ASEL_SHIFT   48
#endif
};

struct k3_udma_glue_common {
    struct device *dev;
#ifdef CPSWG_STRUCT_VERSION
    struct device chan_dev;
#endif
    struct udma_dev *udmax;
    const struct udma_tisci_rm *tisci_rm;
    struct k3_ringacc *ringacc;
    u32 src_thread;
    u32 dst_thread;

    u32  hdesc_size;
    bool epib;
    u32  psdata_size;
    u32  swdata_size;
    u32  atype;
#ifdef CPSWG_STRUCT_VERSION
    struct psil_endpoint_config *ep_config;
#endif
};

struct k3_udma_glue_tx_channel {
    struct k3_udma_glue_common common;

    struct udma_tchan *udma_tchanx;
    int udma_tchan_id;

    struct k3_ring *ringtx;
    struct k3_ring *ringtxcq;

    bool psil_paired;

    int virq;

    atomic_t free_pkts;
    bool tx_pause_on_err;
    bool tx_filt_einfo;
    bool tx_filt_pswords;
    bool tx_supr_tdpkt;
#ifdef CPSWG_STRUCT_VERSION
    int udma_tflow_id;
#endif
};

struct k3_udma_glue_rx_flow {
    struct udma_rflow *udma_rflow;
    int udma_rflow_id;
    struct k3_ring *ringrx;
    struct k3_ring *ringrxfdq;

    int virq;
};

struct k3_udma_glue_rx_channel {
    struct k3_udma_glue_common common;

    struct udma_rchan *udma_rchanx;
    int udma_rchan_id;
    bool remote;

    bool psil_paired;

    u32  swdata_size;
    int  flow_id_base;

    struct k3_udma_glue_rx_flow *flows;
    u32 flow_num;
    u32 flows_ready;
};


#define AM65_CPSW_NAV_SW_DATA_SIZE 16
#define AM65_CPSW_MAX_RX_FLOWS  1

#include <linux/dma/k3-udma-glue.h>
void cleanup(void *data, dma_addr_t desc_dma)
{
    return;
}

static int CpswgCmd(void* arg,  ATEMSYS_T_CPSWG_CMD* pConfig)
{
    struct k3_udma_glue_tx_channel** ppTxChn = NULL;
    struct k3_udma_glue_rx_channel** ppRxChn = NULL;
    __u32* pnTxIrq;
    __u32* pnRxIrq;
    ATEMSYS_T_CPSWG_CMD oConfig;
    ATEMSYS_T_DRV_DESC_PRIVATE* pDrvDescPrivate = NULL;
    ATEMSYS_T_DRV_DESC_PRIVATE* pDrvDescPrivateMainEntry = NULL;
    unsigned int dwRetVal = 0x98110000; /* EC_E_ERROR */
    int nRetVal = -1;
    memset(&oConfig, 0, sizeof(ATEMSYS_T_CPSWG_CMD));

    if (NULL == pConfig)
    {
        nRetVal = copy_from_user(&oConfig, (ATEMSYS_T_CPSWG_CMD *)arg, sizeof(ATEMSYS_T_CPSWG_CMD));
    }
    else
    {
        memcpy(&oConfig, pConfig, sizeof(ATEMSYS_T_CPSWG_CMD));
        nRetVal = 0;
    }
    if (0 != nRetVal)
    {
        ERR("CpswgCmd(): failed: %d\n", nRetVal);
        goto Exit;
    }
    if (oConfig.dwIndex >= ATEMSYS_MAX_NUMBER_DRV_INSTANCES)
    {
        dwRetVal = 0x98110002; /* EC_E_INVALIDINDEX */
        nRetVal = 0;
        goto Exit;
    }
    pDrvDescPrivate = S_apDrvDescPrivate[oConfig.dwIndex];
    if (NULL == pDrvDescPrivate)
    {
        ERR("CpswgCmd(): cant find instance\n");
        nRetVal = -EBUSY;
        goto Exit;
    }
    pDrvDescPrivateMainEntry = pDrvDescPrivate;

    /* use CPSWG Instance 0 for allocation, if there is one */
    if (0 != oConfig.dwIndex)
    {
        unsigned int dwIndex = 0;
        ATEMSYS_T_DRV_DESC_PRIVATE* pDrvDescPrivateTmp = NULL;

        for (dwIndex = 0; dwIndex < ATEMSYS_MAX_NUMBER_DRV_INSTANCES; dwIndex++)
        {
            pDrvDescPrivateTmp = S_apDrvDescPrivate[dwIndex];
            if (NULL == pDrvDescPrivateTmp)
                continue;

            if ((0 == pDrvDescPrivateTmp->MacInfo.dwInstance) && (0 == strcmp(pDrvDescPrivateTmp->MacInfo.szIdent,"CPSWG")))
            {
                pDrvDescPrivateMainEntry = S_apDrvDescPrivate[dwIndex];
                break;
            }
        }
    }

    DBG("CpswgCmd(): dwCmd: %d\n", oConfig.dwCmd);
    ppTxChn = (struct k3_udma_glue_tx_channel**)&pDrvDescPrivate->apvTxChan[oConfig.dwChannelIdx];
    ppRxChn = (struct k3_udma_glue_rx_channel**)&pDrvDescPrivate->apvRxChan[oConfig.dwChannelIdx];
    pnTxIrq = &pDrvDescPrivate->anTxIrq[oConfig.dwChannelIdx];
    pnRxIrq = &pDrvDescPrivate->anRxIrq[oConfig.dwChannelIdx];


    switch (oConfig.dwCmd)
    {
    case ATEMSYS_CPSWG_CMD_CONFIG_TX:
    {
        char tx_chn_name[128];
        struct k3_ring_cfg ring_cfg =
        {
            .elm_size = K3_RINGACC_RING_ELSIZE_8,
            .mode = K3_RINGACC_RING_MODE_RING,
            .flags = 0
        };
        struct k3_udma_glue_tx_channel_cfg tx_cfg = { 0 };

        tx_cfg.swdata_size = AM65_CPSW_NAV_SW_DATA_SIZE;
        tx_cfg.tx_cfg = ring_cfg;
        tx_cfg.txcq_cfg = ring_cfg;
        tx_cfg.tx_cfg.size = oConfig.dwRingSize;
        tx_cfg.txcq_cfg.size = oConfig.dwRingSize;
        snprintf(tx_chn_name, sizeof(tx_chn_name), "tx%d", 0);

        *ppTxChn = k3_udma_glue_request_tx_chn(&pDrvDescPrivateMainEntry->pPDev->dev,
                            tx_chn_name,
                            &tx_cfg);
        if (IS_ERR(*ppTxChn))
        {
            ERR("CpswgCmd(): Failed to request tx dma channel %ld\n", PTR_ERR(*ppTxChn));
            *ppTxChn = NULL;
            goto Exit;
        }

        *pnTxIrq = k3_udma_glue_tx_get_irq(*ppTxChn);
        if (*pnTxIrq <= 0)
        {
            ERR("CpswgCmd(): Failed to get tx dma irq %d\n", *pnTxIrq);
            goto Exit;
        }

        {
            struct k3_udma_glue_tx_channel* pData = (struct k3_udma_glue_tx_channel*)*ppTxChn;
            DBG("CpswgCmd(): k3_udma_glue_request_tx_chn(): udma_tchan_id:0x%x, ringtx:0x%x::0x%px, ringtxcq:0x%x::0x%px\n",
            pData->udma_tchan_id,
            pData->ringtx->ring_id, (unsigned char*)NULL + pData->ringtx->ring_mem_dma,
            pData->ringtxcq->ring_id, (unsigned char*)NULL + pData->ringtxcq->ring_mem_dma);

            oConfig.dwChanId = pData->udma_tchan_id;
            oConfig.dwRingId = pData->ringtx->ring_id;
            oConfig.qwRingDma = pData->ringtx->ring_mem_dma;
            oConfig.dwRingSize = pData->ringtx->size;
            oConfig.dwRingFdqId = pData->ringtxcq->ring_id;
            oConfig.qwRingFdqDma = pData->ringtxcq->ring_mem_dma;
            oConfig.dwRingFdqSize = pData->ringtxcq->size;

            nRetVal = copy_to_user((ATEMSYS_T_CPSWG_CMD *)arg, &oConfig, sizeof(ATEMSYS_T_CPSWG_CMD));
            if (0 != nRetVal)
            {
                ERR("CpswgCmd(): copy_to_user() failed: %d\n", nRetVal);
            }
        }
    } break;
    case ATEMSYS_CPSWG_CMD_CONFIG_RX:
    {
        u32  rx_flow_id_base = -1;
        u32 fdqring_id;

        struct k3_udma_glue_rx_channel_cfg rx_cfg = { 0 };

        rx_cfg.swdata_size = AM65_CPSW_NAV_SW_DATA_SIZE;
        rx_cfg.flow_id_num = AM65_CPSW_MAX_RX_FLOWS;
        rx_cfg.flow_id_base = rx_flow_id_base;

        *ppRxChn = k3_udma_glue_request_rx_chn(&pDrvDescPrivateMainEntry->pPDev->dev, "rx", &rx_cfg);
        if (IS_ERR(*ppRxChn)) {
            ERR("CpswgCmd(): Failed to request rx dma channel %ld\n", PTR_ERR(*ppRxChn));
           *ppRxChn = NULL;
            goto Exit;
        }

        rx_flow_id_base = k3_udma_glue_rx_get_flow_id_base(*ppRxChn);
        fdqring_id = K3_RINGACC_RING_ID_ANY;
        /*for*/
        {
            u32 i = 0;
            struct k3_ring_cfg rxring_cfg = {
                .elm_size = K3_RINGACC_RING_ELSIZE_8,
                .mode = K3_RINGACC_RING_MODE_RING,
                .flags = 0,
            };
            struct k3_ring_cfg fdqring_cfg = {
                .elm_size = K3_RINGACC_RING_ELSIZE_8,
                .mode = K3_RINGACC_RING_MODE_MESSAGE,
                .flags = K3_RINGACC_RING_SHARED,
            };
            struct k3_udma_glue_rx_flow_cfg rx_flow_cfg = {
                .rx_cfg = rxring_cfg,
                .rxfdq_cfg = fdqring_cfg,
                .ring_rxq_id = K3_RINGACC_RING_ID_ANY,
                .src_tag_lo_sel = K3_UDMA_GLUE_SRC_TAG_LO_USE_REMOTE_SRC_TAG,
            };

            if (oConfig.bRingFdqUsingRingMode)
            {
                rx_flow_cfg.rxfdq_cfg.mode = K3_RINGACC_RING_MODE_RING;
            }

            rx_flow_cfg.ring_rxfdq0_id = fdqring_id;
            rx_flow_cfg.rx_cfg.size = oConfig.dwRingSize;
            rx_flow_cfg.rxfdq_cfg.size = oConfig.dwRingSize;

            nRetVal = k3_udma_glue_rx_flow_init(*ppRxChn, i, &rx_flow_cfg);
            if (nRetVal) {
                ERR("CpswgCmd(): Failed to init rx flow%d %d\n", i, nRetVal);
                goto Exit;
            }
            if (!i)
                fdqring_id = k3_udma_glue_rx_flow_get_fdq_id(*ppRxChn, i);

            *pnRxIrq = k3_udma_glue_rx_get_irq(*ppRxChn, i);

            if (*pnRxIrq <= 0) {
                ERR("CpswgCmd(): Failed to get rx dma irq %d\n", *pnRxIrq);
                goto Exit;
            }
        }
        {
            struct k3_udma_glue_rx_flow* pData = (struct k3_udma_glue_rx_flow*)(*ppRxChn)->flows;

            DBG("CpswgCmd(): k3_udma_glue_request_tx_chn(): udma_rflow_id:0x%x, rx_flow_id_base:0x%x, ringrx:0x%x::0x%px, ringrxfdq:0x%x::0x%px\n",
            pData->udma_rflow_id, rx_flow_id_base,
            pData->ringrx->ring_id, (unsigned char*)NULL + pData->ringrx->ring_mem_dma,
            pData->ringrxfdq->ring_id, (unsigned char*)NULL + pData->ringrxfdq->ring_mem_dma);

            oConfig.dwChanId = pData->udma_rflow_id;
            oConfig.dwRingId = pData->ringrx->ring_id;
            oConfig.qwRingDma = pData->ringrx->ring_mem_dma;
            oConfig.dwRingSize = pData->ringrx->size;
            oConfig.dwRingFdqId = pData->ringrxfdq->ring_id;
            oConfig.qwRingFdqDma = pData->ringrxfdq->ring_mem_dma;
            oConfig.dwRingFdqSize = pData->ringrxfdq->size;
            oConfig.dwFlowIdBase = rx_flow_id_base;
            oConfig.bRingFdqUsingRingMode = 0;

            nRetVal = copy_to_user((ATEMSYS_T_CPSWG_CMD *)arg, &oConfig, sizeof(ATEMSYS_T_CPSWG_CMD));
            if (0 != nRetVal)
            {
                ERR("CpswgCmd(): copy_to_user() failed: %d\n", nRetVal);
            }
        }
    } break;
    case ATEMSYS_CPSWG_CMD_ENABLE_TX:
    {
        if (NULL == *ppTxChn)
        {
            nRetVal = -1;
            ERR("CpswgCmd(): tx channel not ready %d\n", nRetVal);
            goto Exit;
        }
        nRetVal = k3_udma_glue_enable_tx_chn(*ppTxChn);
        if (nRetVal)
        {
            ERR("CpswgCmd(): k3_udma_glue_enable_tx_chn() failed %d\n", nRetVal);
            goto Exit;
        }

    } break;
    case ATEMSYS_CPSWG_CMD_ENABLE_RX:
    {
        if (NULL == *ppRxChn)
        {
            nRetVal = -1;
            ERR("CpswgCmd(): rx channel not ready %d\n", nRetVal);
            goto Exit;
        }
        nRetVal = k3_udma_glue_enable_rx_chn(*ppRxChn);
        if (nRetVal) {
            ERR("CpswgCmd(): k3_udma_glue_enable_rx_chn() failed %d\n", nRetVal);
            goto Exit;
        }

    } break;
    case ATEMSYS_CPSWG_CMD_DISABLE_TX:
    {
        if (NULL == *ppTxChn)
        {
            nRetVal = -1;
            ERR("CpswgCmd(): tx channel not ready %d\n", nRetVal);
            goto Exit;
        }
        //for (i = 0; i < tx_ch_num; i++)
            k3_udma_glue_tdown_tx_chn(*ppTxChn, false);

        //for (i = 0; i < tx_ch_num; i++)
        {
            k3_udma_glue_reset_tx_chn(*ppTxChn, NULL, cleanup);
            k3_udma_glue_disable_tx_chn(*ppTxChn);
        }
    } break;
    case ATEMSYS_CPSWG_CMD_DISABLE_RX:
    {
        int i = 0;
        if (NULL == *ppRxChn)
        {
            nRetVal = -1;
            ERR("CpswgCmd(): rx channel not ready %d\n", nRetVal);
            goto Exit;
        }
        k3_udma_glue_tdown_rx_chn(*ppRxChn, true);
        for (i = 0; i < AM65_CPSW_MAX_RX_FLOWS; i++)
            k3_udma_glue_reset_rx_chn(*ppRxChn, i, NULL, cleanup, !!i);

        k3_udma_glue_disable_rx_chn(*ppRxChn);
    } break;
    case ATEMSYS_CPSWG_CMD_RELEASE_TX:
    {
        if (NULL == *ppTxChn)
        {
            nRetVal = -1;
            ERR("CpswgCmd(): tx channel not ready %d\n", nRetVal);
            goto Exit;
        }
        k3_udma_glue_release_tx_chn(*ppTxChn);
        *ppTxChn = NULL;
    } break;
    case ATEMSYS_CPSWG_CMD_RELEASE_RX:
    {
        if (NULL == *ppRxChn)
        {
            nRetVal = -1;
            ERR("CpswgCmd(): rx channel not ready %d\n", nRetVal);
            goto Exit;
        }
        k3_udma_glue_release_rx_chn(*ppRxChn);
        *ppRxChn = NULL;
    } break;
    }



Exit:
    return nRetVal;
}



static void CleanCpswgCmd(ATEMSYS_T_DEVICE_DESC* pDevDesc)
{
    ATEMSYS_T_DRV_DESC_PRIVATE* pDrvDescPrivate = NULL;
    ATEMSYS_T_CPSWG_CMD oConfig;
    unsigned int dwChannelIdx = 0;
    unsigned int dwIndex = 0;
    if (pDevDesc == NULL)
    {
       return;
    }
    for (dwIndex = 0; dwIndex < ATEMSYS_MAX_NUMBER_DRV_INSTANCES; dwIndex++)
    {
        if ((NULL != S_apDrvDescPrivate[dwIndex]) && pDevDesc == S_apDrvDescPrivate[dwIndex]->pDevDesc)
        {
            pDrvDescPrivate = S_apDrvDescPrivate[dwIndex];
            break;
        }
    }
    if (pDrvDescPrivate == NULL)
    {
        return;
    }
    for (dwChannelIdx = 0; ATEMSYS_UDMA_CHANNELS > dwChannelIdx; dwChannelIdx++)
    {
        void** ppvTxChn = &pDrvDescPrivate->apvTxChan[dwChannelIdx];
        void** ppvRxChn = &pDrvDescPrivate->apvRxChan[dwChannelIdx];

        if ((NULL != ppvTxChn) && (NULL != *ppvTxChn))
        {
            memset(&oConfig, 0, sizeof(ATEMSYS_T_CPSWG_CMD));
            oConfig.dwIndex = dwIndex;
            oConfig.dwChannelIdx = dwChannelIdx;
            oConfig.dwCmd = ATEMSYS_CPSWG_CMD_DISABLE_TX;
            CpswgCmd(NULL,  &oConfig);
            oConfig.dwCmd = ATEMSYS_CPSWG_CMD_RELEASE_TX;
            CpswgCmd(NULL,  &oConfig);
        }
        if ((NULL != ppvRxChn) && (NULL != *ppvRxChn))
        {
            memset(&oConfig, 0, sizeof(ATEMSYS_T_CPSWG_CMD));
            oConfig.dwIndex = dwIndex;
            oConfig.dwChannelIdx = dwChannelIdx;
            oConfig.dwCmd = ATEMSYS_CPSWG_CMD_DISABLE_RX;
            CpswgCmd(NULL,  &oConfig);
            oConfig.dwCmd = ATEMSYS_CPSWG_CMD_RELEASE_RX;
            CpswgCmd(NULL,  &oConfig);
        }
    }
}
#endif /*#ifdef CONFIG_TI_K3_UDMA*/


static int IoMemCmd(void* arg)
{
    ATEMSYS_T_IOMEM_CMD oIoMem;
    ATEMSYS_T_DRV_DESC_PRIVATE* pDrvDescPrivate = NULL;
    unsigned int dwRetVal = 0;
    int nRetVal = -1;
    unsigned int dwIndex = 0;
    nRetVal = copy_from_user(&oIoMem, (unsigned long long *)arg, sizeof(ATEMSYS_T_IOMEM_CMD));
    if (0 != nRetVal)
    {
        goto Exit;
    }
    if (oIoMem.dwIndex >= ATEMSYS_MAX_NUMBER_DRV_INSTANCES)
    {
        dwRetVal = 0x98110002; /* EC_E_INVALIDINDEX */
        nRetVal = 0;
        goto Exit;
    }
    pDrvDescPrivate = S_apDrvDescPrivate[oIoMem.dwIndex];
    if (NULL == pDrvDescPrivate)
    {
        ERR("IoMemCmd(): cant find instance\n");
        nRetVal = -EBUSY;
        goto Exit;
    }


    if (ATEMSYS_IOMEM_CMD_MAP_PERMANENT == oIoMem.dwCmd)
    {
        for (dwIndex = 0; IOMEMLIST_LENGTH>dwIndex; dwIndex++)
        {
            if (NULL == pDrvDescPrivate->oIoMemList[dwIndex].pbyBase)
            {
                break;
            }
        }
        if (IOMEMLIST_LENGTH < dwIndex)
        {
            nRetVal = -EFAULT;
            goto Exit;
        }
        pDrvDescPrivate->oIoMemList[dwIndex].pbyBase = devm_ioremap(&pDrvDescPrivate->pPDev->dev, oIoMem.qwPhys, oIoMem.dwSize);
        if (NULL == pDrvDescPrivate->oIoMemList[dwIndex].pbyBase )
        {
            pDrvDescPrivate->oIoMemList[dwIndex].pbyBase = NULL;
            nRetVal = -ENOMEM;;
            goto Exit;
        }
        pDrvDescPrivate->oIoMemList[dwIndex].qwPhys = oIoMem.qwPhys;
        pDrvDescPrivate->oIoMemList[dwIndex].dwSize = oIoMem.dwSize;
        DBG("IoMemCmd(): ATEMSYS_IOMEM_CMD_MAP_PERMANENT Virt:0x%px, Phys:0x%px, Size:0x%08x\n", pDrvDescPrivate->oIoMemList[dwIndex].pbyBase, (unsigned char*)NULL + oIoMem.qwPhys, oIoMem.dwSize);
    }
    else
    {
        for (dwIndex = 0; IOMEMLIST_LENGTH>dwIndex; dwIndex++)
        {
            if (pDrvDescPrivate->oIoMemList[dwIndex].qwPhys == oIoMem.qwPhys)
            {
                break;
            }
        }
        if (IOMEMLIST_LENGTH == dwIndex)
        {
            nRetVal = EFAULT;
            goto Exit;
        }

        if (ATEMSYS_IOMEM_CMD_UNMAP_PERMANENT == oIoMem.dwCmd)
        {
            devm_iounmap(&pDrvDescPrivate->pPDev->dev, pDrvDescPrivate->oIoMemList[dwIndex].pbyBase);
            pDrvDescPrivate->oIoMemList[dwIndex].pbyBase = NULL;
            pDrvDescPrivate->oIoMemList[dwIndex].qwPhys = 0;
            pDrvDescPrivate->oIoMemList[dwIndex].dwSize = 0;
        }
        else
        {
            if (ATEMSYS_IOMEM_CMD_WRITE == oIoMem.dwCmd)
            {
                if (sizeof(unsigned int)/* 4 */  == oIoMem.dwDataSize)
                    *(unsigned int*)(pDrvDescPrivate->oIoMemList[dwIndex].pbyBase + oIoMem.dwOffset) = oIoMem.dwData[0];
                else if (sizeof(unsigned long long)/* 8 */ == oIoMem.dwDataSize)
                {
                    *(unsigned long long*)(pDrvDescPrivate->oIoMemList[dwIndex].pbyBase + oIoMem.dwOffset) = *(unsigned long long*)&oIoMem.dwData[0];
                }
                else
                {
                    int i = 0;
                    for (i = 0; i < oIoMem.dwDataSize; i++)
                    {
                        ((unsigned char*)(pDrvDescPrivate->oIoMemList[dwIndex].pbyBase + oIoMem.dwOffset))[i] = ((unsigned char*)oIoMem.dwData)[i];
                    }
                }
            }
            else if (ATEMSYS_IOMEM_CMD_READ == oIoMem.dwCmd)
            {
                if (sizeof(unsigned int)/* 4 */ == oIoMem.dwDataSize)
                    oIoMem.dwData[0] = *(unsigned int*)(pDrvDescPrivate->oIoMemList[dwIndex].pbyBase + oIoMem.dwOffset);
                else
                {
                    int i = 0;
                    for (i = 0; i < oIoMem.dwDataSize; i++)
                    {
                        ((unsigned char*)oIoMem.dwData)[i] = ((unsigned char*)(pDrvDescPrivate->oIoMemList[dwIndex].pbyBase + oIoMem.dwOffset))[i];
                    }
                }
                nRetVal = copy_to_user((unsigned long long *)arg, &oIoMem, sizeof(ATEMSYS_T_IOMEM_CMD));
                if (0 != nRetVal)
                {
                    goto Exit;
                }
            }
        }
    }
    nRetVal = 0;
Exit:
        return nRetVal;
}

static void CleanIoMemCmd(ATEMSYS_T_DEVICE_DESC* pDevDesc)
{
    ATEMSYS_T_DRV_DESC_PRIVATE* pDrvDescPrivate = NULL;
    unsigned int dwIndex = 0;
    if (pDevDesc == NULL)
    {
        return;
    }
    for (dwIndex = 0; dwIndex < ATEMSYS_MAX_NUMBER_DRV_INSTANCES; dwIndex++)
    {
        pDrvDescPrivate = S_apDrvDescPrivate[dwIndex];
        if (NULL == pDrvDescPrivate)
            continue;
        if (pDrvDescPrivate->pDevDesc == pDevDesc)
            break;
        pDrvDescPrivate = NULL;
    }
    if (NULL == pDrvDescPrivate)
    {
        return;
    }
    for (dwIndex = 0; IOMEMLIST_LENGTH>dwIndex; dwIndex++)
    {
        if (NULL != pDrvDescPrivate->oIoMemList[dwIndex].pbyBase )
        {
            devm_iounmap(&pDrvDescPrivate->pPDev->dev, pDrvDescPrivate->oIoMemList[dwIndex].pbyBase);
            pDrvDescPrivate->oIoMemList[dwIndex].pbyBase = NULL;
            pDrvDescPrivate->oIoMemList[dwIndex].qwPhys = 0;
            pDrvDescPrivate->oIoMemList[dwIndex].dwSize = 0;
        }
    }
}
#endif /*#ifdef INCLUDE_ATEMSYS_DT_DRIVER)*/


#if ((defined CONFIG_SMP) && (LINUX_VERSION_CODE > KERNEL_VERSION(5,14,0)))
static int SetIntCpuAffinityIoctl(ATEMSYS_T_DEVICE_DESC* pDevDesc, unsigned long ioctlParam, size_t size)
{
    int nRetVal = -EIO;
    ATEMSYS_T_IRQ_DESC* pIrqDesc = &(pDevDesc->irqDesc);
    struct cpumask* pCpuMask = 0;

    if (size > sizeof(struct cpumask))
    {
        ERR("SetIntCpuAffinityIoctl: cpu mask length mismatch\n");
        nRetVal = -EINVAL;
        goto Exit;
    }

    /* prepare cpu affinity mask*/
    pCpuMask = (struct cpumask*)kzalloc(sizeof(struct cpumask), GFP_KERNEL);
    if (NULL == pCpuMask)
    {
        ERR("SetIntCpuAffinityIoctl: no memory\n");
        nRetVal = -ENOMEM;
        goto Exit;
    }
    memset(pCpuMask, 0, sizeof(struct cpumask)>size? sizeof(struct cpumask): size);

    nRetVal = copy_from_user(pCpuMask, (struct cpumask *)ioctlParam, size);
    if (0 != nRetVal)
    {
        ERR("SetIntCpuAffinityIoctl failed: %d\n", nRetVal);
        goto Exit;
    }

    /* set cpu affinity mask*/
    if (pIrqDesc->irq)
    {
        nRetVal = irq_force_affinity(pIrqDesc->irq, pCpuMask);
        if (0 != nRetVal)
        {
            ERR("SetIntCpuAffinityIoctl: irq_force_affinity failed: %d\n", nRetVal);
            nRetVal = -EIO;
            goto Exit;
        }
    }

    nRetVal = 0;
Exit:
    if (NULL != pCpuMask)
        kfree(pCpuMask);

    return nRetVal;
}
#endif /* #if ((defined CONFIG_SMP) && (LINUX_VERSION_CODE > KERNEL_VERSION(5,14,0))) */

#if (defined CONFIG_PCI)
static void dev_pci_release(ATEMSYS_T_DEVICE_DESC* pDevDesc)
{
#if (defined INCLUDE_ATEMSYS_PCI_DRIVER)
    if (NULL != pDevDesc->pPciDrvDesc)
    {
        INF("pci_release: Disconnect from PCI device driver %s \n", pci_name(pDevDesc->pPcidev));
        pDevDesc->pPciDrvDesc->pDevDesc = NULL;
#if !(defined CONFIG_XENO_COBALT)
        pDevDesc->pPcidev               = NULL;
#endif
        pDevDesc->pPciDrvDesc           = NULL;
    }
    else
#endif

   if (pDevDesc->pPcidev)
   {
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,29)) && (LINUX_VERSION_CODE < KERNEL_VERSION(6,0,0))
      /* Make sure bus master DMA is disabled if the DMA buffers are finally released */
      pci_clear_master(pDevDesc->pPcidev);
#endif
      pci_release_regions(pDevDesc->pPcidev);

#if (LINUX_VERSION_CODE < KERNEL_VERSION(6,0,0))
      pci_disable_msi(pDevDesc->pPcidev);
#endif

      pci_disable_device(pDevDesc->pPcidev);

      INF("pci_release: PCI device %s released\n", pci_name(pDevDesc->pPcidev));

#if !(defined CONFIG_XENO_COBALT)
      pDevDesc->pPcidev = NULL;
#endif
   }
}
#endif /* CONFIG_PCI */

#if (defined CONFIG_XENO_COBALT)
static int dev_interrupt_handler(rtdm_irq_t* irq_handle)
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
static irqreturn_t dev_interrupt_handler(int nIrq, void* pParam)
{
   ATEMSYS_T_DEVICE_DESC* pDevDesc = (ATEMSYS_T_DEVICE_DESC*) pParam;
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
static int device_open(struct rtdm_fd* fd, int oflags)
{
   ATEMSYS_T_DEVICE_DESC* pDevDesc = (ATEMSYS_T_DEVICE_DESC*) rtdm_fd_to_private(fd);
   memset(pDevDesc, 0, sizeof(ATEMSYS_T_DEVICE_DESC));
   rtdm_event_init(&pDevDesc->irqDesc.irq_event, 0);
   INF("device_open %s\n", rtdm_fd_device(fd)->label);
#else
static int device_open(struct inode* inode, struct file* file)
{
   ATEMSYS_T_DEVICE_DESC* pDevDesc;

   INF("device_open(0x%px)\n", file);

   /* create device descriptor */
   pDevDesc = (ATEMSYS_T_DEVICE_DESC*) kzalloc(sizeof(ATEMSYS_T_DEVICE_DESC), GFP_KERNEL);
   if (pDevDesc == NULL)
   {
      return -ENOMEM;
   }

   file->private_data = (void*) pDevDesc;

   /* Add descriptor to descriptor list */
   mutex_lock(&S_mtx);
   list_add(&pDevDesc->list, &S_DevNode.list);
   mutex_unlock(&S_mtx);
   try_module_get(THIS_MODULE);
#endif /* CONFIG_XENO_COBALT */

   /* use module's platform device for memory maping and allocation */
   pDevDesc->pPlatformDev = S_pPlatformDev;

   return DRIVER_SUCCESS;
}

#if (defined CONFIG_XENO_COBALT)
static void device_release(struct rtdm_fd* fd)
{
    ATEMSYS_T_DEVICE_DESC* pDevDesc = (ATEMSYS_T_DEVICE_DESC*) rtdm_fd_to_private(fd);
    ATEMSYS_T_IRQ_DESC* pIrqDesc = NULL;
#else
static int device_release(struct inode* inode, struct file* file)
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
       CleanIoMemCmd(pDevDesc);

 #ifdef CONFIG_TI_K3_UDMA
       CleanCpswgCmd(pDevDesc);
 #endif

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
static ssize_t device_read(struct rtdm_fd* fd, void* bufp, size_t len)
{
   ATEMSYS_T_DEVICE_DESC*   pDevDesc = (ATEMSYS_T_DEVICE_DESC*) rtdm_fd_to_private(fd);
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
      struct file* filp,   /* see include/linux/fs.h   */
      char __user* bufp,   /* buffer to be filled with data */
      size_t       len,    /* length of the buffer     */
      loff_t*      ppos)
{

   ATEMSYS_T_DEVICE_DESC*   pDevDesc = (ATEMSYS_T_DEVICE_DESC*) filp->private_data;
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
static int device_mmap(struct rtdm_fd* fd, struct vm_area_struct* vma)
{
   ATEMSYS_T_DEVICE_DESC*   pDevDesc = (ATEMSYS_T_DEVICE_DESC*) rtdm_fd_to_private(fd);
#else
static int device_mmap(struct file* filp, struct vm_area_struct* vma)
{
   ATEMSYS_T_DEVICE_DESC*   pDevDesc = filp->private_data;
#endif /* CONFIG_XENO_COBALT */

   int         nRet = -EIO;
   u32         dwLen;
   void*       pVa = NULL;
   dma_addr_t  dmaAddr;
   ATEMSYS_T_MMAP_DESC* pMmapNode;

   DBG("mmap: vm_pgoff 0x%px vm_start = 0x%px vm_end = 0x%px\n",
         (void*) vma->vm_pgoff, (void*) vma->vm_start, (void*) vma->vm_end);

   if (pDevDesc == NULL)
   {
      ERR("mmap: Invalid device dtor\n");
      goto Exit;
   }

   dwLen = PAGE_UP(vma->vm_end - vma->vm_start);
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0))
   vm_flags_set(vma, VM_RESERVED | VM_LOCKED | VM_DONTCOPY);
#else
   vma->vm_flags |= VM_RESERVED | VM_LOCKED | VM_DONTCOPY;
#endif

   /* map device IO memory */
   if (vma->vm_pgoff != 0)
   {

      /* avoid swapping, request IO memory */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0))
      vm_flags_set(vma, VM_IO);
#else
      vma->vm_flags |= VM_IO;
#endif

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
           (u64) (((u64)vma->vm_pgoff) << PAGE_SHIFT), (void*) vma->vm_start, dwLen);

#if (defined DEBUG_IOREMAP)
      {
        volatile unsigned char* ioaddr;
        unsigned long ioBase = vma->vm_pgoff << PAGE_SHIFT;
        INF("try to remap %p\n", (void*)ioBase);
        /* DEBUG Map device's IO memory into kernel space pagetables */
        ioaddr = (volatile unsigned char*) ioremap_nocache(ioBase, dwLen);
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
#if ( (LINUX_VERSION_CODE >= KERNEL_VERSION(5,0,0)) \
    || (defined __aarch64__) || (defined __riscv)\
    || ((defined __arm__) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0))) \
    || ((defined __i386__) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,9,0))) \
    || ((defined __amd64__) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,9,0))) )
         pVa = dma_alloc_coherent(&pDevDesc->pPcidev->dev, dwLen, &dmaAddr, GFP_KERNEL);
         if (NULL == pVa)
         {
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,12,55))
            if (dma_get_mask(&pDevDesc->pPcidev->dev) != DMA_BIT_MASK(64))
            {
                int nRes = 0;
                nRes = dma_set_mask_and_coherent(&pDevDesc->pPcidev->dev, DMA_BIT_MASK(64));
                if (!nRes)
                {
                    pVa = dma_alloc_coherent(&pDevDesc->pPcidev->dev, dwLen, &dmaAddr, GFP_KERNEL);
                }
            }
            if (NULL == pVa)
#endif
            {
                ERR("mmap: dma_alloc_coherent failed\n");
                nRet = -ENOMEM;
                goto Exit;
            }
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
#if (defined __arm__) || (defined __aarch64__) || (defined __riscv)
 #if (defined CONFIG_OF)
         OF_DMA_CONFIGURE(&pDevDesc->pPlatformDev->dev,pDevDesc->pPlatformDev->dev.of_node);
 #endif
         /* dma_alloc_coherent() is currently not tested on PPC.
          * TODO test this and remove legacy dev_dma_alloc()
          */
         pVa = dmam_alloc_coherent(&pDevDesc->pPlatformDev->dev, dwLen, &dmaAddr, GFP_KERNEL);
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,12,55))
         if (NULL == pVa)
         {
            if (dma_get_mask(&pDevDesc->pPlatformDev->dev) != DMA_BIT_MASK(64))
            {
               int nRes = 0;
               nRes = dma_set_mask_and_coherent(&pDevDesc->pPlatformDev->dev, DMA_BIT_MASK(64));
               if (!nRes)
               {
                  pVa = dmam_alloc_coherent(&pDevDesc->pPlatformDev->dev, dwLen, &dmaAddr, GFP_KERNEL);
               }
            }
         }
#endif
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
#if (!(defined ATEMSYS_LEGACY_DMA) && (LINUX_VERSION_CODE < KERNEL_VERSION(5,4,0))) || ((defined ATEMSYS_LEGACY_DMA) && (0 != ATEMSYS_LEGACY_DMA))
      {
         unsigned int dwDmaPfn = 0;

#if (defined __arm__) || (defined __aarch64__) || (defined __riscv)
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
            const struct bus_dma_region* map = pDevDesc->pPcidev->dev.dma_range_map;
            unsigned long dma_pfn_offset = ((map->offset) >> PAGE_SHIFT);
            dwDmaPfn = dwDmaPfn + dma_pfn_offset;
            INF("mmap: remap_pfn_range dma pfn 0x%x, offset pfn 0x%x\n",
                        dwDmaPfn, (u32)dma_pfn_offset);
         }
  #endif /* (LINUX_VERSION_CODE < KERNEL_VERSION(5,10,0))*/
 #endif /* (defined CONFIG_PCI) */
#if (!defined ATEMSYS_DONT_SET_NONCACHED_DMA_PAGEPROTECTIONLFAG)
         vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
#endif
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
#else /* #if (defined ATEMSYS_LEGACY_DMA) */
      {
         struct device* pDmaDev = NULL;

 #if (defined CONFIG_PCI)
         if (NULL != pDevDesc->pPcidev)
         {
            pDmaDev = &pDevDesc->pPcidev->dev;
         }
         else
 #endif /* (defined CONFIG_PCI) */
         if (NULL != pDevDesc->pPlatformDev)
         {
            pDmaDev = &pDevDesc->pPlatformDev->dev;
         }

#if ((defined __arm__) || (defined __aarch64__) || (defined __riscv)) && (!defined ATEMSYS_DONT_SET_NONCACHED_DMA_PAGEPROTECTIONLFAG)
         vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
#endif
            /* for Platform Device */
         nRet = dma_mmap_coherent(pDmaDev,
                                     vma,       /* user space mapping                   */
                                     pVa,       /* kernel virtual address               */
                                     dmaAddr,   /* Phys address                         */
                                     dwLen);    /* size         */
         if (nRet < 0)
         {
            ERR("dma_mmap_coherent failed\n");
            goto ExitAndFree;
         }
      }
#endif /* #if (defined ATEMSYS_LEGACY_DMA) */

      /* Write the physical DMA address into the first 4 bytes of allocated memory */
      /* If there is 64 bit DMA support write upper part into the the next 4 byte  */
      if (pDevDesc->bSupport64BitDma)
      {
         ((u32*) pVa)[0] = (u32)((u64)dmaAddr & 0xFFFFFFFF);
         ((u32*) pVa)[1] = (u32)(((u64)dmaAddr >> 32) & 0xFFFFFFFF);
      }
      else
      {
         *((u32*) pVa) = (u32) dmaAddr;
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

      INF("mmap: mapped DMA memory, Phys:0x%px KVirt:0x%px UVirt:0x%px Size:%u\n",
             (void*)(unsigned long)dmaAddr, (void*)pVa, (void*)vma->vm_start, dwLen);
   }

   nRet = 0;

   goto Exit;

ExitAndFree:

   if (pVa == NULL) goto Exit;

#if (defined CONFIG_PCI)
   if (pDevDesc->pPcidev != NULL)
   {
#if ( (LINUX_VERSION_CODE >= KERNEL_VERSION(5,0,0)) \
    || (defined __aarch64__)  || (defined __riscv)\
    || ((defined __arm__) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0))) \
    || ((defined __i386__) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,9,0))) \
    || ((defined __amd64__) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,9,0))) )
      dma_free_coherent(&pDevDesc->pPcidev->dev, dwLen, pVa, dmaAddr);
#else
      pci_free_consistent(pDevDesc->pPcidev, dwLen, pVa, dmaAddr);
#endif
   }
   else
#endif
   {
#if (defined __arm__) || (defined __aarch64__) || (defined __riscv)
      dmam_free_coherent(&pDevDesc->pPlatformDev->dev, dwLen, pVa, dmaAddr);
#else
      dev_dma_free(dwLen, pVa);
#endif
   }

Exit:
   return nRet;
}


/*
 * This function is called whenever a process tries to do an ioctl on our
 * device file.
 *
 * If the ioctl is write or read/write (meaning output is returned to the
 * calling process), the ioctl call returns the output of this function.
 *
 */
#if (defined CONFIG_XENO_COBALT)
static int atemsys_ioctl(struct rtdm_fd* fd, unsigned int cmd, void __user* user_arg)
{
   ATEMSYS_T_DEVICE_DESC*   pDevDesc = (ATEMSYS_T_DEVICE_DESC*) rtdm_fd_to_private(fd);
   unsigned long   arg = (unsigned long) user_arg;
#else
static long atemsys_ioctl(
      struct file* file,
      unsigned int cmd,
      unsigned long arg)
{
   ATEMSYS_T_DEVICE_DESC*   pDevDesc = file->private_data;
#endif /* CONFIG_XENO_COBALT */

   int nRetVal = -EFAULT;

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
         nRetVal = ioctl_pci_finddevice(pDevDesc, arg, _IOC_SIZE(cmd)); /* size determines version */
         if (0 != nRetVal)
         {
           /* be quiet. ioctl may fail */
           goto Exit;
         }
      } break;
      case ATEMSYS_IOCTL_PCI_CONF_DEVICE_v1_0_00:
      case ATEMSYS_IOCTL_PCI_CONF_DEVICE_v1_3_05:
      case ATEMSYS_IOCTL_PCI_CONF_DEVICE_v1_4_12:
      {
         nRetVal = ioctl_pci_configure_device(pDevDesc, arg, _IOC_SIZE(cmd)); /* size determines version */
         if (0 != nRetVal)
         {
            ERR("ioctl ATEMSYS_IOCTL_PCI_CONF_DEVICE failed: %d\n", nRetVal);
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
         nRetVal = ioctl_int_connect(pDevDesc, arg);
         if (0 != nRetVal)
         {
            ERR("ioctl ATEMSYS_IOCTL_INT_CONNECT failed: %d\n", nRetVal);
            goto Exit;
         }
      } break;

      case ATEMSYS_IOCTL_INT_DISCONNECT:
      {
         nRetVal = dev_int_disconnect(pDevDesc);
         if (0 != nRetVal)
         {
            /* be quiet. ioctl may fail */
            goto Exit;
         }
      } break;

      case ATEMSYS_IOCTL_INT_INFO:
      {
         nRetVal = ioctl_intinfo(pDevDesc, arg);
         if (0 != nRetVal)
         {
            ERR("ioctl ATEMSYS_IOCTL_INT_INFO failed: %d\n", nRetVal);
            goto Exit;
         }
      } break;

      case ATEMSYS_IOCTL_MOD_GETVERSION:
      {
         __u32 dwVersion = USE_ATEMSYS_API_VERSION;

#if (defined CONFIG_XENO_COBALT)
         nRetVal = rtdm_safe_copy_to_user(fd, user_arg, &dwVersion, sizeof(__u32));
#else
         nRetVal = put_user(dwVersion, (__u32*)arg);
#endif /* CONFIG_XENO_COBALT */

         if (0 != nRetVal)
         {
            ERR("ioctl ATEMSYS_IOCTL_MOD_GETVERSION failed: %d\n", nRetVal);
            goto Exit;
         }
      } break;

      case ATEMSYS_IOCTL_MOD_SET_API_VERSION:
      {
         __u32 dwApiVersion = 0;

#if (defined CONFIG_XENO_COBALT)
         nRetVal = rtdm_safe_copy_from_user(fd, &dwApiVersion, user_arg, sizeof(__u32));
#else
         nRetVal = get_user(dwApiVersion, (__u32*)arg);
#endif

         /* activate supported features */
         if (EC_ATEMSYSVERSION(1,4,15) <= dwApiVersion)
         {
            pDevDesc->bSupport64BitDma = true;
         }

         if (0 != nRetVal)
         {
            ERR("ioctl ATEMSYS_IOCTL_MOD_SETVERSION failed: %d\n", nRetVal);
            goto Exit;
         }
      } break;
#if ((defined CONFIG_SMP) && (LINUX_VERSION_CODE > KERNEL_VERSION(5,14,0)))
      case ATEMSYS_IOCTL_INT_SET_CPU_AFFINITY:
      {
          nRetVal = SetIntCpuAffinityIoctl(pDevDesc, arg, _IOC_SIZE(cmd));
          if (0 != nRetVal)
          {
              ERR("ioctl ATEMSYS_IOCTL_INT_SET_CPU_AFFINITY failed: %d\n", nRetVal);
              goto Exit;
          }
      } break;
#endif

#if (defined INCLUDE_ATEMSYS_DT_DRIVER)
    case ATEMSYS_IOCTL_IOMEM_CMD:
    {
        nRetVal = IoMemCmd((void*)arg);
        if (0 != nRetVal)
        {
            ERR("ioctl ATEMSYS_IOCTL_IOMEM_CMD failed: 0x%x\n", nRetVal);
            goto Exit;
        }
    } break;


#ifdef CONFIG_TI_K3_UDMA
    case ATEMSYS_IOCTL_CPSWG_CMD:
    {
        nRetVal = CpswgCmd((__u32*)arg, NULL);
        if (0 != nRetVal)
        {
            ERR("ioctl ATEMSYS_IOCTL_CPSWG_CMD failed: 0x%x\n", nRetVal);
            goto Exit;
        }
    } break;
#endif /*#ifdef CONFIG_TI_K3_UDMA*/

    case ATEMSYS_IOCTL_GET_MAC_INFO:
    {
        nRetVal = GetMacInfoIoctl(pDevDesc, arg);
        if (0 != nRetVal)
        {
            ERR("ioctl ATEMSYS_IOCTL_GET_MAC_INFO failed: 0x%x\n", nRetVal);
            goto Exit;
        }
    } break;
    case ATEMSYS_IOCTL_PHY_START_STOP:
    {
        nRetVal = PhyStartStopIoctl(arg);
        if (0 != nRetVal)
        {
            ERR("ioctl ATEMSYS_IOCTL_PHY_START_STOP failed: %d\n", nRetVal);
            goto Exit;
        }
    } break;
    case ATEMSYS_IOCTL_GET_MDIO_ORDER:
    {
        nRetVal = GetMdioOrderIoctl(arg);
        if (0 != nRetVal)
        {
            ERR("ioctl ATEMSYS_IOCTL_GET_MDIO_ORDER failed: %d\n", nRetVal);
            goto Exit;
        }
    } break;
    case ATEMSYS_IOCTL_RETURN_MDIO_ORDER:
    {
        nRetVal = ReturnMdioOrderIoctl(arg);
        if (0 != nRetVal)
        {
            ERR("ioctl ATEMSYS_IOCTL_RETURN_MDIO_ORDER failed: %d\n", nRetVal);
            goto Exit;
        }
    } break;
    case ATEMSYS_IOCTL_GET_PHY_INFO:
    {
        nRetVal = GetPhyInfoIoctl(arg);
        if (0 != nRetVal)
        {
            ERR("ioctl ATEMSYS_IOCTL_GET_PHY_INFO failed: %d\n", nRetVal);
            goto Exit;
        }
      } break;
    case ATEMSYS_IOCTL_PHY_RESET:
    {
        nRetVal = PhyResetIoctl(arg);
        if (0 != nRetVal)
        {
            ERR("ioctl ATEMSYS_IOCTL_PHY_RESET failed: %d\n", nRetVal);
            goto Exit;
        }
    } break;
#endif /* INCLUDE_ATEMSYS_DT_DRIVER */

      default:
      {
         nRetVal = -EOPNOTSUPP;
         goto Exit;
      } /* no break */
   }

   nRetVal = DRIVER_SUCCESS;

Exit:
   return nRetVal;
}

#if (defined CONFIG_COMPAT) && !(defined CONFIG_XENO_COBALT)
/*
 * ioctl processing for 32 bit process on 64 bit system
 */
static long atemsys_compat_ioctl(
      struct file*  file,
      unsigned int  cmd,
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
    ATEMSYS_T_MAC_INFO oInfo;
    ATEMSYS_T_DRV_DESC_PRIVATE* pDrvDescPrivate = NULL;
    unsigned int dwRetVal = 0x98110000; /* EC_E_ERROR */
    int nRetVal = -1;
    unsigned int i = 0;

    memset(&oInfo, 0, sizeof(ATEMSYS_T_MAC_INFO));
    nRetVal = copy_from_user(&oInfo, (ATEMSYS_T_MAC_INFO *)ioctlParam, sizeof(ATEMSYS_T_MAC_INFO));
    if (0 != nRetVal)
    {
        ERR("GetMacInfoIoctl failed: %d\n", nRetVal);
        goto Exit;
    }

    for (i = 0; i < ATEMSYS_MAX_NUMBER_DRV_INSTANCES; i++)
    {
        if (NULL == S_apDrvDescPrivate[i])
        {
            continue;
        }
        if ((0 == strcmp(S_apDrvDescPrivate[i]->MacInfo.szIdent, oInfo.szIdent)) &&
            (S_apDrvDescPrivate[i]->MacInfo.dwInstance == oInfo.dwInstance))
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

        oInfo.qwRegAddr            = pDrvDescPrivate->MacInfo.qwRegAddr;
        oInfo.dwRegSize            = pDrvDescPrivate->MacInfo.dwRegSize;
        oInfo.dwStatus             = pDrvDescPrivate->MacInfo.dwStatus;
        oInfo.ePhyMode             = pDrvDescPrivate->MacInfo.ePhyMode;
        oInfo.dwIndex              = pDrvDescPrivate->MacInfo.dwIndex;
        oInfo.bNoMdioBus           = pDrvDescPrivate->MacInfo.bNoMdioBus;
        oInfo.dwPhyAddr            = pDrvDescPrivate->MacInfo.dwPhyAddr;
        oInfo.bPhyResetSupported   = pDrvDescPrivate->MacInfo.bPhyResetSupported;

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
    oInfo.dwErrorCode = dwRetVal;
    nRetVal = copy_to_user((ATEMSYS_T_MAC_INFO *)ioctlParam, &oInfo, sizeof(ATEMSYS_T_MAC_INFO));
    if (0 != nRetVal)
    {
        ERR("GetMacInfoIoctl failed: %d\n", nRetVal);
    }
    return nRetVal;
}

static int PhyStartStopIoctl( unsigned long ioctlParam)
{
    ATEMSYS_T_PHY_START_STOP_INFO oPhyStartStopInfo;
    ATEMSYS_T_DRV_DESC_PRIVATE* pDrvDescPrivate = NULL;
    unsigned int dwRetVal = 0x98110000; /* EC_E_ERROR */
    int nRetVal = -1;
    memset(&oPhyStartStopInfo, 0, sizeof(ATEMSYS_T_PHY_START_STOP_INFO));
    nRetVal = copy_from_user(&oPhyStartStopInfo, (ATEMSYS_T_PHY_START_STOP_INFO *)ioctlParam, sizeof(ATEMSYS_T_PHY_START_STOP_INFO));
    if (0 != nRetVal)
    {
        ERR("PhyStartStopIoctl failed: %d\n", nRetVal);
        goto Exit;
    }
    if (oPhyStartStopInfo.dwIndex >= ATEMSYS_MAX_NUMBER_DRV_INSTANCES)
    {
        dwRetVal = 0x98110002; /* EC_E_INVALIDINDEX */
        nRetVal = 0;
        goto Exit;
    }
    pDrvDescPrivate = S_apDrvDescPrivate[oPhyStartStopInfo.dwIndex];
    if (NULL == pDrvDescPrivate)
    {
        dwRetVal = 0x9811000C; /* EC_E_NOTFOUND*/
        nRetVal = 0;
        goto Exit;
    }
    if (oPhyStartStopInfo.bStart)
    {
#if (defined CONFIG_XENO_COBALT)
        mutex_lock(&S_oAtemsysWorkerThreadDesc.WorkerTask_mutex);
        if (NULL == S_oAtemsysWorkerThreadDesc.pfNextTask)
        {
            S_oAtemsysWorkerThreadDesc.pfNextTask = StartPhyThread;
            S_oAtemsysWorkerThreadDesc.pNextTaskData = (void*)pDrvDescPrivate->pPDev;
        }
        else
        {
            mutex_unlock(&S_oAtemsysWorkerThreadDesc.WorkerTask_mutex);
            ERR("PhyStartStopIoctl: StartPhy failed! WorkerThread is busy!\n");
            nRetVal = -EAGAIN;
            goto Exit;
        }
        mutex_unlock(&S_oAtemsysWorkerThreadDesc.WorkerTask_mutex);
#else
        pDrvDescPrivate->etx_thread_StartPhy = kthread_create(StartPhyThread,(void*)pDrvDescPrivate->pPDev,"StartPhyThread");
        if(NULL == pDrvDescPrivate->etx_thread_StartPhy)
        {
            ERR("PhyStartStopIoctl: Cannot create kthread for StartPhyThread\n");
            nRetVal = -EAGAIN;
            goto Exit;
        }
        wake_up_process(pDrvDescPrivate->etx_thread_StartPhy);
#endif /*#if (defined CONFIG_XENO_COBALT)*/
    }
    else
    {
#if (defined CONFIG_XENO_COBALT)
        mutex_lock(&S_oAtemsysWorkerThreadDesc.WorkerTask_mutex);
        if (NULL == S_oAtemsysWorkerThreadDesc.pfNextTask)
        {
            S_oAtemsysWorkerThreadDesc.pfNextTask = StopPhyThread;
            S_oAtemsysWorkerThreadDesc.pNextTaskData = (void*)pDrvDescPrivate->pPDev;
        }
        else
        {
            mutex_unlock(&S_oAtemsysWorkerThreadDesc.WorkerTask_mutex);
            ERR("PhyStartStopIoctl: StopPhy failed! WorkerThread is busy!\n");
            nRetVal = -EAGAIN;
            goto Exit;
        }
        mutex_unlock(&S_oAtemsysWorkerThreadDesc.WorkerTask_mutex);
#else
        pDrvDescPrivate->etx_thread_StopPhy = kthread_create(StopPhyThread,(void*)pDrvDescPrivate->pPDev,"StopPhyThread");
        if(NULL == pDrvDescPrivate->etx_thread_StopPhy)
        {
            ERR("PhyStartStopIoctl: Cannot create kthread for StopPhyThread\n");
            nRetVal = -EAGAIN;
            goto Exit;
        }
        wake_up_process(pDrvDescPrivate->etx_thread_StopPhy);
#endif /* #if (defined CONFIG_XENO_COBALT) */
    }
    nRetVal = 0;
    dwRetVal = 0; /* EC_E_NOERROR */
Exit:
    oPhyStartStopInfo.dwErrorCode = dwRetVal;

    nRetVal = copy_to_user((ATEMSYS_T_PHY_START_STOP_INFO *)ioctlParam, &oPhyStartStopInfo, sizeof(ATEMSYS_T_PHY_START_STOP_INFO));
    if (0 != nRetVal)
    {
        ERR("PhyStartStopIoctl failed: %d\n", nRetVal);
    }
    return nRetVal;
}


static int GetMdioOrderIoctl( unsigned long ioctlParam)
{
    ATEMSYS_T_DRV_DESC_PRIVATE* pDrvDescPrivate = NULL;
    ATEMSYS_T_MDIO_ORDER oOrder;
    bool bLocked = false;
    unsigned int dwRetVal = 0x98110000; /* EC_E_ERROR */
    int nRetVal = -1;
    memset(&oOrder, 0, sizeof(ATEMSYS_T_MDIO_ORDER));
    nRetVal = copy_from_user(&oOrder, (ATEMSYS_T_MDIO_ORDER *)ioctlParam, sizeof(ATEMSYS_T_MDIO_ORDER));
    if (0 != nRetVal)
    {
        ERR("GetMdioOrderIoctl failed: %d\n", nRetVal);
        goto Exit;
    }
    if (oOrder.dwIndex >= ATEMSYS_MAX_NUMBER_DRV_INSTANCES)
    {
        dwRetVal = 0x98110002; /* EC_E_INVALIDINDEX */
        nRetVal = 0;
        goto Exit;
    }
    pDrvDescPrivate = S_apDrvDescPrivate[oOrder.dwIndex];
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
            oOrder.bInUse        = pDrvDescPrivate->MdioOrder.bInUse;
            oOrder.bInUseByIoctl = pDrvDescPrivate->MdioOrder.bInUseByIoctl;
            oOrder.bWriteOrder   = pDrvDescPrivate->MdioOrder.bWriteOrder;
            oOrder.wMdioAddr     = pDrvDescPrivate->MdioOrder.wMdioAddr;
            oOrder.wReg          = pDrvDescPrivate->MdioOrder.wReg;
            oOrder.wValue        = pDrvDescPrivate->MdioOrder.wValue;
        }
    }

    dwRetVal = 0; /* EC_E_NOERROR*/
    nRetVal = 0;
Exit:
    if (bLocked)
    {
        mutex_unlock(&pDrvDescPrivate->mdio_order_mutex);
    }
    oOrder.dwErrorCode = dwRetVal;
    nRetVal = copy_to_user((ATEMSYS_T_MDIO_ORDER *)ioctlParam, &oOrder, sizeof(ATEMSYS_T_MDIO_ORDER));
    if (0 != nRetVal)
    {
        ERR("GetMdioOrderIoctl failed: %d\n", nRetVal);
    }
    return nRetVal;
}

static int ReturnMdioOrderIoctl( unsigned long ioctlParam)
{
    ATEMSYS_T_DRV_DESC_PRIVATE* pDrvDescPrivate = NULL;
    ATEMSYS_T_MDIO_ORDER oOrder;
    unsigned int dwRetVal = 0x98110000; /* EC_E_ERROR */
    int nRetVal = -1;
    memset(&oOrder, 0, sizeof(ATEMSYS_T_MDIO_ORDER));
    nRetVal = copy_from_user(&oOrder, (ATEMSYS_T_MDIO_ORDER *)ioctlParam, sizeof(ATEMSYS_T_MDIO_ORDER));
    if (0 != nRetVal)
    {
        ERR("ReturnMdioOrderIoctl failed: %d\n", nRetVal);
        goto Exit;
    }

    if (oOrder.dwIndex >= ATEMSYS_MAX_NUMBER_DRV_INSTANCES)
    {
        dwRetVal = 0x98110002; /* EC_E_INVALIDINDEX */
        nRetVal = 0;
        goto Exit;
    }
    pDrvDescPrivate = S_apDrvDescPrivate[oOrder.dwIndex];
    if (NULL == pDrvDescPrivate)
    {
        dwRetVal = 0x9811000C; /* EC_E_NOTFOUND*/
        nRetVal = 0;
        goto Exit;
    }

    pDrvDescPrivate = S_apDrvDescPrivate[oOrder.dwIndex];
    if (NULL == pDrvDescPrivate)
    {
        dwRetVal = 0x9811000C; /* EC_E_NOTFOUND*/
        nRetVal = 0;
        goto Exit;
    }

    mutex_lock(&pDrvDescPrivate->mdio_order_mutex);
    pDrvDescPrivate->MdioOrder.wValue = oOrder.wValue;
    pDrvDescPrivate->MdioOrder.bInUseByIoctl = false;
    mutex_unlock(&pDrvDescPrivate->mdio_order_mutex);

    /* wake MdioRead or MdioWrite */
    pDrvDescPrivate->mdio_wait_queue_cnt = 1;
    wake_up_interruptible(&pDrvDescPrivate->mdio_wait_queue);

    dwRetVal = 0 /* EC_E_NOERROR*/;
    nRetVal = 0;

Exit:
    oOrder.dwErrorCode = dwRetVal;
    nRetVal = copy_to_user((ATEMSYS_T_MDIO_ORDER *)ioctlParam, &oOrder, sizeof(ATEMSYS_T_MDIO_ORDER));
    if (0 != nRetVal)
    {
        ERR("ReturnMdioOrderIoctl failed: %d\n", nRetVal);
    }
    return nRetVal;
}

static int GetPhyInfoIoctl(unsigned long ioctlParam)
{
    ATEMSYS_T_DRV_DESC_PRIVATE* pDrvDescPrivate  = NULL;
    ATEMSYS_T_PHY_INFO oStatus;
    unsigned int dwRetVal = 0x98110000; /* EC_E_ERROR */
    int nRetVal = -1;
    memset(&oStatus, 0, sizeof(ATEMSYS_T_PHY_INFO));
    nRetVal = copy_from_user(&oStatus, (ATEMSYS_T_PHY_INFO *)ioctlParam, sizeof(ATEMSYS_T_PHY_INFO));
    if (0 != nRetVal)
    {
        ERR("GetPhyInfoIoctl failed: %d\n", nRetVal);
        goto Exit;
    }

    if (oStatus.dwIndex >= ATEMSYS_MAX_NUMBER_DRV_INSTANCES)
    {
        dwRetVal = 0x98110002; /* EC_E_INVALIDINDEX */
        nRetVal = 0;
        goto Exit;
    }
    pDrvDescPrivate = S_apDrvDescPrivate[oStatus.dwIndex];
    if (NULL == pDrvDescPrivate)
    {
        dwRetVal = 0x9811000C; /* EC_E_NOTFOUND*/
        nRetVal = 0;
        goto Exit;
    }

    oStatus.dwLink    = pDrvDescPrivate->PhyInfo.dwLink;
    oStatus.dwDuplex  = pDrvDescPrivate->PhyInfo.dwDuplex;
    oStatus.dwSpeed   = pDrvDescPrivate->PhyInfo.dwSpeed;
    oStatus.bPhyReady = pDrvDescPrivate->PhyInfo.bPhyReady;

    dwRetVal = 0; /* EC_E_NOERROR */
    nRetVal = 0;
Exit:
    oStatus.dwErrorCode = dwRetVal;
    nRetVal = copy_to_user((ATEMSYS_T_PHY_INFO *)ioctlParam, &oStatus, sizeof(ATEMSYS_T_PHY_INFO));
    if (0 != nRetVal)
    {
        ERR("GetPhyInfoIoctl failed: %d\n", nRetVal);
    }
    return nRetVal;
}

static int PhyResetIoctl(unsigned long ioctlParam)
{
    ATEMSYS_T_DRV_DESC_PRIVATE* pDrvDescPrivate  = NULL;
    unsigned int* pdwIoctlData = (__u32*)ioctlParam;
    unsigned int dwIndex = 0;
    unsigned int dwRetVal = 0x98110000; /* EC_E_ERROR */
    int nRetVal = -1;
    int nRes = -1;

    nRes = get_user(dwIndex, pdwIoctlData);
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
        dwRetVal = 0x9811000C; /* EC_E_NOTFOUND */
        nRetVal = 0;
        goto Exit;
    }

    if (!pDrvDescPrivate->MacInfo.bPhyResetSupported)
    {
        DBG("PhyResetIoctl: PhyReset not supported\n");
        dwRetVal = 0x98110001; /* EC_E_NOTSUPPORTED */
        nRetVal = 0;
        goto Exit;
    }

    nRes = ResetPhyViaGpio(pDrvDescPrivate);
    if (0 != nRes)
    {
        dwRetVal = 0x98110000; /* EC_E_ERROR */
        nRetVal = 0;
        goto Exit;
    }

    dwRetVal = 0; /* EC_E_NOERROR */
    nRetVal = 0;
Exit:
    put_user(dwRetVal, pdwIoctlData);

    return nRetVal;
}

static void UpdatePhyInfoByLinuxPhyDriver(struct net_device* ndev)
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

static int MdioProbe(struct net_device* ndev)
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
    else if (NULL != pDrvDescPrivate->pMdioNode)
    {
        struct platform_device* mdio;
        mdio = of_find_device_by_node(pDrvDescPrivate->pMdioNode);
        snprintf(phy_name, sizeof(phy_name), PHY_ID_FMT, mdio->name, pDrvDescPrivate->MacInfo.dwPhyAddr);
        pPhyDev = phy_connect(ndev, phy_name, &UpdatePhyInfoByLinuxPhyDriver, pDrvDescPrivate->PhyInterface);
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
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,1,0))
            strscpy(mdio_bus_id, pDrvDescPrivate->pMdioBus->id, MII_BUS_ID_SIZE);
#else
            strlcpy(mdio_bus_id, pDrvDescPrivate->pMdioBus->id, MII_BUS_ID_SIZE);
#endif
            break;
        }

        if (nPhy_id >= PHY_MAX_ADDR)
        {
            INF("%s: no PHY, assuming direct connection to switch\n", pDrvDescPrivate->pPDev->name);
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,1,0))
            strscpy(mdio_bus_id, "fixed-0", MII_BUS_ID_SIZE);
#else
            strlcpy(mdio_bus_id, "fixed-0", MII_BUS_ID_SIZE);
#endif
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

static int MdioRead(struct mii_bus* pBus, int mii_id, int regnum)
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

static int MdioWrite(struct mii_bus* pBus, int mii_id, int regnum, u16 value)
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

static int MdioInit(struct platform_device* pPDev)
{
    struct net_device* pNDev = platform_get_drvdata(pPDev);
    ATEMSYS_T_DRV_DESC_PRIVATE* pDrvDescPrivate = netdev_priv(pNDev);
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

    if (NULL != pDrvDescPrivate->pMdioDevNode)
    {
        nRes = of_mdiobus_register(pDrvDescPrivate->pMdioBus, pDrvDescPrivate->pMdioDevNode);
        of_node_put(pDrvDescPrivate->pMdioDevNode);
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


static int StopPhy(struct platform_device* pPDev)
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

static int StartPhy(struct platform_device* pPDev)
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
        /* remove mdio bus */
        if (NULL != pDrvDescPrivate->pMdioBus)
        {
            mdiobus_unregister(pDrvDescPrivate->pMdioBus);
            mdiobus_free(pDrvDescPrivate->pMdioBus);
            pDrvDescPrivate->pMdioBus = NULL;
        }
        return nRes;
    }
    /* phy */
    phy_start(pDrvDescPrivate->pPhyDev);
    phy_start_aneg(pDrvDescPrivate->pPhyDev);

    return 0;
}

static int StartPhyThread(void* data)
{
    struct platform_device* pPDev = (struct platform_device*)data;

    StartPhy(pPDev);

    return 0;
}

static int StopPhyThread(void* data)
{
    struct platform_device* pPDev = (struct platform_device*)data;

    StopPhy(pPDev);

    return 0;
}

static int StopPhyWithoutIoctlMdioHandling(struct platform_device* pPDev)
{
    struct net_device* pNDev = platform_get_drvdata(pPDev);
    ATEMSYS_T_DRV_DESC_PRIVATE* pDrvDescPrivate = netdev_priv(pNDev);

    /* start StopPhy as thread */
#if (defined CONFIG_XENO_COBALT)
    mutex_lock(&S_oAtemsysWorkerThreadDesc.WorkerTask_mutex);
    if (NULL == S_oAtemsysWorkerThreadDesc.pfNextTask)
    {
        S_oAtemsysWorkerThreadDesc.pfNextTask = StopPhyThread;
        S_oAtemsysWorkerThreadDesc.pNextTaskData = (void*)pDrvDescPrivate->pPDev;
    }
    else
    {
        ERR("StopPhyWithoutIoctlMdioHandling failed! WorkerThread is busy!\n");
        return -EAGAIN;
    }
    mutex_unlock(&S_oAtemsysWorkerThreadDesc.WorkerTask_mutex);
#else
    pDrvDescPrivate->etx_thread_StopPhy = kthread_create(StopPhyThread,(void*)pDrvDescPrivate->pPDev,"StopPhyThread");
    if(NULL == pDrvDescPrivate->etx_thread_StopPhy)
    {
        ERR("Cannot create kthread for StopPhyThread\n");
        return -1;
    }
    wake_up_process(pDrvDescPrivate->etx_thread_StopPhy);
#endif /* #if (defined CONFIG_XENO_COBALT) */

    /* trigger event to continue MdioRead and MdioWrite */
    /* MdioRead returns always 0 */
    pDrvDescPrivate->mdio_wait_queue_cnt = 1000; // wait will be skipped 1000 times
    wake_up_interruptible(&pDrvDescPrivate->mdio_wait_queue);

    return 0;
}

static struct device_node* findDeviceTreeNode(struct platform_device* pPDev)
{
    int                    nTimeout;
    unsigned int           dwRegAddr32;
    long long unsigned int qwRegAddr64;
    char                   aBuff[32] = {0};
    struct device_node*    pDevNode;

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

static int ResetPhyViaGpio(ATEMSYS_T_DRV_DESC_PRIVATE* pDrvDescPrivate)
{
    int nRes = 0;
#if (LINUX_VERSION_CODE > KERNEL_VERSION(6,0,0))
    if (!pDrvDescPrivate->bPhyResetGpioPinOwner)
#endif
    {
        nRes = devm_gpio_request_one(&pDrvDescPrivate->pPDev->dev, pDrvDescPrivate->nPhyResetGpioPin,
            pDrvDescPrivate->bPhyResetGpioActiveHigh ? GPIOF_OUT_INIT_HIGH : GPIOF_OUT_INIT_LOW,
            "atemsys-phy-reset");
        pDrvDescPrivate->bPhyResetGpioPinOwner = true;
    }
    if (nRes)
    {
        ERR("%s: failed to get atemsys-phy-reset-gpios: %d \n", pDrvDescPrivate->pPDev->name, nRes);
        return nRes;
    }

    if (pDrvDescPrivate->nPhyResetDuration > 20)
        msleep(pDrvDescPrivate->nPhyResetDuration);
    else
        usleep_range(pDrvDescPrivate->nPhyResetDuration * 1000, pDrvDescPrivate->nPhyResetDuration * 1000 + 1000);

    gpio_set_value_cansleep(pDrvDescPrivate->nPhyResetGpioPin, !pDrvDescPrivate->bPhyResetGpioActiveHigh);

#if (LINUX_VERSION_CODE <= KERNEL_VERSION(6,0,0))
    devm_gpio_free(&pDrvDescPrivate->pPDev->dev, pDrvDescPrivate->nPhyResetGpioPin);
#endif

    if (!pDrvDescPrivate->nPhyResetPostDelay)
        return 0;

    if (pDrvDescPrivate->nPhyResetPostDelay > 20)
        msleep(pDrvDescPrivate->nPhyResetPostDelay);
    else
        usleep_range(pDrvDescPrivate->nPhyResetPostDelay * 1000, pDrvDescPrivate->nPhyResetPostDelay * 1000 + 1000);

    return 0;
}

static int EthernetDriverProbe(struct platform_device* pPDev)
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

    /* resets */
    {
        struct reset_control*   pResetCtl;
        const char*             szTempString = NULL;

        nRes = of_property_read_string(pDevNode, "reset-names", &szTempString);
        pResetCtl = devm_reset_control_get_optional(&pPDev->dev, szTempString);
        if (NULL != pResetCtl)
        {
            nRes = reset_control_assert(pResetCtl);
            reset_control_deassert(pResetCtl);

            /* Some reset controllers have only reset callback instead of
             * assert + deassert callbacks pair.
             */
            if (-ENOTSUPP == nRes)
            {
                reset_control_reset(pResetCtl);
                pDrvDescPrivate->pResetCtl = pResetCtl;
            }
        }
    }

    /* get prepare data for atemsys and print some data to kernel log */
    {
        unsigned int    dwTemp          = 0;
        const char*     szTempString    = NULL;
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
        if ((strcmp(pDrvDescPrivate->MacInfo.szIdent, "CPSWG") == 0) && (0==pDrvDescPrivate->PhyInterface))
        {
            struct device_node* pDevNodeNew = pDevNode;
            pDevNodeNew = of_get_child_by_name(pDevNodeNew, "ethernet-ports");
            pDevNodeNew = of_get_child_by_name(pDevNodeNew, "port");
            nRes = of_get_phy_mode(pDevNodeNew, &pDrvDescPrivate->PhyInterface);
        }
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
        if ((strcmp(pDrvDescPrivate->MacInfo.szIdent, "CPSWG") == 0) && (NULL == pDrvDescPrivate->pPhyNode))
        {
            struct device_node* pDevNodeNew = pDevNode;
            pDevNodeNew = of_get_child_by_name(pDevNodeNew, "ethernet-ports");
            pDevNodeNew = of_get_child_by_name(pDevNodeNew, "port");
            pDrvDescPrivate->pPhyNode = of_parse_phandle(pDevNodeNew, "phy-handle", 0);
        }
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
            int nLen;
            const __be32* pPhyId;
            pPhyId = of_get_property(pDevNode, "phy_id", &nLen);

            if (nLen == (sizeof(__be32) * 2))
            {
                pDrvDescPrivate->pMdioNode = of_find_node_by_phandle(be32_to_cpup(pPhyId));
                pDrvDescPrivate->MacInfo.dwPhyAddr = be32_to_cpup(pPhyId+1);
            }
            else
            {
                INF("%s: Missing phy-handle in the Device Tree\n", pPDev->name);
            }
        }

        /* check if mdio node is sub-node and mac has own mdio bus */
        {
            pDrvDescPrivate->pMdioDevNode = of_get_child_by_name(pDevNode, "mdio");
            if (NULL == pDrvDescPrivate->pMdioDevNode)
                pDrvDescPrivate->pMdioDevNode = of_get_child_by_name(pDevNode, "mdio0");
            if (NULL == pDrvDescPrivate->pMdioDevNode)
                pDrvDescPrivate->pMdioDevNode = of_get_child_by_name(pDevNode, "mdio1");
            if (NULL == pDrvDescPrivate->pMdioDevNode)
                pDrvDescPrivate->pMdioDevNode = of_get_child_by_name(pDevNode, "phy");
            if (NULL == pDrvDescPrivate->pMdioDevNode)
                pDrvDescPrivate->pMdioDevNode = of_get_child_by_name(pDevNode, "ethernet-phy");

            if ((NULL == pDrvDescPrivate->pMdioDevNode) && (NULL != pDrvDescPrivate->pPhyNode))
            {
                /* check if phy node is subnode and use first sub-node as node for mdio bus */
                struct device_node *pTempNode = of_get_parent(pDrvDescPrivate->pPhyNode);
                if ((NULL != pTempNode) && (pTempNode == pDevNode))
                {
                    pDrvDescPrivate->pMdioDevNode = pDrvDescPrivate->pPhyNode;
                }
                else if ((NULL != pTempNode) && (of_get_parent(pTempNode) == pDevNode))
                {
                    pDrvDescPrivate->pMdioDevNode = pTempNode;
                }
            }

            if (NULL != pDrvDescPrivate->pMdioDevNode)
            {
                /* mdio bus is owned by current mac instance */
                pDrvDescPrivate->MacInfo.bNoMdioBus = false;
                INF("%s: mac has mdio bus.\n", pPDev->name );
            }
            else if ((NULL != pDrvDescPrivate->pPhyNode) || (NULL != pDrvDescPrivate->pMdioNode))
            {
                /* mdio bus owned by another mac instance */
                pDrvDescPrivate->MacInfo.bNoMdioBus = true;
                INF("%s: mac has no mdio bus, uses mdio bus of other instance.\n", pPDev->name);
            }
            else
            {
                /* legacy mode: no node for mdio bus in device tree defined */
                pDrvDescPrivate->MacInfo.bNoMdioBus = false;
                INF("%s: handle mdio bus without device tree node.\n", pPDev->name );
            }
            if (pDrvDescPrivate->pMdioDevNode == pDrvDescPrivate->pPhyNode)
            {
                pDrvDescPrivate->pMdioDevNode = NULL;
            }
        }

        /* PHY reset data */
        nRes = of_property_read_u32(pDevNode, "atemsys-phy-reset-duration", &pDrvDescPrivate->nPhyResetDuration);
        if (nRes) pDrvDescPrivate->nPhyResetDuration = 0;
        pDrvDescPrivate->nPhyResetGpioPin = of_get_named_gpio(pDevNode, "atemsys-phy-reset-gpios", 0);
        nRes = of_property_read_u32(pDevNode, "atemsys-phy-reset-post-delay", &pDrvDescPrivate->nPhyResetPostDelay);
        if (nRes) pDrvDescPrivate->nPhyResetPostDelay = 0;
        pDrvDescPrivate->bPhyResetGpioActiveHigh = of_property_read_bool(pDevNode, "atemsys-phy-reset-active-high");

        if ((0 != pDrvDescPrivate->nPhyResetDuration) && (pDrvDescPrivate->nPhyResetGpioPin != -EPROBE_DEFER)
                && gpio_is_valid(pDrvDescPrivate->nPhyResetGpioPin))
        {
            pDrvDescPrivate->MacInfo.bPhyResetSupported = true;
            DBG("%s: PhyReset ready: GpioPin: %d; Duration %d, bActiveHigh %d, post delay %d\n", pPDev->name,
                pDrvDescPrivate->nPhyResetGpioPin, pDrvDescPrivate->nPhyResetDuration,
                pDrvDescPrivate->bPhyResetGpioActiveHigh, pDrvDescPrivate->nPhyResetPostDelay);
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

#if (LINUX_VERSION_CODE > KERNEL_VERSION(6,11,0))
        EthernetDriverRemove(pPDev);
        return 1;
#else
        return EthernetDriverRemove(pPDev);
#endif
    }

#ifdef INCLUDE_ATEMSYS_DT_REGISTER_NETDEVICE
    /* register node as net_device */
    if (bRegisterDtbNetDevice)
    {
        RegisterEthernetDriverAsNetDevice(pDevNode, (struct _ATEMSYS_T_DRV_DESC_PRIVATE*)pDrvDescPrivate);
    }
#endif

    /* start drivers of sub-nodes */
    if (strcmp(pDrvDescPrivate->MacInfo.szIdent, "CPSW") == 0
       || strcmp(pDrvDescPrivate->MacInfo.szIdent, "ICSS") == 0)
    {
        of_platform_populate(pDevNode, NULL, NULL, &pPDev->dev);
        DBG("%s: start drivers of sub-nodes.\n", pPDev->name );
    }
    if (strcmp(pDrvDescPrivate->MacInfo.szIdent, "CPSWG") == 0)
    {
        /* in subnode "ethernet-ports" start driver for "port@2" */
        struct device_node* pDevNodeNew = pDevNode;
        pDevNodeNew = of_get_child_by_name(pDevNodeNew, "ethernet-ports");
        of_platform_populate(pDevNodeNew, NULL, NULL, &pPDev->dev);
        DBG("%s: start drivers of sub-nodes.\n", pPDev->name );
    }

    /* prepare mutex for mdio */
    mutex_init(&pDrvDescPrivate->mdio_mutex);
    mutex_init(&pDrvDescPrivate->mdio_order_mutex);
    init_waitqueue_head(&pDrvDescPrivate->mdio_wait_queue);
    pDrvDescPrivate->mdio_wait_queue_cnt = 0;

    return 0;
}


#ifdef INCLUDE_ATEMSYS_DT_REGISTER_NETDEVICE
static int netd_dummy_int(struct net_device *netdev)
{
    return 0;
}

static void netd_dummy_void(struct net_device *netdev)
{
}

static netdev_tx_t netd_xmit_frame(struct sk_buff *skb,
                   struct net_device *netdev)
{
    return NETDEV_TX_BUSY;
}

static int netd_set_mac_address(struct net_device *netdev, void *p)
{
    struct sockaddr *addr = p;

    eth_hw_addr_set(netdev, addr->sa_data);
    return 0;
}
static int netd_do_ioctl(struct net_device *netdev, struct ifreq *ifr, int cmd)
{
    return -EOPNOTSUPP;
}
static void netd_tx_timeout(struct net_device *netdev, unsigned int txqueue)
{
}

static int netd_set_features(struct net_device *netdev, netdev_features_t features)
{
    return 0;
}

static const struct net_device_ops AtemsysNetdevOps = {
    .ndo_open           = netd_dummy_int,
    .ndo_stop           = netd_dummy_int,
    .ndo_start_xmit     = netd_xmit_frame,
    .ndo_validate_addr  = netd_dummy_int,
    .ndo_set_rx_mode    = netd_dummy_void,
    .ndo_set_mac_address    = netd_set_mac_address,
    .ndo_eth_ioctl      = netd_do_ioctl,
    .ndo_tx_timeout     = netd_tx_timeout,
#ifdef CONFIG_NET_POLL_CONTROLLER
    .ndo_poll_controller    = netd_dummy_void,
#endif
    .ndo_set_features    = netd_set_features,
};

int RegisterEthernetDriverAsNetDevice(struct device_node* pDevNode, struct _ATEMSYS_T_DRV_DESC_PRIVATE* pDrvDescPrivate)
{
    struct net_device *netdev;
    int err = 0;
    u8 addr[ETH_ALEN] = {0};

    if (!(netdev = alloc_etherdev(sizeof(int))))
        return -ENOMEM;
    eth_random_addr(addr);
    eth_hw_addr_set(netdev, addr);
    INF("%s: register_netdev mac: %02x:%02x:%02x:%02x:%02x:%02x\n", pDrvDescPrivate->pPDev->name,
        addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);

    netdev->hw_features |= NETIF_F_RXFCS;
    netdev->priv_flags |= IFF_SUPP_NOFCS;
    netdev->hw_features |= NETIF_F_RXALL;

    netdev->netdev_ops = &AtemsysNetdevOps;
    netdev->watchdog_timeo = 1000;
    strscpy(netdev->name, ATEMSYS_DT_DRIVER_NAME, sizeof(ATEMSYS_DT_DRIVER_NAME));

    SET_NETDEV_DEV(netdev, &pDrvDescPrivate->pPDev->dev);
    netdev->dev.of_node = pDevNode;

    strcpy(netdev->name, "eth%d");
    err = register_netdev(netdev);
    return err;
}
#endif /* #ifdef INCLUDE_ATEMSYS_DT_REGISTER_NETDEVICE */

#if (LINUX_VERSION_CODE > KERNEL_VERSION(6,11,0))
static void EthernetDriverRemove(struct platform_device* pPDev)
#else
static int EthernetDriverRemove(struct platform_device* pPDev)
#endif
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

    /* resets */
    if (NULL != pDrvDescPrivate->pResetCtl)
    {
        reset_control_assert(pDrvDescPrivate->pResetCtl);
    }
    for (i = 0; i < ATEMSYS_MAX_NUMBER_OF_CLOCKS; i++)
    {
        if (NULL != pDrvDescPrivate->clk_ids[i])
        {
            clk_disable_unprepare(pDrvDescPrivate->clks[i]);
            DBG("%s: Clock %s unprepared\n", pPDev->name, pDrvDescPrivate->clk_ids[i]);
        }
    }
    mutex_destroy(&pDrvDescPrivate->mdio_mutex);
    mutex_destroy(&pDrvDescPrivate->mdio_order_mutex);

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

#if (LINUX_VERSION_CODE < KERNEL_VERSION(6,11,0))
    return 0;
#endif
}

static int CleanUpEthernetDriverOnRelease(ATEMSYS_T_DEVICE_DESC* pDevDesc)
{
    ATEMSYS_T_DRV_DESC_PRIVATE* pDrvDescPrivate = NULL;
    int nRes = -1;
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
                int timeout = 0;
                for (timeout = 50; timeout-- < 0; msleep(100))
                {
                    nRes = StopPhyWithoutIoctlMdioHandling(pDrvDescPrivate->pPDev);
                    if (-EAGAIN != nRes)
                        break;
                }
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

static void PciDriverRemove(struct pci_dev* pPciDev)
{
    ATEMSYS_T_PCI_DRV_DESC_PRIVATE* pPciDrvDescPrivate = (ATEMSYS_T_PCI_DRV_DESC_PRIVATE*)pci_get_drvdata(pPciDev);

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
#if (LINUX_VERSION_CODE < KERNEL_VERSION(6,0,0))
    pci_disable_msi(pPciDev);
#endif
    pci_release_regions(pPciDev);

#if (LINUX_VERSION_CODE <= KERNEL_VERSION(6,4,0))
    pci_disable_pcie_error_reporting(pPciDev);
#endif
    pci_disable_device(pPciDev);

    INF("%s: %s: disconnected\n", pci_name(pPciDev), ATEMSYS_PCI_DRIVER_NAME);
}

static int PciDriverProbe(struct pci_dev* pPciDev, const struct pci_device_id* id)
{
    ATEMSYS_T_PCI_DRV_DESC_PRIVATE* pPciDrvDescPrivate = NULL;
    int nRes = -ENODEV;
    int dwIndex = 0;

    /* check if is wanted pci device */
    if ((strcmp(AllowedPciDevices, "PCI_ANY_ID") != 0) && (strstr(AllowedPciDevices, pci_name(pPciDev)) == NULL))
    {
        /* don't attach driver */
        DBG("%s: PciDriverProbe: restricted by user parameters!\n", pci_name(pPciDev));

        return -ENODEV; /* error code doesn't create error message */
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
#if (LINUX_VERSION_CODE <= KERNEL_VERSION(6,4,0))
    pci_enable_pcie_error_reporting(pPciDev);
#endif
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


static const struct pci_device_id pci_devtype[] = {
    {
    /* all devices of class PCI_CLASS_NETWORK_ETHERNET */
    .vendor      = PCI_ANY_ID,
    .device      = PCI_ANY_ID,
    .subvendor   = PCI_ANY_ID,
    .subdevice   = PCI_ANY_ID,
    .class       = (PCI_CLASS_NETWORK_ETHERNET << 8),
    .class_mask  = (0xFFFF00),
    .driver_data = (kernel_ulong_t)&oAtemsysPciInfo
    },
    {
     /* all devices with BECKHOFF vendor id */
    .vendor      = PCI_VENDOR_ID_BECKHOFF,
    .device      = PCI_ANY_ID,
    .subvendor   = PCI_ANY_ID,
    .subdevice   = PCI_ANY_ID,
    .driver_data = (kernel_ulong_t)&oAtemsysPciInfo
    },
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
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,6,0))
static int  __init atemsys_init_module(void)
#else
int init_module(void)
#endif
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
#endif /* CONFIG_XENO_COBALT */

    /* Register Pci and Platform Driver */
#if (defined INCLUDE_ATEMSYS_DT_DRIVER)
    memset(S_apDrvDescPrivate ,0, ATEMSYS_MAX_NUMBER_DRV_INSTANCES * sizeof(ATEMSYS_T_DRV_DESC_PRIVATE*));
    platform_driver_register(&mac_driver);
#if (defined CONFIG_XENO_COBALT)
    memset(&S_oAtemsysWorkerThreadDesc, 0, sizeof(ATEMSYS_T_WORKER_THREAD_DESC));
    mutex_init(&S_oAtemsysWorkerThreadDesc.WorkerTask_mutex);
    S_oAtemsysWorkerThreadDesc.etx_thread = kthread_create(AtemsysWorkerThread,(void*)&S_oAtemsysWorkerThreadDesc,"Atemsys_WorkerThread");
    if(NULL == S_oAtemsysWorkerThreadDesc.etx_thread)
    {
        ERR("Cannot create kthread for AtemsysWorkerThread\n");
    }
    wake_up_process(S_oAtemsysWorkerThreadDesc.etx_thread);
#endif /*#if (defined CONFIG_XENO_COBALT)*/
#endif

#if (defined INCLUDE_ATEMSYS_PCI_DRIVER)
    memset(S_apPciDrvDescPrivate ,0, ATEMSYS_MAX_NUMBER_DRV_INSTANCES * sizeof(ATEMSYS_T_PCI_DRV_DESC_PRIVATE*));

    if (0 == strcmp(AllowedPciDevices, ""))
    {
        DBG("Atemsys PCI driver not registered\n");
    }
    else
    {
        if (0 != pci_register_driver(&oPciDriver))
        {
            INF("Register Atemsys PCI driver failed!\n");
        }
    }
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,4,0))
    S_pDevClass = class_create(ATEMSYS_DEVICE_NAME);
#else
    S_pDevClass = class_create(THIS_MODULE, ATEMSYS_DEVICE_NAME);
#endif
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

#if (defined __arm__) || (defined __aarch64__) || (defined __riscv)
    {
        int nRetVal = 0;
        S_pPlatformDev = platform_device_alloc("atemsys_PDev", MKDEV(MAJOR_NUM, 0));
        S_pPlatformDev->dev.parent = S_pDev;

        nRetVal = platform_device_add(S_pPlatformDev);
        if (nRetVal != 0) {
            ERR("platform_device_add failed. return=%d\n", nRetVal);
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

    INF("%s v%s loaded\n", ATEMSYS_DEVICE_NAME, ATEMSYS_VERSION_STR);
    return 0;
}

/*
 * Cleanup - unregister the appropriate file from /proc
 */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,6,0))
static void  __exit atemsys_cleanup_module(void)
#else
void cleanup_module(void)
#endif
{
   INF("%s v%s unloaded\n", ATEMSYS_DEVICE_NAME, ATEMSYS_VERSION_STR);

    /* Unregister Pci and Platform Driver */
#if (defined INCLUDE_ATEMSYS_DT_DRIVER)
    platform_driver_unregister(&mac_driver);
#if (defined CONFIG_XENO_COBALT)
    S_oAtemsysWorkerThreadDesc.bWorkerTaskShutdown = true;
    for (;;)
    {
        if (!S_oAtemsysWorkerThreadDesc.bWorkerTaskRunning)
        {
            break;
        }

        msleep(100);
    }
    mutex_destroy(&S_oAtemsysWorkerThreadDesc.WorkerTask_mutex);
#endif /*#if (defined CONFIG_XENO_COBALT)*/
#endif

#if (defined INCLUDE_ATEMSYS_PCI_DRIVER)
    if (0 != strcmp(AllowedPciDevices, ""))
    {
        pci_unregister_driver(&oPciDriver);
    }
#endif

#if (defined __arm__) || (defined __aarch64__) || (defined __riscv)
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

   device_destroy(S_pDevClass, MKDEV(MAJOR_NUM, 0));
   class_destroy(S_pDevClass);

#if (defined CONFIG_XENO_COBALT)
   rtdm_dev_unregister(&device);
#else
   unregister_chrdev(MAJOR_NUM, ATEMSYS_DEVICE_NAME);
#endif /* CONFIG_XENO_COBALT */
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,6,0))
module_init(atemsys_init_module);
module_exit(atemsys_cleanup_module);
#endif
