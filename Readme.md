# Kernel module atemsys

Kernel module that grants direct access to hardware, improving the performance of the LinkLayers, used in the EtherCAT Master Stack Software EC-Master and EtherCAT Network Simulation Software EC-Simulator.

It provides usermode access to:
- PCI configuration space
- Device IO memory
- Contiguous DMA memory
- Single device interrupt

The following diagram shows the architecture of [EC-Master](https://www.acontis.com/en/ethercat-master.html) on Linux.

<p align="center">
<img src="https://github.com/acontis/atemsys/blob/main/ec-masterarchlinux.png" alt="ec-masterarchlinux" width="800">
</p>


## Installation
### Building on the target device
Atemsys can be built natively on the target device:
#### 1) Get the latest version of atemsys
```bash
git clone https://github.com/acontis/atemsys.git
```
#### 2a) if you have kernel headers available on your linux target you can build atemsys in the following way:
```bash
cd atemsys
make modules
```
#### 2b) if no kernel headers are available
1) get the Kernel sources of your desired version. This can be done e.g. in the following ways:
- Clone with git: `git clone -b v4.4.189 https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git`
- Download from kernel.org: https://mirrors.edge.kernel.org/pub/linux/kernel/v4.x/linux-4.4.189.tar.gz
2) Unpack\clone the kernel into directory linux
3) Unpack `/proc/config.gz` from target into linux directory:
```bash
zcat config.gz > linux/.config
```
4) Prepare kernel:
```bash
cd linux
make oldconfig
make prepare
make modules_prepare
cd ..
```
5) Build atemsys
```bash
cd atemsys
make KERNELDIR=../linux/ modules
```

#### 3) load the atemsys module
```bash
sudo insmod atemsys.ko
```

### Cross-Compile for a target device
The atemsys kernel module can be cross compiled for a target device using:
```
git clone https://github.com/acontis/atemsys.git
cd atemsys
make ARCH=<...> CROSS_COMPILE=<...> KERNELDIR=<path to target kernel dir> modules
```
e.g. for ARM this works in the following way
- ARM 32 Bit:
```
make ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf- KERNELDIR=<path to target kernel dir> modules
```
- ARM 64 Bit:
```
make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- KERNELDIR=<path to target kernel dir> modules
```

afterwards load the atemsys module on the target device using:
```bash
sudo insmod atemsys.ko
```

### Configuring acontis atemsys for Yocto Linux


## Use Atemsys as Device Tree Ethernet Driver
Atemsys as Device Tree based device driver for the Ethernet MAC can handle several upcoming issues:
- Latest Linux versions bring more complex power saving behavior. To solve this a Linux driver is necessary to claim the same as the native driver from the Linux power-related management systems.
- Some PHY configurations are currently not supported by the EcMaster. As Linux driver the Atemsys can use the corresponding Linux PHY driver.
- Systems with 2 Ethernet ports and shared Mdio bus can easier separated between Linux and EcMaster. The Ethernet port which provides the Mdio bus should be assigned to Linux. 

Customize the Linux device tree:
- The device tree file can be customized before compiling the kernel and modules at `<kernel sources>/arch/<cpu architecture>/boot/dts`
- On the running system the compiled device tree file can be generally found next to the kernel image, which is normally in the `/boot` folder of the system. The \*.dtb-file can be un-compiled with the device tree compiler
```bash
> dtc -I dtb -O dts -f <file name>.dtb -o <file name>.dts
```
and recompiled with
```bash
> dtc -I dts -O dtb -f <file name>.dts -o <file name>.dtb
```

- To assigned the compatible property has to be change to "atemsys"
- Change the compatible property to "atemsys" so the Ethernet device tree node is assigned to the atemsys device driver.
- Add atemsys-Ident and atemsys-Instance properties with the EC_LINK_PARMS_IDENT_* and the instance used by EcMaster, see EcLink.h
- Remove all interrupted properties, like interrupt-parent and interrupts, in the ethernet-phy sub-node. 

### Example: Ethernet device node for FslFec on Freescale/NXP i.MX6DL
```
ethernet@02188000 {
  compatible = "atemsys";
  atemsys-Ident = "FslFec";
  atemsys-Instance = <0x1>;
  reg = <0x2188000 0x4000>;
  interrupts-extended = <0x1 0x0 0x76 0x4 0x1 0x0 0x77 0x4>;
  clocks = <0x2 0x75 0x2 0x75 0x2 0xbe>;
  clock-names = "ipg", "ahb", "ptp";
  stop-mode = <0x4 0x34 0x1b>;
  fsl,wakeup_irq = <0x0>;
  status = "okay";
  pinctrl-names = "default";
  pinctrl-0 = <0x3e>;
  phy-mode = "rmii";
  phy-handle = <0x3f>; 
 
  mdio {
    #address-cells = <0x1>;
    #size-cells = <0x0>; 
 
    ethernet-phy@0 {
      reg = <0x0>;
      micrel,led-mode = <0x0>;
      linux,phandle = <0x3f>;
      phandle = <0x3f>;
    };
  };
};
```


