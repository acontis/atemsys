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
#### 2) Install kernel headers if neccessary, e.g.
```bash
sudo apt-get install linux-headers-$(uname -r)
```
>:information_source: If kernel headers cannot be installed, see the cross-compiling section below.
#### 3) Build atemsys
```bash
cd atemsys
make modules
```
#### 3) Load the atemsys module
```bash
sudo insmod atemsys.ko
```

### Cross-Compile for a target device
The atemsys kernel module can also be cross compiled for a target device. 
To do this, the additional parameters `ARCH=`, `CROSS_COMPILE=` and `KERNELDIR=`must be passed to `make` e.g.:
- ARM 32 Bit:
```
make ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf- KERNELDIR=<path to target kernel dir>
```
- ARM 64 Bit:
```
make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- KERNELDIR=<path to target kernel dir>
```

#### 1) Get the Kernel sources of your desired version. This can be done e.g. in the following ways:
- Clone with git: 
  `git clone -b v4.4.189 https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git`
- Download from kernel.org:
  https://mirrors.edge.kernel.org/pub/linux/kernel/v4.x/linux-4.4.189.tar.gz

>⚠️ Warning:
>The kernel version and source code must exactly match that installed on the target.
>Custom kernels with patched sources are often used in embedded devices. Contact the manufacturer for the appropriate sources for your device.

#### 2) Unpack\clone the kernel into directory linux
#### 3) Unpack `/proc/config.gz` from target into linux directory:
```bash
zcat config.gz > linux/.config
```
#### 4) Prepare kernel:
```bash
cd linux
make ARCH=<...> CROSS_COMPILE=<...> oldconfig
make ARCH=<...> CROSS_COMPILE=<...> prepare
make ARCH=<...> CROSS_COMPILE=<...> modules_prepare
cd ..
```
#### 5) Get the latest version of atemsys
```bash
git clone https://github.com/acontis/atemsys.git
```
#### 6) Build atemsys
```
cd atemsys
make ARCH=<...> CROSS_COMPILE=<...> KERNELDIR=<path to target kernel dir> modules
```
#### 7) Load the atemsys module
```bash
sudo insmod atemsys.ko
```

### Build with Yocto
There are recipes for creating atemsys with Yocto. Further information can be found here https://github.com/acontis/meta-acontis.

## Use atemsys as device tree Ethernet Driver
Atemsys as device tree based platform device driver for the Ethernet MAC can handle several upcoming issues:
- Latest Linux versions bring more complex power saving behavior. To solve this a Linux driver is necessary to claim the same as the native driver from the Linux power-related management systems.
- Some PHY configurations are currently not supported by the EC-Master. As Linux driver the atemsys can use the corresponding Linux PHY driver.
- Systems with 2 Ethernet ports and a shared Mdio bus can be separated more easily between Linux and the EC-Master. The Ethernet port that provides the Mdio bus should be assigned to Linux.

### Device tree
The device tree file can be customized before compiling the kernel and modules at `<kernel sources>/arch/<cpu architecture>/boot/dts`. 

On the running system the compiled device tree file can be generally found next to the kernel image, which is normally in the `/boot` folder of the system. The `*.dtb`-file can be converted with the device tree compiler
  ```bash
  > dtc -I dtb -O dts -f <file name>.dtb -o <file name>.dts
  ```
  and recompiled with
  ```bash
  > dtc -I dts -O dtb -f <file name>.dts -o <file name>.dtb
  ```
### Customize device tree
- Assign the Ethernet device tree node to the atemsys device driver by assigning the value `atemsys` to the `compatible` property. It is also possible to add `atemsys` to the existing `compatible` list
- Add the properties `atemsys-Ident` and `atemsys-Instance`. 
  - `atemsys-Ident` for the name of the link layer 
  - `atemsys-Instance` with the instance number that is to be used by EC-Master.
  - See also `EC_LINK_PARMS_IDENT_*` in `EcLink.h`
- Remove all interrupt properties, like `interrupt-parent` and `interrupts`, in the `ethernet-phy` sub-node. 
- To support PHY reset via a GPIO pin add (with your values)
  - atemsys-phy-reset-gpios = <0x4a 0x05 0x01>;
  - atemsys-phy-reset-duration = <0x0a>;
  - [atemsys-phy-reset-post-delay = <0x64>;]
  - [atemsys-phy-reset-active-high = <0x1>;]]

### Example
:information_source: More example device trees for different platforms can be found in the [Wiki](https://github.com/acontis/atemsys/wiki).

**Ethernet device node for FslFec on Freescale/NXP i.MX6DL**
<pre><code>
ethernet@02188000 {
  <strong>compatible = "atemsys";</strong>
  <strong>atemsys-Ident = "FslFec";</strong>
  <strong>atemsys-Instance = <0x1>;</strong>
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
</code></pre>


### Kernel Modul Parameters

<strong>loglevel:</strong>
Set atemsys log level (Default <code>KERN_INFO(6)</code>) according kernel log level definition.<br>
Example: <code>insmod atemsys loglevel=3</code>

<strong>AllowedPciDevices:</strong>
Select PCI / PCIe devices to be registered by atemsys. By default all PCI network devices are registered. Passing an empty string turns off the PCI driver registration. A semicolon separated list of devices defined by the following format can be passed:<br>
<code>\<domain\>:\<bus\>:\<device\>.\<func\></code><br>
Example: <code>insmod atemsys AllowedPciDevices="0000:01:00.0;0000:02:00.0"</code>
