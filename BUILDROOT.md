
# Generating Buildroot kernel & filesytem images for sandbox analysis

## Purpose & Scope

Provided along is a [.config](https://github.com/M3rcuryLake/Nyxelf/blob/main/data/.config) file that produces an x86_64 Linux kernel and an ext2 root filesystem sized to ~340 MB, intended for sandbox analysis along with the Nyxelf of ELF binaries.  
The system is configured for dynamic and static instrumentation: BPF tooling, ftrace, debug symbols (DWARF4), BTF, user/kernel tracing, network capture utilities, and common runtime helpers (DHCP, network management, wireless support). This accompanying manual only documents them and gives concrete, minimal example commands.


## Explanation of mapping of `menuconfig`

These are the important Buildroot `menuconfig` and `linux-menuconfig` selections present in the `.config` and what they mean in practice.

### _Buildroot (`make menuconfig`)_

-   **Target options → Target Architecture: `x86_64`**  
    Produces binaries and kernel built for AMD64 / Intel 64. Use this when you will run images under QEMU x86_64 or on compatible hardware.
-   **Compiler cache enabled (ccache)**  
    Speeds repeated builds by caching compilation results. Useful during iterative development; watch disk usage. 
-   **/dev management = Dynamic (devtmpfs + eudev)**  
    The kernel will mount `devtmpfs` at boot and `eudev` will populate device nodes dynamically. This mirrors real system behavior and enables hotplug for virtual devices.    
-   **PATH set to** `(/usr/bin:/bin:/sbin:/usr/sbin)`  
    Ensures BusyBox and other utilities are resolved reliably during runtime and scripts.    
-   **Target packages (selected)**
    
    -   `bpftool`, `bpftrace` — to inspect and attach eBPF programs and to write quick BPF probes.
    -   `valgrind` — dynamic memory/thread checking (big & slow; keep for deep analysis).
    -   `strace` — syscall tracing for userland processes.
    -   `tcpdump` — pcap capture for network traffic capture.
    -   `dhcpcd`, `network-manager`, `wpa_supplicant` — networking stack clients to obtain IP via DHCP and manage wireless connections inside the guest.
    -   *Lightning library* (selected to fix `libsframe.so.1`-type issues I kept running into issues) — ensures required runtime libs are present for certain analysis tools.        
-   **Filesystem**  
    `ext2` chosen as the rootfs format with a *maximum* size ~340 MB. Ext2 is simple to mount and debug; no journal reduces write amplification and simplifies snapshotting in sandboxes.
    
    
### _Linux kernel (`make linux-menuconfig`)_

-   **Networking support**
    -   IPv4/IPv6 enabled.
    -   IP multicasting, Policy routing and verbose route monitoring available to observe route changes.    
    -   Kernel-level autoconfiguration enabled, extending network layer support with DHCP, BOOTP, RARP. These are useful for guests relying on kernel-level network helpers.
    -    in the *Wireless* sub-section, `cfg80211` and `mac80211` enabled — support for modern wireless stacks (if testing wireless behavior in VMs or hardware).
    - Both TCP and UDP support are builtin but when using `ping`, the program breaks. It may suggest ICMP protocol is not supported in this particular case, I haven't been able to find a fix and I may be wrong about ICMP. If you do find a fix, you are welcome to contribute :) 
        
-   **Tracing / BPF / Debugging**
    
    -   **BPF subsystem** enables programmable instrumentation without rebuilding the kernel. ftrace provides low-level kernel tracing primitives, it applicated in almost the same way as [SystemTap](https://wiki.archlinux.org/title/SystemTap) in [LiSa](https://github.com/danielpoliakov/lisa/tree/master/lisa)
    -   ftrace enabled and `debugfs` mounted support — for function tracing, dynamic tracepoints, etc. `debugfs` or `tracefs` is a pseudo-filesystem used by many tracing subsystems to present state and control knobs. But according to the should use  `/sys/kernel/tracing`.**  Both  `/sys/kernel/tracing`  and  `/sys/kernel/debug/tracing`  are  `tracefs`  mounts, so in theory they are equivalent. However, the second one depends on  `debugfs`  being available (since it is created inside the  `debugfs`  mount). This is mentioned in this [thread](https://lkml.org/lkml/2015/1/26/454) from lkml.org

    -   **Devtmpfs + eudev** is enabled  dynamic device management is necessary when the guest is run under emulators (QEMU/virtio) where device lists change between runs. `devtmpfs` provides a kernel-managed `/dev`; `eudev` is required as a dependency for NetworkManager.
    -   Debug info set to **DWARF v4** and **BTF** (BPF Type Format) enabled for both user and kernel mode — essential for high-fidelity stack traces, symbol resolution, and meaningful bpftrace scripts. DWARF debug symbols provide source-level and type information for debugging, while BTF adds lightweight type metadata that eBPF tooling uses to resolve kernel and user types at runtime. Enabling both makes tools like `bpftrace` and `bpftool` much more informative.

    -   Kernel hacking → **Tracers**: I can't talk about this directly here as many tracers are enabled and I may be wrong about most of them. Some of which I used are trace max stack, function probes, profiler, event injection, syscall and user-mode tracing. Without these bpftrace may not be able to trace that probe. This makes the kernel heavy but maximally useful for forensic tracing.
        
-   **Trade-offs**:  
    Enabling all tracers, debug symbols, and BPF increases kernel and rootfs size. For sandbox images intended for repeated distribution, consider a trimmed "analysis" vs "fast" configuration.

### _Mount-Based File Sync System:_
At first I was using a simple `subprocesses.run()` system which used `e2cp` to copy .pcap files from the filesystem image, but I faced a constant issue. Tcpdump buffers packet data in memory for performance reasons and writes at once. When `pexpect` sends commands it doesn’t “gracefully” stop background processes like `tcpdump`.  If the script terminates `tcpdump` with a forceful signal, the process never executes its cleanup routine that writes the `.pcap` and flushes the capture count summary. That’s why my manual runs worked perfectly, but automated runs didn’t.
To bridge this gap, QEMU provides a *mount-based shared filesystem mechanism* with the *VirtFS (9p filesystem)* protocol using the `-virtfs` flag.
finally to connect the shared directory I used the following commands inside the guest.
```bash
mkdir -p /mnt/host_trace 
mount -t 9p -o trans=virtio,version=9p2000.L host_trace /mnt/host_trace
```

This setup allows the host to expose a directory that the guest can access as though it were a normal filesystem.  
The communication between the two is handled through a **paravirtualized interface**, meaning it’s optimized for virtualized environments and doesn’t require network or block devices.

## Practical build steps

On incremental rebuilds, `ccache` will speed up compilation. Monitor `~/.ccache` or the configured cache dir. Also in the `.config` I have enabled the `require host pahole` as pahole (part of the `dwarves` toolset) is a utility that uses debugging information like DWARF or BTF to show data structure layouts, help optimize their size, and pretty-print data and is a dependency for `ftrace` and `btf` .
For prerequisites and dependencies lookup [this doc](https://buildroot.org/downloads/manual/prerequisite.txt).

```bash
sudo apt install -y ccache dwarves which sed make binutils \
 build-essential diffutils gcc g++ bash patch gzip bzip2 perl \
 tar cpio unzip rsync file bc findutils libncurses-dev
wget https://buildroot.org/downloads/buildroot-2025.08.1.tar.gz
tar xvf buildroot-2025.08.1.tar.gz
```


After finishing the installation and extraction process, run the following commands to start the build process 

```bash
# First ensure repo tree contains .config (the provided config)
cp path/to/nyxelf/data/.config path/to/buildroot/.config

# Enter Buildroot and (optionally) review or tweak interactively
cd buildroot

# Clean (optional) and build
make clean && make -j$(nproc)         # compiles toolchain, packages, kernel, rootfs

# - Kernel image typically: output/images/bzImage
# - Rootfs image (ext2): output/images/rootfs.ext2
# - Output/images/rootfs.tar (depending on config)

```
If the build process is excruciatingly slow, set `BR2_JLEVEL=0` to amount the number of processors you want to allocate to the build process.

And finally to boot up the image, use :
```bash
qemu-system-x86_64 -kernel bzImage -hda rootfs.ext2 \
-append "root=/dev/sda rw console=ttyS0" --enable-kvm --nographic -m 512\
-virtfs local,path=../data/,mount_tag=host_trace,security_model=none,readonly=off \
-smp $(nproc) -cpu host
```
Security model and read-only mode is set to none to escape from the permission hell. Nothing else. And I won't explain this basic qemu command after all of this.

## 10. Conclusion (short)

This build is deliberately configured to maximize observability inside a guest: BPF, ftrace, DWARF4/BTF, debugfs, and standard analysis tools are enabled to let probe kernel and user behavior deeply. The `.config` included with the repository is the big thing, throw it in with Buildroot to reproduce the described image.
