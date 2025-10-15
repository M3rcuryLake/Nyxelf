import os
import subprocess
import sys
from time import sleep
import pexpect
import datetime

def ext_copy(source_file, image_path, target_path, gid=0, uid=0):
    """
    Copy a file into a filesystem image.

    Args:
        source_file (str): Path to the source file to copy.
        image_path (str): Path to the ext2/3/4 filesystem image.
        target_path (str): Target path inside the image.
        gid (int): Group ID to set for the file (default: 0).
        uid (int): User ID to set for the file (default: 0).
    """
    source_file = os.path.abspath(source_file)
    image_path = os.path.abspath(image_path)

    command = f"e2cp -G {gid} -O {uid} {source_file} {image_path}:{target_path}"
    print("[*] Copying executable to Sandbox...")

    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()

    if process.returncode == 0:
        check = subprocess.run(["e2ls", f"{image_path}:{target_path}"], stdout=subprocess.PIPE, text=True)
        print(check.stdout)
        print("[*] Copied file to Sandbox successfully")
    else:
        print(f"Error copying file: {stderr.decode()}")

    sleep(1)

def session(file_path, kernel, rootfs, bpfr, nettrace, logtofile):
    """
    Start a QEMU session for dynamic analysis.

    Args:
        file_path (str): Path to the file to be analyzed.
        kernel (str): Path to the kernel image.
        rootfs (str): Path to the root filesystem image.
        bpfr (str): shell script used for running BPFtrace.
        nettrace (bool) : If True, enables tcpdump network logging.
    """

    file_name = os.path.basename(file_path)
    data_dir = "./data/"
    user = "root"

    print("[*] Anayzing executable in Sandbox Environment")
    marker_a = datetime.datetime.now()


    cmd = (
        f"qemu-system-x86_64 -kernel {kernel} -hda {rootfs} "
        f"-append \"root=/dev/sda rw console=ttyS0\" "
        "--enable-kvm --nographic -m 512 -cpu host -smp 4 "
        f"-virtfs local,path={data_dir},mount_tag=host_trace,security_model=none,readonly=off"
    )

    child = pexpect.spawn(cmd, encoding='utf-8', timeout=120)
    if logtofile:
        child.logfile = open(f"{data_dir}/qemu.logs", "w")
    else:
        child.logfile = sys.stdout

    def expect_prompt():
        try:
            child.expect('# ')
        except pexpect.TIMEOUT:
            child.sendline('')
            child.expect('# ')

    try:
        child.expect('Nyxelf login: ')
        child.sendline(user)
        expect_prompt()
    
        print("[*] Starting DHCP Client Daemon...")
        child.sendline("dhcpcd && sleep 3")
        # Starts the DHCP client daemon (dhcpcd) to get an IP via DHCP,
        # then waits 3 seconds for the interface to come up.
        expect_prompt()

        child.sendline("mount -t tracefs nodev /sys/kernel/tracing || true")
        print("[*] Mounted tracefs.")
        # Mounts the kernel’s tracing filesystem (tracefs),
        # which exposes kernel tracing info. The || true ensures it doesn’t exit on failure.
        expect_prompt()

        child.sendline("mkdir -p /mnt/host_trace && mount -t 9p -o trans=virtio,version=9p2000.L host_trace /mnt/host_trace")
        print("[*] Enabled Host-Guest Sync")
        # Creates the mount point /mnt/host_trace and then 
        # mounts a 9p (Plan 9) shared filesystem provided by QEMU, allowing host-guest file exchange.
        # Uses the virtio transport and 9p2000.L protocol.
        expect_prompt()

        child.sendline("echo '[+] 9P mounted:' && mount | grep host_trace")
        # Prints a status message and verifies the 9p mount worked.
        expect_prompt()

        child.sendline(f'chmod +x {bpfr} && chmod +x {file_name}')
        expect_prompt()
         
        perf_a = datetime.datetime.now()

        if nettrace:
            print("[*] Capturing Network Packets.")
            child.sendline("nohup tcpdump -U -i enp0s3 -w /mnt/host_trace/trace.pcap > /dev/null 2>&1 &")
            expect_prompt()
            sleep(1)
        else:
            print("[*] Network Analysis Disabled.")

        print("[*] Started BPFtrace Analysis...")
        child.sendline(f"./{bpfr} '{file_name}'")
        expect_prompt()
        trace_output = child.before
        perf_b = datetime.datetime.now()
        sleep(5)

        child.sendline("sync")
        expect_prompt()
        print("[*] Finished BPFtrace Analysis.")

        child.sendline(f'chmod +x {file_name}')
        expect_prompt()

        print("[*] Anayzing Memory with Valgrind.")
        child.sendline(f"valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes --time-stamp=yes --verbose ./{file_path}")
        expect_prompt()
        memtrace_output = child.before
        
        intr = 0
        idr = trace_output.split("\n")
        for _ in idr:
            if _.startswith("Attaching"):
                intr = idr.index(_)
        trace_output = "\n".join(idr[intr:])


        print("[*] Dynamic Analysis Done")
        
        with open(f'{data_dir}/trace.log', 'w') as trace_file:
            trace_file.write(trace_output)
            print("[*] The BPFtrace and the Tcpdump (.pcap) files are saved to the ./data directory...")

    finally:
        if child.isalive():
            child.sendline('poweroff')
            child.close()
    
    marker_b = datetime.datetime.now()

    sandbox_time = marker_b - marker_a
    exec_time = perf_b - perf_a
    size = os.path.getsize(file_path)

    return trace_output, memtrace_output, sandbox_time, exec_time, size

