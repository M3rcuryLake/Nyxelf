import os
import subprocess
import sys
from time import sleep
import pexpect

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
    print(f"Running command: {command}")

    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()

    if process.returncode == 0:
        check = subprocess.run(["e2ls", f"{image_path}:{target_path}"], stdout=subprocess.PIPE, text=True)
        print(check.stdout)
        print("[*] Copied file to Sandbox successfully")
    else:
        print(f"Error copying file: {stderr.decode()}")

    sleep(1)

def session(file_path, kernel, rootfs, limit='2048'):
    """
    Start a QEMU session for dynamic analysis.

    Args:
        file_path (str): Path to the file to be analyzed.
        kernel (str): Path to the kernel image.
        rootfs (str): Path to the root filesystem image.
        limit (str): Maximum length of strings in strace output (default: '2048').
    """
    file_name = os.path.basename(file_path)
    data_dir = "./data/"
    user = "root"

    print("[*] Starting Sandbox Analysis")

    cmd = (
        f"qemu-system-x86_64 -kernel {kernel} -hda {rootfs} "
        f"-append \"root=/dev/sda rw console=ttyS0\" --enable-kvm --nographic"
    )

    child = pexpect.spawn(cmd, encoding='utf-8')
    child.logfile = sys.stdout

    try:
        # Log in to the sandbox
        child.expect('buildroot login: ')
        child.sendline(user)

        # List files to confirm file presence
        child.expect('# ')
        child.sendline('ls')
        child.expect('# ')
        print(child.before)

        # Make the file executable
        child.sendline(f'chmod a+x {file_name}')
        child.expect('# ')

        # Run the file with strace
        child.sendline(f'strace -tt -s {limit} ./{file_name}')
        child.expect('# ')
        strace_output = child.before

        print("[*] Dynamic Analysis Done")

        # Save the strace log
        with open(f'{data_dir}/strace.log', 'w') as trace_file:
            trace_file.write(strace_output)
    finally:
        if child.isalive():
            child.sendline('poweroff')
            child.close()
