bpftrace -c "$1" -e '
tracepoint:syscalls:sys_enter*
{
	if (pid == cpid) {               
		printf("[+] PID %d (%s) hit probe: %s \n",
		pid, comm, probe);
	}
}'
