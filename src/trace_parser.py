def byte_sequences(input_string):
    
    # this function is used to remove the unknown and undecodable BINARY data
    # and replace it with a simple string saying "[BINARY DATA]"

    result = input_string.startswith('"\\')
    return result

def init_parser(log):

    # converts the input log
    # to a list with three items (time, agrs, return value)

    list_st = []
    for _ in log:
        aps = _.split("\n")[0]
        aps = aps.split(" ", 1)
        list_st.append(aps)

    print("[*] Parsed Strace Output")

    return list_st


def parser(strace_list, TYPE = "long"):

    """
    Parse and categorize strace output into file I/O and process management syscalls.

    Args:
        strace_list (list): List of parsed strace log entries.
        TYPE (str): Output type, "long" or "short" (default: "long").

    Returns:
        dict: Categorized syscall details.
    """

    FILE_IO_SYSCALLS = [
        "open", "openat", "read", "write", "close", "stat", "fstat", "lstat",
        "unlink", "rename", "access", "pread64", "pwrite64", "mkdir"
    ]
    PROCESS_MANAGEMENT_SYSCALLS = [
        "execve", "fork", "vfork", "clone", "exit", "exit_group", "waitpid",
        "wait4", "set_tid_address", "set_robust_list", "prlimit64", "arch_prctl"
    ]

        

    def filter_syscalls(log_lines):
        fd_to_filename ={}
        file_io_calls = []
        process_mgmt_calls = []
        cells_long = ["Timestamp", "Syscall", "Syscall Details", "Return"]
        cells = ["Timestamp", "Syscall", "Return"]
        
        for line in log_lines:
            if len(line) < 2:
                continue
            syscall_details = line[1]
        
            # extract syscall name 
            syscall_name = syscall_details.split("(")[0]
            if syscall_name in ["open", "openat"]:
            
            
            # Dereferences the file path to its designated file descriptor
            # it locates the number to in the ARGUMENTS section and replaces it 
            # with the filepath retrived from the thingy


                filename = syscall_details.split(', ')[1].strip('"')
                fd = syscall_details.split(') = ')[-1].strip()
                if fd.isdigit():
                    fd_to_filename[fd] = filename

            for fd, filename in fd_to_filename.items():
                if f"{fd}" in syscall_details:
                    syscall_details = syscall_details.replace(f"{fd}" , f'{filename}', 1)


            det = syscall_details.split(' = ')[0] 
            ret = syscall_details.split(' = ')[-1]

            det = det.split('(')[-1]
            det = det.split(')')[0]

            data = det.split(', ')
            
            if len(data)>1 and byte_sequences(data[1]):
                data[1] = "[BINARY DATA]"
                det = ", ".join(data)
                

            # replaces 0, 1, 2 with stdin, stdout and stderr for better understanding

            if syscall_name in FILE_IO_SYSCALLS:
                if det.split(", ")[0] == '0':
                    det = det.replace('0', 'Read from STDIN', 1)

                elif det.split(", ")[0] == '1':
                    det = det.replace('1', 'Write to STDOUT', 1)

                elif det.split(", ")[0] == '2':
                    det = det.replace('2', 'Error : STDERR', 1)




            if TYPE == "long":

                # added a "long" type and a "short" type option
                # long type : shows the ARGUMENTS
                # short : only shows the syscall and return value


                line = [line[0], syscall_name, det, ret]

                if syscall_name in FILE_IO_SYSCALLS:
                    file_io_calls.append(dict(zip(cells_long, line)))
                elif syscall_name in PROCESS_MANAGEMENT_SYSCALLS:
                    process_mgmt_calls.append(dict(zip(cells_long, line)))

            
            else:
                line = [line[0], syscall_name, ret]

                if syscall_name in FILE_IO_SYSCALLS:
                    file_io_calls.append(dict(zip(cells, line)))
                elif syscall_name in PROCESS_MANAGEMENT_SYSCALLS:
                    process_mgmt_calls.append(dict(zip(cells, line)))

        return file_io_calls, process_mgmt_calls


    file_io, process_mgmt = filter_syscalls(strace_list)

    print("[*] Catagorized Strace Output")

    return  {
                "<h2>File I/O Syscalls</h2>" : file_io,
                "<h2>Process Management Syscalls</h2>" : process_mgmt
        }

    


