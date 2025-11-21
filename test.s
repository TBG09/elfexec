.section .data
    filename: .string "test_output.txt"
    output_str: .ascii "Hello from elfexec!\n"
    output_len = . - output_str

.section .text
.global _start

_start:
    # 1. Create and open the file
    # int open(const char *pathname, int flags, mode_t mode);
    mov $2, %rax              # syscall number for open
    lea filename(%rip), %rdi  # pathname
    mov $0101, %rsi           # flags (O_WRONLY | O_CREAT)
    mov $0644, %rdx           # mode
    syscall
    
    # rax now holds the new file descriptor. Store it in r12.
    mov %rax, %r12

    # 2. Write the string to the new file
    mov $1, %rax              # syscall number for write
    mov %r12, %rdi            # fd (from our open call)
    lea output_str(%rip), %rsi # buffer
    mov $output_len, %rdx     # count
    syscall

    # 3. Close the file
    # int close(int fd);
    mov $3, %rax              # syscall number for close
    mov %r12, %rdi            # fd to close
    syscall

    # 4. Exit
    mov $60, %rax             # syscall number for exit
    xor %rdi, %rdi            # exit code 0
    syscall
