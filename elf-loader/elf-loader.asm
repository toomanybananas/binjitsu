%include "linux/32.asm"
%include "linux/64.asm"
%include "defines.asm"

%define PAGE_SIZE   4096

; !!! If you change this, then change it in print_sizes.py too !!!
%define LOADER_POS  0x100000

org LOADER_POS

; ELF-loader written in shellcode for loading 32-bit static ELF-files
; It works on both 32-bit and 64-bit linux, assuming that it is possible
; to jump to 32-bit mode from 64-bit mode by doing a far jump to 0x23:ADDR
;
; Algorithm: (a is 32-bit only, b is 64-bit only)
; 1a:
;       Assume that a stack is available
;       where you can push at least 6 words
; 1b:
;       Allocate such a stack (this cannot be done in 32-bit
;       mode without already having memory available)
; 2:
;       Find the address of the beginning of the code using a call.
;       Find the entire length of the payload, which can be done
;       since the position of the code is known
; 3:
;       Allocate space at LOADER_POS for moving the entire payload
; 4:
;       Move the payload to LOADER_POS
; 5a:
;       Jump to LOADER
; 5b:
;       Jump to LOADER as 32-bit code
; 6:
;       Parse the elf headers and load in the relevant parts, by first
;       unmapping it's pages and then mapping them again
; 7:
;       Put a bit of content on the stack so that libc won't fail
; 8:
;       Jump to the entry-point
;
; Known bugs/problems:
; - The stack is not set up in the same way as the kernel
;   would. The argv and envp is greatly simplified and the ELF aux
;   table is not there.
;   See http://www.win.tue.nl/~aeb/linux/hh/stack-layout.html
;
; - A lot of stuff is still mapped into the memory space when the
;   program runs.
;
; - In 32-bit mode you _could_ make do with just a single word needed
;   on the stack, by only doing a single call to get the shellcode-address
;   and use this for storage afterwards. This however makes it harder to
;   use the same code in both 32-bit and 64-bit so this is not done currently.
;
; - Even if the 64-bit kernel supports jumping to 32-bit mode with the 0x23
;   segment, it still has a few kinks. For example will mmap per default
;   allocate pages in the entire 64-bit range even though it only returns the
;   lower 32-bits. This behaviour can be fixed by using MAP_32BIT however it
;   might not always be this easy.
;
; Compile with:
; nasm elf-loader.asm && (cat elf-loader && python print_sizes.py elf-loader $STATIC_ELF && cat $STATIC_ELF) > payload

; Step 1a/1b
[bits 64] ; Mixed 32/64-bit
detect_mode:
    xor eax, eax
    and rax, rax        ; This is a "dec eax; and eax, eax" on 32-bit

    jne short get_info

; Step 1b
[bits 64] ; Pure 64-bit
alloc_stack:
    mov rax, SYS64_mmap
    xor rdi, rdi                                    ; addr
    mov rsi, 120                                    ; length
    mov rdx, PROT_READ | PROT_WRITE                 ; prot
    mov r10, MAP_SHARED | MAP_ANONYMOUS | MAP_32BIT ; flags
    xor r8, r8                                      ; fd
    xor r9, r9                                      ; offset

    syscall
    lea esp, [rax+120]

; Step 2
[bits 64] ; Mixed 32/64-bit
get_info:
    call tramp
tramp:
    pop rsi
    sub rsi, (tramp - $$)
    mov ebp, [rsi + len - $$]

; Step 3
[bits 64] ; Mixed 32/64-bit
    push SYS_mmap
    pop rax

    ; In 64-bit these all push 8 bytes each, but all this changes is that
    ; it adds more 0-bytes at the top of the stack, so it doesn't really
    ; matter much
    push 0                                                  ; offset
    push 0                                                  ; fd
    push MAP_SHARED | MAP_ANONYMOUS | MAP_FIXED             ; flags

    lea ebx, [rsp - 12]
    mov dword [rbx+8], PROT_READ | PROT_WRITE | PROT_EXEC   ; prot
    mov [rbx+4], ebp                                        ; len
    mov dword [rbx+0], $$                                   ; addr

    int 0x80

; Step 4
[bits 64] ; Mixed 32/64-bit
    mov edi, eax
    mov ecx, [rsi + len - $$]
    rep movsb

; Step 5a/5b
[bits 64] ; Mixed 32/64-bit
    xor rax, rax
    and rax, rax
    je jump_64

; Step 5a
[bits 32] ; Pure 32-bit
jump_32:
    mov ebx, parse_elf
    jmp ebx

; Step 5b
[bits 64] ; Pure 64-bit
jump_64:
    push 0x23
    push jump_64_fixup
    jmp far [rsp]

[bits 32] ; Pure 32-bit
jump_64_fixup:
    push ss
    pop ds

    push ss
    pop es

; Step 6
[bits 32] ; Pure 32-bit
parse_elf:
    movzx   ebp, word [elf_begin + Elf32_Ehdr.e_phnum]
    mov     edx, [elf_begin + Elf32_Ehdr.e_phoff]
    add     edx, elf_begin

map_loop:
    cmp dword [edx+Elf32_Phdr.p_type], PT_LOAD
    jne map_next

    mov edi, [edx + Elf32_Phdr.p_vaddr]
    and edi, ~(PAGE_SIZE-1)

    mov esi, [edx + Elf32_Phdr.p_filesz]
    dec esi
    shr esi, 12
    inc esi

map_inner_loop:
    mov ebx, edi
    mov ecx, PAGE_SIZE
    mov eax, SYS_munmap
    int 0x80

    mov [mmap_addr], edi
    mov ebx, mmap_addr
    mov eax, SYS_mmap
    int 0x80

    add edi, PAGE_SIZE
    dec esi
    jne map_inner_loop

    mov esi, [edx + Elf32_Phdr.p_offset]
    add esi, elf_begin
    mov edi, [edx + Elf32_Phdr.p_vaddr]
    mov ecx, [edx + Elf32_Phdr.p_filesz]
    rep movsb

map_next:
    add edx, Elf32_Phdr_size
    dec ebp
    jne map_loop

map_stack:
    mov dword [mmap_addr], 0
    mov dword [mmap_len], 16*PAGE_SIZE
    mov dword [mmap_flags], MAP_SHARED | MAP_ANONYMOUS | MAP_32BIT
    mov ebx, mmap_addr
    mov eax, SYS_mmap
    int 0x80
    lea esp, [eax+16*PAGE_SIZE]

; Step 7
[bits 32] ; Pure 32-bit
fix_stack:
    mov ecx, 64
fix_stack_loop:
    push 0
    loop fix_stack_loop

; Step 8
[bits 32] ; Pure 32-bit
    jmp [elf_begin + Elf32_Ehdr.e_entry]

mmap_addr:      dd $$
mmap_len:       dd PAGE_SIZE
mmap_prot:      dd PROT_READ | PROT_WRITE | PROT_EXEC
mmap_flags:     dd MAP_SHARED | MAP_ANONYMOUS | MAP_FIXED
mmap_fd:        dd 0
mmap_offset:    dd 0

len:
next_page equ len + 4
elf_begin equ len + 8