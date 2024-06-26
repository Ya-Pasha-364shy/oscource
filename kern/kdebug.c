#include <inc/string.h>
#include <inc/memlayout.h>
#include <inc/assert.h>
#include <inc/dwarf.h>
#include <inc/elf.h>
#include <inc/x86.h>
#include <inc/error.h>

#include <kern/kdebug.h>
#include <kern/pmap.h>
#include <kern/env.h>
#include <inc/uefi.h>


void
load_kernel_dwarf_info(struct Dwarf_Addrs *addrs) {
    addrs->aranges_begin = (uint8_t *)(uefi_lp->DebugArangesStart);
    addrs->aranges_end = (uint8_t *)(uefi_lp->DebugArangesEnd);
    addrs->abbrev_begin = (uint8_t *)(uefi_lp->DebugAbbrevStart);
    addrs->abbrev_end = (uint8_t *)(uefi_lp->DebugAbbrevEnd);
    addrs->info_begin = (uint8_t *)(uefi_lp->DebugInfoStart);
    addrs->info_end = (uint8_t *)(uefi_lp->DebugInfoEnd);
    addrs->line_begin = (uint8_t *)(uefi_lp->DebugLineStart);
    addrs->line_end = (uint8_t *)(uefi_lp->DebugLineEnd);
    addrs->str_begin = (uint8_t *)(uefi_lp->DebugStrStart);
    addrs->str_end = (uint8_t *)(uefi_lp->DebugStrEnd);
    addrs->pubnames_begin = (uint8_t *)(uefi_lp->DebugPubnamesStart);
    addrs->pubnames_end = (uint8_t *)(uefi_lp->DebugPubnamesEnd);
    addrs->pubtypes_begin = (uint8_t *)(uefi_lp->DebugPubtypesStart);
    addrs->pubtypes_end = (uint8_t *)(uefi_lp->DebugPubtypesEnd);
}

void
load_user_dwarf_info(struct Dwarf_Addrs *addrs) {
    assert(curenv);

    uint8_t *binary = curenv->binary;
    assert(binary);

    struct {
        const uint8_t **end;
        const uint8_t **start;
        const char *name;
    } sections[] = {
            {&addrs->aranges_end, &addrs->aranges_begin, ".debug_aranges"},
            {&addrs->abbrev_end, &addrs->abbrev_begin, ".debug_abbrev"},
            {&addrs->info_end, &addrs->info_begin, ".debug_info"},
            {&addrs->line_end, &addrs->line_begin, ".debug_line"},
            {&addrs->str_end, &addrs->str_begin, ".debug_str"},
            {&addrs->pubnames_end, &addrs->pubnames_begin, ".debug_pubnames"},
            {&addrs->pubtypes_end, &addrs->pubtypes_begin, ".debug_pubtypes"},
    };

    memset(addrs, 0, sizeof(*addrs));

    /* Load debug sections from curenv->binary elf image */
    // LAB 8: Your code here
    assert(curenv->binary);

    const struct Elf* elf_header   = (const struct Elf*) curenv->binary;
    
    const struct Secthdr* sec_headers      = (const struct Secthdr*) (curenv->binary + elf_header->e_shoff);
    const        uint16_t sec_headers_num  = (const        uint16_t) elf_header->e_shnum;

    const struct Secthdr* shstr_header = sec_headers + elf_header->e_shstrndx;
    uint64_t shstr_offs = shstr_header->sh_offset; 
    const char* shstr = (const char*) (binary + shstr_offs);
    
    for (unsigned sections_iter = 0; sections_iter < sizeof(sections) / sizeof(sections[0]); sections_iter++)
    {
        for (uint16_t sec_header_iter = 0; sec_header_iter < sec_headers_num; sec_header_iter++)
        {
            const struct Secthdr* cur_sec_header = sec_headers + sec_header_iter;
            uint32_t sh_name = cur_sec_header->sh_name;

            if (strcmp(sections[sections_iter].name, shstr + sh_name) == 0)
            {

                *(sections[sections_iter].start) = curenv->binary  + cur_sec_header->sh_offset;
                *(sections[sections_iter].end  ) = *(sections->start) + cur_sec_header->sh_size;

                // user_mem_assert(curenv, *(sections[sections_iter].start), cur_sec_header->sh_size, PROT_R);

                goto found;
            }
        }

        panic("load_user_dwarf_info: failed to find debug section: %s \n", sections[sections_iter].name);

    found:
        continue;
    }
}

#define UNKNOWN       "<unknown>"
#define CALL_INSN_LEN 5

/* debuginfo_rip(addr, info)
 * Fill in the 'info' structure with information about the specified
 * instruction address, 'addr'.  Returns 0 if information was found, and
 * negative if not.  But even if it returns negative it has stored some
 * information into '*info'
 */
int
debuginfo_rip(uintptr_t addr, struct Ripdebuginfo *info) {
    if (!addr) return 0;

    /* Initialize *info */
    strcpy(info->rip_file, UNKNOWN);
    strcpy(info->rip_fn_name, UNKNOWN);
    info->rip_fn_namelen = sizeof UNKNOWN - 1;
    info->rip_line = 0;
    info->rip_fn_addr = addr;
    info->rip_fn_narg = 0;


    /* Temporarily load kernel cr3 and return back once done.
     * Make sure that you fully understand why it is necessary. */

    // LAB 8: Your code here:

    struct AddressSpace* prev = switch_address_space(&kspace);

    /* Load dwarf section pointers from either
     * currently running program binary or use
     * kernel debug info provided by bootloader
     * depending on whether addr is pointing to userspace
     * or kernel space */

    // LAB 8: Your code here:

    struct Dwarf_Addrs addrs;
    if (addr > MAX_USER_ADDRESS)
        load_kernel_dwarf_info(&addrs);
    else 
        load_user_dwarf_info(&addrs);

    switch_address_space(prev);

    Dwarf_Off offset = 0, line_offset = 0;
    int res = info_by_address(&addrs, addr, &offset);
    if (res < 0) goto error;

    char *tmp_buf = NULL;
    res = file_name_by_info(&addrs, offset, &tmp_buf, &line_offset);
    if (res < 0) goto error;
    strncpy(info->rip_file, tmp_buf, sizeof(info->rip_file));

    /* Find line number corresponding to given address.
     * Hint: note that we need the address of `call` instruction, but rip holds
     * address of the next instruction, so we should substract 5 from it.
     * Hint: use line_for_address from kern/dwarf_lines.c */

    // LAB 2: Your res here:
    int line = 0;
    res = line_for_address(&addrs, addr, line_offset, &line);
    if (res < 0) goto error;
    info->rip_line = line;

    /* Find function name corresponding to given address.
     * Hint: note that we need the address of `call` instruction, but rip holds
     * address of the next instruction, so we should substract 5 from it.
     * Hint: use function_by_info from kern/dwarf.c
     * Hint: info->rip_fn_name can be not NULL-terminated,
     * string returned by function_by_info will always be */

    // LAB 2: Your res here:
    tmp_buf = NULL;
    uintptr_t offs;
    res = function_by_info(&addrs, addr - 5,  offset, &tmp_buf, &offs);
    if (res < 0) goto error;
    strncpy(info->rip_fn_name, tmp_buf, RIPDEBUG_BUFSIZ);
    info->rip_fn_namelen = strlen(tmp_buf);
    info->rip_fn_addr = offs;

error:
    return res;
}

uintptr_t
find_function(const char *const fname) {
    /* There are two functions for function name lookup.
     * address_by_fname, which looks for function name in section .debug_pubnames
     * and naive_address_by_fname which performs full traversal of DIE tree.
     * It may also be useful to look to kernel symbol table for symbols defined
     * in assembly. */

    // LAB 3: Your code here:
    struct Dwarf_Addrs addrs;
    load_kernel_dwarf_info(&addrs);

    uintptr_t offset = 0;

    int res = naive_address_by_fname(&addrs, fname, &offset);
    if (res < 0)
        res = address_by_fname(&addrs, fname, &offset);
    
    if (res < 0 && res != -E_NO_ENT)
        panic("address_by_fname: %i", res);

    if (offset != 0 && res == 0)
        return offset;

    for (struct Elf64_Sym *kern_sym = (struct Elf64_Sym *)uefi_lp->SymbolTableStart;
        (EFI_PHYSICAL_ADDRESS) kern_sym < uefi_lp->SymbolTableEnd; kern_sym++) {

        const char *kern_sym_name = (const char *)(uefi_lp->StringTableStart + kern_sym->st_name);

        if (!strcmp (kern_sym_name, fname))
        {
            offset = (uintptr_t) kern_sym->st_value;
            return offset;
        }
    }

    
    return offset;
}
