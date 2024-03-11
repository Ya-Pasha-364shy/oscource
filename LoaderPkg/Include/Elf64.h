/** @file
  Copyright (c) 2020, ISP RAS. All rights reserved.
  SPDX-License-Identifier: BSD-3-Clause
**/

#ifndef JOS_UEFI_ELF_H
#define JOS_UEFI_ELF_H

#define ELF_MAGIC 0x464C457FU   /* "\x7FELF" in little endian */

struct Elf {
  UINT32 e_magic;       // must equal ELF_MAGIC
  UINT8  e_elf[12];
  UINT16 e_type;
  UINT16 e_machine;
  UINT32 e_version;
  /**
   * This member gives the virtual address to which the system first transfers control,
   * thus starting the process. If the file has no associated entry point,
   * this member holds zero.
  */
  UINT64 e_entry;
  /**
   * This member holds the program header table's (таблица сегментов) file offset in bytes.
   * If the file has no program header table, this member holds zero.
   * https://github.com/compilepeace/BINARY_DISSECTION_COURSE/blob/master/ELF/PROGRAM_HEADER_TABLE/PHT.md
  */
  UINT64 e_phoff;
  /**
   * This member holds the section header table's (таблица секций) file offset in bytes.
   * If the file has no section header table, this member holds zero.
  */
  UINT64 e_shoff;
  UINT32 e_flags;
  UINT16 e_ehsize;
  UINT16 e_phentsize;
  UINT16 e_phnum;
  /**
   * This member holds a section header's size in bytes.
   * A section header is one entry in the section header table;
   * all entries are the same size.
  */
  UINT16 e_shentsize;
  /**
   * This member holds the number
   * of entries in the section header table.
  */
  UINT16 e_shnum;
  /**
   * This member holds the section header table
   * index of the entry associated with the
   * section name string table.
   * If the file has no section name string table,
   * this member holds the value SHN_UNDEF.
  */
  UINT16 e_shstrndx;
};

/* это элемент таблицы заголовков (сегментов) - для каждого сегмента - своя таблица */
struct Proghdr {
  /**
   * kind of segment this array element describes or how to
   * interpret the array element's information 
  */
  UINT32 p_type;
  /**
   * flags relevant to the segment
  */
  UINT32 p_flags;
  /**
   * Дает смещение от начала файла, в
   * котором находится первый байт сегмента.
  */
  UINT64 p_offset;
  /**
   * Этот член дает виртуальный адрес,
   * по которому в памяти находится первый байт сегмента.
  */
  UINT64 p_va;
  /**
   * В системах, для которых важна физическая адресация,
   * этот член зарезервирован для физического адреса сегмента.
   * Этому участнику требуется информация, специфичная для операционной системы.
  */
  UINT64 p_pa;
  UINT64 p_filesz;
  UINT64 p_memsz;
  UINT64 p_align;
};

/* это элемент таблицы разделов (или секций .text, .data, .debug_info, - для каждой секции, своя таблица)*/
struct Secthdr {
  /**
   * This member specifies the name of the section.
   * Its value is an index into the "section header string table (strtab)" section
  */
  UINT32 sh_name;
  UINT32 sh_type;
  UINT64 sh_flags;
  UINT64 sh_addr;
  UINT64 sh_offset;
  UINT64 sh_size;
  UINT32 sh_link;
  UINT32 sh_info;
  UINT64 sh_addralign;
  UINT64 sh_entsize;
};

/* это элемент таблица символов */
struct Elf64_Sym {
  /**
   * This member holds an index into the object file's symbol string table, which holds
   * the character representations of the symbol names.
  */
  UINT32            st_name;
  UINT8             st_info;
  UINT8             st_other;
  UINT16            st_shndx;
  UINT64            st_value;
  UINT64            st_size;
};

/* Values for e_type. */
#define ET_NONE    0  /* Unknown type. */
#define ET_REL    1  /* Relocatable. */
#define ET_EXEC    2  /* Executable. */
#define ET_DYN    3  /* Shared object. */
#define ET_CORE    4  /* Core file. */
#define ET_LOOS    0xfe00  /* First operating system specific. */
#define ET_HIOS    0xfeff  /* Last operating system-specific. */
#define ET_LOPROC  0xff00  /* First processor-specific. */
#define ET_HIPROC  0xffff  /* Last processor-specific. */

/* Values for e_machine. */
#define EM_X86_64  62  /* Advanced Micro Devices x86-64 */
#define EM_AMD64  EM_X86_64  /* Advanced Micro Devices x86-64 (compat) */

/* Symbol Binding - ELFNN_ST_BIND - st_info */
#define STB_LOCAL  0  /* Local symbol */
#define STB_GLOBAL  1  /* Global symbol */
#define STB_WEAK  2  /* like global - lower precedence */
#define STB_LOOS  10  /* Reserved range for operating system */
#define STB_HIOS  12  /*   specific semantics. */
#define STB_LOPROC  13  /* reserved range for processor */
#define STB_HIPROC  15  /*   specific semantics. */

/* Symbol type - ELFNN_ST_TYPE - st_info */
#define STT_NOTYPE  0  /* Unspecified type. */
#define STT_OBJECT  1  /* Data object. */
#define STT_FUNC  2  /* Function. */
#define STT_SECTION  3  /* Section. */
#define STT_FILE  4  /* Source file. */
#define STT_COMMON  5  /* Uninitialized common block. */
#define STT_TLS    6  /* TLS object. */
#define STT_NUM    7
#define STT_LOOS  10  /* Reserved range for operating system */
#define STT_HIOS  12  /*   specific semantics. */
#define STT_LOPROC  13  /* reserved range for processor */
#define STT_HIPROC  15  /*   specific semantics. */

/* Symbol visibility - ELFNN_ST_VISIBILITY - st_other */
#define STV_DEFAULT  0x0  /* Default visibility (see binding). */
#define STV_INTERNAL  0x1  /* Special meaning in relocatable objects. */
#define STV_HIDDEN  0x2  /* Not visible. */
#define STV_PROTECTED  0x3  /* Visible but not preemptible. */

/*
 * Macros for manipulating st_info
 */
#define ELF_ST_BIND(x)          ((x) >> 4)
#define ELF_ST_TYPE(x)          (((unsigned int) x) & 0xf)
#define ELF32_ST_BIND(x)        ELF_ST_BIND(x)
#define ELF32_ST_TYPE(x)        ELF_ST_TYPE(x)
#define ELF64_ST_BIND(x)        ELF_ST_BIND(x)
#define ELF64_ST_TYPE(x)        ELF_ST_TYPE(x)

#define ET_NONE         0
#define ET_REL          1
#define ET_EXEC         2
#define ET_DYN          3
#define ET_CORE         4
#define ET_LOPROC       0xff00
#define ET_HIPROC       0xffff

// Values for Proghdr::p_type
#define ELF_PROG_LOAD           1

/* Legal values for p_type (segment type).  */

#define PT_NULL         0               /* Program header table entry unused */
#define PT_LOAD         1               /* Loadable program segment */
#define PT_DYNAMIC      2               /* Dynamic linking information */
#define PT_INTERP       3               /* Program interpreter */
#define PT_NOTE         4               /* Auxiliary information */
#define PT_SHLIB        5               /* Reserved */
#define PT_PHDR         6               /* Entry for header table itself */
#define PT_TLS          7               /* Thread-local storage segment */
#define PT_NUM          8               /* Number of defined types */
#define PT_LOOS         0x60000000      /* Start of OS-specific */
#define PT_GNU_EH_FRAME 0x6474e550      /* GCC .eh_frame_hdr segment */
#define PT_GNU_STACK    0x6474e551      /* Indicates stack executability */
#define PT_GNU_RELRO    0x6474e552      /* Read-only after relocation */
#define PT_LOSUNW       0x6ffffffa
#define PT_SUNWBSS      0x6ffffffa      /* Sun Specific segment */
#define PT_SUNWSTACK    0x6ffffffb      /* Stack segment */
#define PT_HISUNW       0x6fffffff
#define PT_HIOS         0x6fffffff      /* End of OS-specific */
#define PT_LOPROC       0x70000000      /* Start of processor-specific */
#define PT_HIPROC       0x7fffffff      /* End of processor-specific */

/* Flag bits for Proghdr::p_flags */
#define ELF_PROG_FLAG_EXEC      1
#define ELF_PROG_FLAG_WRITE     2
#define ELF_PROG_FLAG_READ      4

/* Values for Secthdr::sh_type */
#define ELF_SHT_NULL            0
#define ELF_SHT_PROGBITS        1
#define ELF_SHT_SYMTAB          2
#define ELF_SHT_STRTAB          3

/* Values for Secthdr::sh_name */
#define ELF_SHN_UNDEF           0

#endif /* JOS_UEFI_ELF_H */
