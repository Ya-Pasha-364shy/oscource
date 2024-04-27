/* See COPYRIGHT for copyright information. */

#ifndef JOS_INC_ENV_H
#define JOS_INC_ENV_H

#include <inc/types.h>
#include <inc/trap.h>
#include <inc/memlayout.h>

typedef int32_t envid_t;

/* An environment ID 'envid_t' has three parts:
 *
 * +1+---------------21-----------------+--------10--------+
 * |0|          Uniqueifier             |   Environment    |
 * | |                                  |      Index       |
 * +------------------------------------+------------------+
 *                                       \--- ENVX(eid) --/
 *
 * The environment index ENVX(eid) equals the environment's offset in the
 * 'envs[]' array.  The uniqueifier distinguishes environments that were
 * created at different times, but share the same environment index.
 *
 * All real environments are greater than 0 (so the sign bit is zero).
 * envid_ts less than 0 signify errors.  The envid_t == 0 is special, and
 * stands for the current environment.
 */

#define LOG2NENV    10
#define NENV        (1 << LOG2NENV) // 1024
#define ENVX(envid) ((envid) & (NENV - 1))

/* Values of env_status in struct Env */
enum {
    ENV_FREE,
    ENV_DYING,
    ENV_RUNNABLE,
    ENV_RUNNING,
    ENV_NOT_RUNNABLE
};

/* Special environment types */
enum EnvType {
    ENV_TYPE_IDLE,
    ENV_TYPE_KERNEL,
    ENV_TYPE_USER,
};

struct List {
    struct List *prev, *next;
};

struct AddressSpace {
    /**
     * аппаратная таблица страниц
    */
    pml4e_t *pml4;     /* Virtual address of pml4 - таблица страниц */
    uintptr_t cr3;     /* Physical address of pml4 - энтрипоинт в таблицу страниц*/
    /**
     * Дерево, описывающее отображение виртуальных страниц на адреса.
     * Листья содержат ссылки на виртуальные страницы физической памяти,
     * отображённые на соотвествующие физические адреса.
     * Есть MAPPING_NODE (конечная нода), есть INTERMEDIATE_NODE
    */
    struct Page *root; /* root node of address space tree */
};


struct Env {
    struct Trapframe env_tf; /* Saved registers */
    struct Env *env_link;    /* Next free Env */
    envid_t env_id;          /* Unique environment identifier */
    envid_t env_parent_id;   /* env_id of this env's parent */
    enum EnvType env_type;   /* Indicates special system environments */
    unsigned env_status;     /* Status of the environment */
    uint32_t env_runs;       /* Number of times environment has run */

    uint8_t *binary; /* Pointer to process ELF image in kernel memory */

    /* Address space */
    struct AddressSpace address_space;
};

#endif /* !JOS_INC_ENV_H */
