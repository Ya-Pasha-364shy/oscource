/* Simple command-line kernel monitor useful for
 * controlling the kernel and exploring the system interactively. */

#include <inc/stdio.h>
#include <inc/string.h>
#include <inc/memlayout.h>
#include <inc/assert.h>
#include <inc/env.h>
#include <inc/x86.h>

#include <kern/console.h>
#include <kern/monitor.h>
#include <kern/kclock.h>
#include <kern/kdebug.h>
#include <kern/tsc.h>
#include <kern/timer.h>
#include <kern/env.h>
#include <kern/pmap.h>
#include <kern/trap.h>
#include <kern/sched.h>

#include <kern/ip.h>
#include <kern/inet.h>
#include <inc/error.h>
#include <kern/eth.h>
#include <kern/icmp.h>
#include <kern/udp.h>
#include <kern/tcp.h>
#include <kern/traceopt.h>
#include <kern/http.h>

#define WHITESPACE "\t\r\n "
#define MAXARGS    16

/* Functions implementing monitor commands */
int mon_exit(int argc, char **argv, struct Trapframe *tf);

int mon_help(int argc, char **argv, struct Trapframe *tf);
int mon_kerninfo(int argc, char **argv, struct Trapframe *tf);
int mon_echo(int argc, char **argv, struct Trapframe *tf);
int mon_backtrace(int argc, char **argv, struct Trapframe *tf);
int mon_dumpcmos(int argc, char **argv, struct Trapframe *tf);
int mon_start(int argc, char **argv, struct Trapframe *tf);
int mon_stop(int argc, char **argv, struct Trapframe *tf);
int mon_frequency(int argc, char **argv, struct Trapframe *tf);
int mon_memory(int argc, char **argv, struct Trapframe *tf);
int mon_pagetable(int argc, char **argv, struct Trapframe *tf);
int mon_virt(int argc, char **argv, struct Trapframe *tf);

int mon_e1000_recv(int argc, char **argv, struct Trapframe *tf);
int mon_e1000_tran(int argc, char **argv, struct Trapframe *tf);
int mon_http_test(int argc, char **argv, struct Trapframe *tf);

struct Command {
    const char *name;
    const char *desc;
    /* return -1 to force monitor to exit */
    int (*func)(int argc, char **argv, struct Trapframe *tf);
};

static struct Command commands[] = {
        {"help", "Display this list of commands", mon_help},
        {"kerninfo", "Display information about the kernel", mon_kerninfo},
        {"echo", "Display input text", mon_echo},
        {"backtrace", "Print stack backtrace", mon_backtrace},
        {"dumpcmos", "Display CMOS contents", mon_dumpcmos},
        {"timer_start", "Start timer", mon_start},
        {"timer_stop", "Stop timer", mon_stop},
        {"timer_freq", "Get timer frequency", mon_frequency},
        {"memory", "Display allocated memory pages", mon_memory},
        {"pagetable", "Display current page table", mon_pagetable},
        {"virt", "Display virtual memory tree", mon_virt},
        {"e1000_recv", "Test e1000 receive", mon_e1000_recv},
        {"e1000_tran", "Test e1000 transmit", mon_e1000_tran},
        {"http_test", "Test http parsing", mon_http_test},
        {"exit", "Normal exit from monitor", mon_exit},
};

#define NCOMMANDS (sizeof(commands) / sizeof(commands[0]))

/* Implementations of basic kernel monitor commands */

int
mon_help(int argc, char **argv, struct Trapframe *tf) {
    for (size_t i = 0; i < NCOMMANDS; i++)
        cprintf("%s - %s\n", commands[i].name, commands[i].desc);
    return 0;
}

int
mon_kerninfo(int argc, char **argv, struct Trapframe *tf) {
    extern char _head64[], entry[], etext[], edata[], end[];

    cprintf("Special kernel symbols:\n");
    cprintf("  _head64 %16lx (virt)  %16lx (phys)\n", (unsigned long)_head64, (unsigned long)_head64);
    cprintf("  entry   %16lx (virt)  %16lx (phys)\n", (unsigned long)entry, (unsigned long)entry - KERN_BASE_ADDR);
    cprintf("  etext   %16lx (virt)  %16lx (phys)\n", (unsigned long)etext, (unsigned long)etext - KERN_BASE_ADDR);
    cprintf("  edata   %16lx (virt)  %16lx (phys)\n", (unsigned long)edata, (unsigned long)edata - KERN_BASE_ADDR);
    cprintf("  end     %16lx (virt)  %16lx (phys)\n", (unsigned long)end, (unsigned long)end - KERN_BASE_ADDR);
    cprintf("Kernel executable memory footprint: %luKB\n", (unsigned long)ROUNDUP(end - entry, 1024) / 1024);
    return 0;
}

int
mon_backtrace(int argc, char **argv, struct Trapframe *tf) {
    cprintf("Stack backtrace:\n");

    uint64_t rbp = tf->tf_regs.reg_rbp;
    if (tf == NULL) {
        rbp = read_rbp();
    }

    struct Ripdebuginfo info;
    while (rbp != 0) {
        // rip is placed before the start of frame
        uint64_t rip = *(uint64_t*)(rbp + 8);
        cprintf("  rbp %016lx  rip %016lx\n", rbp, rip);

        debuginfo_rip(rip, &info);

        cprintf("    %s:%d: %s+%lu\n",
                info.rip_file,
                info.rip_line,
                info.rip_fn_name,
                (rip - info.rip_fn_addr));

        // load the saved start of previous frame
        rbp = *(uint64_t*)rbp;
    }

    return 0;
}

int
mon_echo(int argc, char **argv, struct Trapframe *tf) {
    for (int i = 1; i < argc; i++)
    {
        if (i + 1 == argc)
            cprintf("%s\n", argv[i]);
        else
            cprintf("%s ", argv[i]);
    }
    return 0;
}

/* Implement timer_start (mon_start), timer_stop (mon_stop), timer_freq (mon_frequency) commands. */
// LAB 5: Your code here:

int
mon_start(int argc, char **argv, struct Trapframe *tf) {
    if (argc != 2) {
        return 1;
    }
    timer_start(argv[1]);
    return 0;
}

int
mon_stop(int argc, char **argv, struct Trapframe *tf) {
    if (argc != 1) {
        return 1;
    }
    timer_stop();
    return 0;
}

int
mon_frequency(int argc, char **argv, struct Trapframe *tf) {
    if (argc != 2) {
        return 1;
    }
    timer_cpu_frequency(argv[1]);
    return 0;
}

// LAB 6: Your code here
/* Implement memory (mon_memory) commands. */
int
mon_memory(int argc, char **argv, struct Trapframe *tf) {
    dump_memory_lists();
    return 0;
}

/* Implement mon_pagetable() and mon_virt()
 * (using dump_virtual_tree(), dump_page_table())*/
int
mon_pagetable(int argc, char **argv, struct Trapframe *tf) {
    // LAB 7: Your code here
    dump_page_table(KADDR(rcr3()));
    return 0;
}

int
mon_virt(int argc, char **argv, struct Trapframe *tf) {
    // LAB 7: Your code here
    dump_virtual_tree(current_space->root, MAX_CLASS);
    return 0;
}

// LAB 4: Your code here
int
mon_dumpcmos(int argc, char **argv, struct Trapframe *tf) {
    // Dump CMOS memory in the following format:
    // 00: 00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF
    // 10: 00 ..
    // Make sure you understand the values read.
    // Hint: Use cmos_read8()/cmos_write8() functions.
    // LAB 4: Your code here
    uint8_t res;
    for (int ptr = 0; ptr < CMOS_SIZE; ptr++)
    {
        outb(CMOS_CMD, ptr);
        res = inb(CMOS_DATA);

        if (ptr % 16 == 0)
        {
            if (ptr != 0)
                cprintf("\n");
            
            cprintf("%02x: ", ptr);
        }
        cprintf("%02x ", res);
    }
    cprintf("\n");

    return 0;
}


int
mon_e1000_recv(int argc, char **argv, struct Trapframe *tf) {
    char buf[1000];
    int len = e1000_receive(buf);
    cprintf("received len: %d\n", len);
    cprintf("received packet: ");
    for (int i = 0; i < len; i++) {
        cprintf("%x ", buf[i] & 0xff);
    }
    cprintf("\n");
    return 0;
}

static inline bool
is_time_over(uint64_t *a, uint64_t *b, uint64_t *timeout) {
    static uint64_t cpu_frequency;
    if (!cpu_frequency) {
        cpu_frequency = hpet_cpu_frequency();
    }

    asm("pause");
    *b = read_tsc();

    return (*b - *a < *timeout * cpu_frequency) ? false : true;
}

int
mon_eth_recv(struct Trapframe *tf) {

    int len = 0;
    uint64_t tsc0 = read_tsc(), tsc1 = 0;
    uint64_t timeout = 30;
    char buf[1000];

    do {
        memset(buf, 0, sizeof(buf));

        e1000_listen();
        len = eth_recv(buf);
        if (trace_packets && len >= 0) {
            cprintf("received len: %d\n", len);
            if (len > 0) {
                cprintf("received packet: ");
                for (int i = 0; i < len; i++) {
                    cprintf("%x ", buf[i] & 0xff);
                }
                cprintf("\n");
            }
        } else {
            cprintf("received status: %s%s\n", (len >= 0) ? "OK" : "ERROR", (len == 0) ? " EMPTY" : " ");
        }
        cprintf("\n");

    } while (!is_time_over(&tsc0, &tsc1, &timeout));

    sched_yield();
}

int
mon_e1000_tran(int argc, char **argv, struct Trapframe *tf) {
    for (int i = 0; i < 70; i++) {
        char buf[] = "Hello\n";
        udp_send(buf, sizeof(buf));
    }
    return 0;
}

int
mon_http_test(int argc, char **argv, struct Trapframe *tf) {
    char reply[1024] = {};
    size_t reply_len = 0;

    char *buf1 = "Hello, HTTP!";
    cprintf("%s\n", http_parse(buf1, strlen(buf1), reply, &reply_len) ? "FAULT" : "SUCCESS");
    udp_send(reply, reply_len);

    char *buf2 = "POST /hello.world HTTP/1.1";
    cprintf("%s\n", http_parse(buf2, strlen(buf2), reply, &reply_len) ? "FAULT" : "SUCCESS");
    tcp_send(NULL, (void *)reply, reply_len);

    char *buf3 = "GET /hello.world HTTP/2";
    cprintf("%s\n", http_parse(buf3, strlen(buf3), reply, &reply_len) ? "FAULT" : "SUCCESS");
    udp_send(reply, reply_len);

    char *buf4 = "GET /hello.world HTTP/1.1";
    cprintf("%s\n", http_parse(buf4, strlen(buf4), reply, &reply_len) ? "FAULT" : "SUCCESS");
    udp_send(reply, reply_len);
    return 0;
}

int
mon_exit(int argc, char **argv, struct Trapframe *tf) {
    cprintf("\nBye !\n\n");
    return -1;
}

/* Kernel monitor command interpreter */

static int
runcmd(char *buf, struct Trapframe *tf) {
    int argc = 0;
    char *argv[MAXARGS];

    argv[0] = NULL;

    /* Parse the command buffer into whitespace-separated arguments */
    for (;;) {
        /* gobble whitespace */
        while (*buf && strchr(WHITESPACE, *buf)) *buf++ = 0;
        if (!*buf) break;

        /* save and scan past next arg */
        if (argc == MAXARGS - 1) {
            cprintf("Too many arguments (max %d)\n", MAXARGS);
            return 0;
        }
        argv[argc++] = buf;
        while (*buf && !strchr(WHITESPACE, *buf)) buf++;
    }
    argv[argc] = NULL;

    /* Lookup and invoke the command */
    if (!argc) return 0;
    for (size_t i = 0; i < NCOMMANDS; i++) {
        if (strcmp(argv[0], commands[i].name) == 0)
            return commands[i].func(argc, argv, tf);
    }

    cprintf("Unknown command '%s'\n", argv[0]);
    return 0;
}

void
monitor(struct Trapframe *tf) {

    cprintf("Welcome to the JOS kernel monitor!\n");
    cprintf("Type 'help' for a list of commands.\n");

    // if (tf) print_trapframe(tf);

    char *buf;
    do buf = readline("K> ");
    while (runcmd(buf, tf) >= 0);
}
