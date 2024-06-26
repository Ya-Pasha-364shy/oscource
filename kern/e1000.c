#include <kern/e1000.h>
#include <kern/pci.h>
#include <kern/pmap.h>
#include <kern/timer.h>
#include <inc/types.h>
#include <inc/string.h>
#include <inc/error.h>
#include <kern/traceopt.h>

// Base mmio address
volatile uint32_t *phy_mmio_addr;
#define E1000_REG(offset) (phy_mmio_addr[offset >> 2])

struct tx_desc tx_desc_table[E1000_NU_DESC] __attribute__((aligned (PAGE_SIZE)));
struct rx_desc rx_desc_table[E1000_NU_DESC] __attribute__((aligned (PAGE_SIZE)));
char tx_buf[E1000_NU_DESC][E1000_BUFFER_SIZE] __attribute__((aligned (PAGE_SIZE)));
char rx_buf[E1000_NU_DESC][E1000_BUFFER_SIZE] __attribute__((aligned (PAGE_SIZE)));

static void
dump_tx_desc(uint32_t tx_idx) {
    cprintf("TX Desc %08x:\n", tx_idx);
    cprintf("\tbuf_addr: %08lx\n", tx_desc_table[tx_idx].buf_addr);
    cprintf("\tlength:   %08x\n", tx_desc_table[tx_idx].length);
    cprintf("\tstatus:   %08x\n", tx_desc_table[tx_idx].status);
    cprintf("\n");
}

static void
dump_rx_desc(uint32_t rx_idx) {
    cprintf("RX Desc %08x:\n", rx_idx);
    cprintf("\tbuf_addr: %08lx\n", rx_desc_table[rx_idx].buf_addr);
    cprintf("\tlength:   %08x\n", rx_desc_table[rx_idx].length);
    cprintf("\tchecksum: %08x\n", rx_desc_table[rx_idx].checksum);
    cprintf("\tstatus:   %08x\n", rx_desc_table[rx_idx].status);
    cprintf("\terrors:   %08x\n", rx_desc_table[rx_idx].errors);
    cprintf("\n");
}

static inline bool
is_time_over(uint64_t *a, uint64_t *b, double *timeout) {
    static uint64_t cpu_frequency;
    if (!cpu_frequency) {
        cpu_frequency = hpet_cpu_frequency();
    }

    asm("pause");
    *b = read_tsc();

    return (*b - *a < (uint64_t)(*timeout * cpu_frequency)) ? false : true;
}

/**
 * Инициализирует очереди отправки для E1000
 */
static void
e1000_transmit_init() {
    // Set TX Base Address Low
    E1000_REG(E1000_TDBAL) = (uint32_t)PADDR(tx_desc_table);

    // Set TX Base Address High
    E1000_REG(E1000_TDBAH) = 0;

    // Set TX Length
    E1000_REG(E1000_TDLEN) = sizeof(tx_desc_table);

    // Set TX Head
    E1000_REG(E1000_TDH) = 0;

    // Set TX Tail
    E1000_REG(E1000_TDT) = 0;

    // Set TX Control Register
    E1000_REG(E1000_TCTL) = E1000_TCTL_EN |
                            E1000_TCTL_PSP |
                            (E1000_TCTL_CT & (0x10 << 4)) |
                            (E1000_TCTL_COLD & (0x40 << 12));

    // Set TX Inter-packet Gap
    E1000_REG(E1000_TIPG) = 0x60200a;

    // Set TX Descriptors
    for (int i = 0; i < E1000_NU_DESC; i++) {
        // Set TX status as Descriptor Done
        tx_desc_table[i].status |= E1000_TXD_STAT_DD;
        // Set TX buffer address
        tx_desc_table[i].buf_addr = PADDR(tx_buf[i]);
        // Set TX cmd
        tx_desc_table[i].cmd = E1000_TXD_CMD_RS | E1000_TXD_CMD_EOP;
    }

    if (trace_packets) dump_tx_desc(0);
}

/**
 * Инициализирует очереди принятия пакетов на E1000
 */
static void
e1000_receive_init() {
    // Set RX Base Address Low
    E1000_REG(E1000_RDBAL) = PADDR(rx_desc_table);

    // Set RX Base Address High
    E1000_REG(E1000_RDBAH) = 0;

    // Set RX Length
    E1000_REG(E1000_RDLEN) = sizeof(rx_desc_table);

    // Set RX Head
    E1000_REG(E1000_RDH) = 0;

    // Set RX Tail
    E1000_REG(E1000_RDT) = E1000_NU_DESC - 1;

    // Set RX Control Register
    E1000_REG(E1000_RCTL) = E1000_RCTL_EN | E1000_RCTL_BAM | E1000_RCTL_CRC;

    // Set RX Descriptors
    for (int i = 0; i < E1000_NU_DESC; i++) {
        // Clear RX status Descriptor Done
        rx_desc_table[i].status &= ~E1000_RXD_STAT_DD;
        // Set RX buffer address
        rx_desc_table[i].buf_addr = PADDR(rx_buf[i]);
    }

    if (trace_packets) dump_rx_desc(0);
}

/**
 * Функция сопоставления pci-устройства и e1000.
 * Нужна для мапинга регистров устройства (сетевой карты) в память ядра.
 */
int
e1000_attach(struct pci_func *pciFunction) {
    // Get phy_mmio address and size
    pci_get_bar_info(pciFunction);

    // Map phy_mmio
    phy_mmio_addr = mmio_map_region(pciFunction->reg_base[0], pciFunction->reg_size[0]);

    // We don't have to set RX Address Low and High as
    uint32_t num1 = E1000_REG(E1000_RAL);
    uint32_t num2 = E1000_REG(E1000_RAH);
    cprintf("MAC - %02x:%02x:%02x:%02x:%02x:%02x\n", num1 & 0xff, (num1 >> 8) & 0xff, (num1 >> 16) & 0xff, (num1 >> 24) & 0xff, num2 & 0xff, (num2 >> 8) & 0xff);

    // Set RX Address Low and High as:
    // MAC address 10:00:00:11:11:11
    // because it's already done in qemu options
    // E1000_REG(E1000_RAL) = 0x10000011;
    // *(uint16_t *)&E1000_REG(E1000_RAH) = 0x1111;

    // Set Multicast Table Array
    E1000_REG(E1000_MTA) = 0;

    e1000_transmit_init();
    e1000_receive_init();

    cprintf("E1000 status: %08x\n", E1000_REG(E1000_DEVICE_STATUS));

    return 1;
}

/**
 * Помещаем в очередь отправки e1000 пакет размером len
 * Если очередь отправки полна - возвращаем отрицательное число
 */
int
e1000_transmit(const char* buf, uint16_t len) {
    // Trunk packet length
    len = len > E1000_BUFFER_SIZE ? E1000_BUFFER_SIZE : len;

    // Tail TX Descriptor Index
    uint32_t tail_tx = E1000_REG(E1000_TDT);

    // Check status of tail TX Descriptor
    if (!(tx_desc_table[tail_tx].status & E1000_TXD_STAT_DD)) {
        cprintf("\nE1000 transmit queue is full\n");
        return -1;
    }

    // Move data to buffer
    memmove(tx_buf[tail_tx], buf, len);

    // Set packet length
    tx_desc_table[tail_tx].length = len;

    // Clear TX status Descriptor Done
    tx_desc_table[tail_tx].status &= ~E1000_TXD_STAT_DD;

    if (trace_packets) dump_tx_desc(tail_tx);

    // Point to next TX Descriptor
    E1000_REG(E1000_TDT) = (tail_tx + 1) % E1000_NU_DESC;

    return 0;
}

/**
 * Ожидаем освобождение слота под пакет в какой-либо очереди отправки на сетевой карте.
 * Если место есть, возвращаем индекс очереди, что освободилась.
 */
int
e1000_timeout_transmit(double timeout) {
    uint64_t tsc0 = read_tsc(), tsc1 = 0;
    do {
        // Tail TX Descriptor Index
        uint32_t tail_tx = E1000_REG(E1000_TDT);
        tail_tx = (tail_tx + 1) % E1000_NU_DESC;

        // Check status of tail TX Descriptor
        if (rx_desc_table[tail_tx].status & E1000_TXD_STAT_DD) {
            return 0;
        }
    } while (!is_time_over(&tsc0, &tsc1, &timeout));

    // if (trace_packets) cprintf("transmit TIMEOUT! (%d ms)\n", (uint32_t)(timeout * 1000));
    return -1;
}

/**
 * Ждём бесконечно события, пока на карте не появятся данные.
 */
void
e1000_listen(void) {
    while (1) {
        uint32_t tail_rx = E1000_REG(E1000_RDT);
        tail_rx = (tail_rx + 1) % E1000_NU_DESC;

        // Check status of tail RX Descriptor
        if (rx_desc_table[tail_rx].status & E1000_RXD_STAT_DD) {
            break;
        }
    }
}

/**
 * Ждём в течение времени timeout события появления новых данных в какой-либо очереди.
 * Если появились - вернуть 0, иначе = -1
 */
int
e1000_timeout_listen(double timeout) {
    uint64_t tsc0 = read_tsc(), tsc1 = 0;

    do {
        uint32_t tail_rx = E1000_REG(E1000_RDT);
        tail_rx = (tail_rx + 1) % E1000_NU_DESC;

        // Check status of tail RX Descriptor
        if (rx_desc_table[tail_rx].status & E1000_RXD_STAT_DD) {
            return 0;
        }
    } while (!is_time_over(&tsc0, &tsc1, &timeout));

    // if (trace_packets) cprintf("recieve TIMEOUT! (%d ms)\n", (uint32_t)(timeout * 1000));
    return -1;
}

/**
 * Читаем из входящей очереди и записываем последний прочитанный элемент
 * в память, на которую указывает указатель buffer.
 */
int
e1000_receive(char *buffer) {
    // Tail RX Descriptor Index
    uint32_t tail_rx = E1000_REG(E1000_RDT);
    tail_rx = (tail_rx + 1) % E1000_NU_DESC;

    if (trace_packets) dump_rx_desc(tail_rx);

    // Check status of tail RX Descriptor
    if (!(rx_desc_table[tail_rx].status & E1000_RXD_STAT_DD)) {
        cprintf("\nE1000 receive queue is empty\n");
        return 0;
    }
    if (!(rx_desc_table[tail_rx].status & E1000_RXD_STAT_EOP)){
        cprintf("\nE1000 receive status is not EOP\n");
        return 0;
    }

    // Clear RX status Descriptor Done
    rx_desc_table[tail_rx].status &= ~E1000_RXD_STAT_DD;

    // Get packet length
    int len = (int)rx_desc_table[tail_rx].length;

    // Get data from buffer
    memmove(buffer, rx_buf[tail_rx], len);

    // Point to next RX Descriptor
    E1000_REG(E1000_RDT) = tail_rx;

    return len;
}