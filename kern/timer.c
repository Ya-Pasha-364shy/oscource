#include <inc/types.h>
#include <inc/assert.h>
#include <inc/string.h>
#include <inc/memlayout.h>
#include <inc/stdio.h>
#include <inc/x86.h>
#include <inc/uefi.h>
#include <kern/timer.h>
#include <kern/kclock.h>
#include <kern/picirq.h>
#include <kern/trap.h>

#define kilo      (1000ULL)
#define Mega      (kilo * kilo)
#define Giga      (kilo * Mega)
#define Tera      (kilo * Giga)
#define Peta      (kilo * Tera)
#define ULONG_MAX ~0UL

#if LAB <= 6
/* Early variant of memory mapping that does 1:1 aligned area mapping
 * in 2MB pages. You will need to reimplement this code with proper
 * virtual memory mapping in the future. */
void *
mmio_map_region(physaddr_t pa, size_t size) {
    void map_addr_early_boot(uintptr_t addr, uintptr_t addr_phys, size_t sz);
    const physaddr_t base_2mb = 0x200000;
    uintptr_t org = pa;
    size += pa & (base_2mb - 1);
    size += (base_2mb - 1);
    pa &= ~(base_2mb - 1);
    size &= ~(base_2mb - 1);
    map_addr_early_boot(pa, pa, size);
    return (void *)org;
}
void *
mmio_remap_last_region(physaddr_t pa, void *addr, size_t oldsz, size_t newsz) {
    return mmio_map_region(pa, newsz);
}
#endif

struct Timer timertab[MAX_TIMERS];
struct Timer *timer_for_schedule;

struct Timer timer_hpet0 = {
        .timer_name = "hpet0",
        .timer_init = hpet_init,
        .get_cpu_freq = hpet_cpu_frequency,
        .enable_interrupts = hpet_enable_interrupts_tim0,
        .handle_interrupts = hpet_handle_interrupts_tim0,
};

struct Timer timer_hpet1 = {
        .timer_name = "hpet1",
        .timer_init = hpet_init,
        .get_cpu_freq = hpet_cpu_frequency,
        .enable_interrupts = hpet_enable_interrupts_tim1,
        .handle_interrupts = hpet_handle_interrupts_tim1,
};

struct Timer timer_acpipm = {
        .timer_name = "pm",
        .timer_init = acpi_enable,
        .get_cpu_freq = pmtimer_cpu_frequency,
};

void
acpi_enable(void) {
    FADT *fadt = get_fadt();
    outb(fadt->SMI_CommandPort, fadt->AcpiEnable);
    while ((inw(fadt->PM1aControlBlock) & 1) == 0) /* nothing */
        ;
}

static void *
acpi_find_table(const char *sign) {
    /*
     * This function performs lookup of ACPI table by its signature
     * and returns valid pointer to the table mapped somewhere.
     *
     * It is a good idea to checksum tables before using them.
     *
     * HINT: Use mmio_map_region/mmio_remap_last_region
     * before accessing table addresses
     * (Why mmio_remap_last_region is requrired?)
     * HINT: RSDP address is stored in uefi_lp->ACPIRoot
     * HINT: You may want to distunguish RSDT/XSDT
     */
    // LAB 5: Your code here:

    // MMIO - это метод выполнения операций ввода/вывода между
    // перефирийными устройствами и центральным процессором.
    // Каждое устройство ввода-вывода либо контролирует адресную шину ЦП,
    // либо реагирует на любой доступ ЦП к адресу, назначенному этому устройству.
    // В данном случае периф. устройства - это таймеры. 

    static RSDT *rsdt;
    static size_t rsdt_len;
    static size_t rsdt_entsz;
    uint64_t rsdt_pa;
    size_t i = 0;
    uint8_t err = 0;
    uint64_t fadt_pa = 0;
    if (!rsdt) {
        if (!uefi_lp->ACPIRoot) {
            panic("No rsdp\n");
        }
        // достаём rsdp, если не нашлось (максимум выполнится 1 раз)
        RSDP *rsdp = mmio_map_region(uefi_lp->ACPIRoot, sizeof(RSDP));
        if (!rsdp->Revision) {
            // проверка чексум
            for (i = 0; i < offsetof(RSDP, Length); ++i) {
                err += ((uint8_t *)rsdp)[i];
            }
            if (err) {
                panic("Invalid RSD table detected\n");
            }
            // сохраняем значение адреса RSDP
            // размапленое - физическое
            rsdt_pa = rsdp->RsdtAddress;
            rsdt_entsz = 4;
        } else { // The ACPI Version can be detected using the Revision field in the RSDP.
                 // If this field contains 0, then ACPI Version 1.0 is used. For subsequent
                 // versions (ACPI version 2.0 to 6.1), the value 2 is used
            for (i = 0; i < rsdp->Length; ++i) {
                err += ((uint8_t *)rsdp)[i];
            }
            if (err) {
                panic("Invalid XSDT table detected\n");
            }
            // физический адрес XSDT таблицы
            rsdt_pa = rsdp->XsdtAddress;
            rsdt_entsz = 8;
        }
        // смотрим в страницы памяти по 2МБ, находим место, где лежит RSDT 
        rsdt = mmio_map_region(rsdt_pa, sizeof(RSDT));
        // в зависимости от ревизии, может потребоваться больше байт
        rsdt = mmio_remap_last_region(rsdt_pa, rsdt, sizeof(RSDP), rsdt->h.Length);
        for (i = 0; i < rsdt->h.Length; ++i) {
            err += ((uint8_t *)rsdt)[i];
        }
        if (err) {
            panic("Invalid RSDP\n");
        }
        // корректировки длины RSDT в зависимости от ревизии.
        if (!rsdp->Revision) {
            if (strncmp(rsdt->h.Signature, "RSDT", 4)) {
                panic("Invalid RSDT\n");
            }
            rsdt_len = (rsdt->h.Length - sizeof(RSDT)) / 4;
        } else {
            if (strncmp(rsdt->h.Signature, "XSDT", 4)) {
                panic("Invalid XSDT\n");
            }
            rsdt_len = (rsdt->h.Length - sizeof(RSDT)) / 8;
        }
    }
    ACPISDTHeader *head = NULL;
    for (i = 0; i < rsdt_len; ++i) {
        // обходим всю таблицу системных дескрипторов до тех пор,
        // пока не найдём нужный нам регистр, имеющий некоторый дескриптор.
        memcpy(&fadt_pa, (uint8_t *)rsdt->PointerToOtherSDT + i * rsdt_entsz, rsdt_entsz);
        head = mmio_map_region(fadt_pa, sizeof(ACPISDTHeader));
        head = mmio_remap_last_region(fadt_pa, head, sizeof(ACPISDTHeader), rsdt->h.Length);
        for (size_t i = 0; i < head->Length; i++) {
            err += ((uint8_t *)head)[i];
        }
        if (err) {
            panic("Invalid ACPI table '%.4s'", head->Signature);
        }
        if (!strncmp(head->Signature, sign, 4)) {
            return head;
        }
    }
    return NULL;
}

/* Obtain and map FADT ACPI table address. */
FADT *
get_fadt(void) {
    // LAB 5: Your code here
    // (use acpi_find_table)
    // HINT: ACPI table signatures are
    //       not always as their names
    // "FADT" - signature is “FACP”.
    FADT *fadt_ptr = acpi_find_table("FACP");
    return fadt_ptr ? fadt_ptr : NULL;
}

/* Obtain and map RSDP ACPI table address. */
HPET *
get_hpet(void) {
    // LAB 5: Your code here
    // (use acpi_find_table)
    HPET *hpet_ptr = acpi_find_table("HPET");
    return hpet_ptr ? hpet_ptr : NULL;
}

/* Getting physical HPET timer address from its table. */
HPETRegister *
hpet_register(void) {
    HPET *hpet_timer = get_hpet();
    if (!hpet_timer->address.address) panic("hpet is unavailable\n");

    uintptr_t paddr = hpet_timer->address.address;
    return mmio_map_region(paddr, sizeof(HPETRegister));
}

/* Debug HPET timer state. */
void
hpet_print_struct(void) {
    HPET *hpet = get_hpet();
    assert(hpet != NULL);
    cprintf("signature = %s\n", (hpet->h).Signature);
    cprintf("length = %08x\n", (hpet->h).Length);
    cprintf("revision = %08x\n", (hpet->h).Revision);
    cprintf("checksum = %08x\n", (hpet->h).Checksum);

    cprintf("oem_revision = %08x\n", (hpet->h).OEMRevision);
    cprintf("creator_id = %08x\n", (hpet->h).CreatorID);
    cprintf("creator_revision = %08x\n", (hpet->h).CreatorRevision);

    cprintf("hardware_rev_id = %08x\n", hpet->hardware_rev_id);
    cprintf("comparator_count = %08x\n", hpet->comparator_count);
    cprintf("counter_size = %08x\n", hpet->counter_size);
    cprintf("reserved = %08x\n", hpet->reserved);
    cprintf("legacy_replacement = %08x\n", hpet->legacy_replacement);
    cprintf("pci_vendor_id = %08x\n", hpet->pci_vendor_id);
    cprintf("hpet_number = %08x\n", hpet->hpet_number);
    cprintf("minimum_tick = %08x\n", hpet->minimum_tick);

    cprintf("address_structure:\n");
    cprintf("address_space_id = %08x\n", (hpet->address).address_space_id);
    cprintf("register_bit_width = %08x\n", (hpet->address).register_bit_width);
    cprintf("register_bit_offset = %08x\n", (hpet->address).register_bit_offset);
    cprintf("address = %08lx\n", (unsigned long)(hpet->address).address);
}

static volatile HPETRegister *hpetReg;
/* HPET timer period (in femtoseconds) */
static uint64_t hpetFemto = 0;
/* HPET timer frequency */
static uint64_t hpetFreq = 0;

/* HPET timer initialisation */
void
hpet_init() {
    if (hpetReg == NULL) {
        nmi_disable();
        hpetReg = hpet_register();
        uint64_t cap = hpetReg->GCAP_ID;
        hpetFemto = (uintptr_t)(cap >> 32);
        if (!(cap & HPET_LEG_RT_CAP)) panic("HPET has no LegacyReplacement mode");

        // cprintf("hpetFemto = %llu\n", hpetFemto);
        hpetFreq = (1 * Peta) / hpetFemto;
        // cprintf("HPET: Frequency = %d.%03dMHz\n", (uintptr_t)(hpetFreq / Mega), (uintptr_t)(hpetFreq % Mega));
        /* Enable ENABLE_CNF bit to enable timers */
        hpetReg->GEN_CONF |= HPET_ENABLE_CNF;
        nmi_enable();
    }
}

/* HPET register contents debugging. */
void
hpet_print_reg(void) {
    cprintf("GCAP_ID = %016lx\n", (unsigned long)hpetReg->GCAP_ID);
    cprintf("GEN_CONF = %016lx\n", (unsigned long)hpetReg->GEN_CONF);
    cprintf("GINTR_STA = %016lx\n", (unsigned long)hpetReg->GINTR_STA);
    cprintf("MAIN_CNT = %016lx\n", (unsigned long)hpetReg->MAIN_CNT);
    cprintf("TIM0_CONF = %016lx\n", (unsigned long)hpetReg->TIM0_CONF);
    cprintf("TIM0_COMP = %016lx\n", (unsigned long)hpetReg->TIM0_COMP);
    cprintf("TIM0_FSB = %016lx\n", (unsigned long)hpetReg->TIM0_FSB);
    cprintf("TIM1_CONF = %016lx\n", (unsigned long)hpetReg->TIM1_CONF);
    cprintf("TIM1_COMP = %016lx\n", (unsigned long)hpetReg->TIM1_COMP);
    cprintf("TIM1_FSB = %016lx\n", (unsigned long)hpetReg->TIM1_FSB);
    cprintf("TIM2_CONF = %016lx\n", (unsigned long)hpetReg->TIM2_CONF);
    cprintf("TIM2_COMP = %016lx\n", (unsigned long)hpetReg->TIM2_COMP);
    cprintf("TIM2_FSB = %016lx\n", (unsigned long)hpetReg->TIM2_FSB);
}

/* HPET main timer counter value. */
uint64_t
hpet_get_main_cnt(void) {
    return hpetReg->MAIN_CNT;
}

/* - Configure HPET timer 0 to trigger every 0.5 seconds on IRQ_TIMER line
 * - Configure HPET timer 1 to trigger every 1.5 seconds on IRQ_CLOCK line
 *
 * HINT To be able to use HPET as PIT replacement consult
 *      LegacyReplacement functionality in HPET spec.
 * HINT Don't forget to unmask interrupt in PIC */
void
hpet_enable_interrupts_tim0(void) {
    // LAB 5: Your code here
    // включаем "замену устаревших версий". Легаси-часть
    hpetReg->GEN_CONF |= HPET_LEG_RT_CNF;
    hpetReg->TIM0_CONF = (IRQ_TIMER << 9);
    // включаем 2-ой бит, 3-ий бит и 6-ой - тригер на прерывания, периодичность,
    // возможность прямого установления периода соотвественно.
    hpetReg->TIM0_CONF |= HPET_TN_TYPE_CNF | HPET_TN_INT_ENB_CNF | HPET_TN_VAL_SET_CNF;
    // устанавливаем значение, чтобы триггериться каждые 0.5 секунд.
    // hpetReg->TIM0_COMP = hpet_get_main_cnt() + Peta / hpetFemto / 2;
    hpetReg->TIM0_COMP = Peta / hpetFemto / 2;
    // размаскирование прерываний на линии IRQ_TIMER
    pic_irq_unmask(IRQ_TIMER);
}

void
hpet_enable_interrupts_tim1(void) {
    // LAB 5: Your code here
    hpetReg->GEN_CONF |= HPET_LEG_RT_CNF;
    hpetReg->TIM1_CONF = (IRQ_CLOCK << 9);
    hpetReg->TIM1_CONF |= HPET_TN_TYPE_CNF | HPET_TN_INT_ENB_CNF | HPET_TN_VAL_SET_CNF;
    // hpetReg->TIM1_COMP = hpet_get_main_cnt() + Peta / hpetFemto / 2 * 3;
    // тригерримся каждые 1,5 секунды
    hpetReg->TIM1_COMP = Peta / hpetFemto / 2 * 3;
    // размаскирование прерываний на линии IRQ_CLOCK
    pic_irq_unmask(IRQ_CLOCK);
}

void
hpet_handle_interrupts_tim0(void) {
    pic_send_eoi(IRQ_TIMER);
}

void
hpet_handle_interrupts_tim1(void) {
    pic_send_eoi(IRQ_CLOCK);
}

/* Calculate CPU frequency in Hz with the help with HPET timer.
 * HINT Use hpet_get_main_cnt function and do not forget about
 * about pause instruction. */
uint64_t
hpet_cpu_frequency(void) {
    // LAB 5: Your code here
    uint64_t cpu_freq;
    uint64_t first = hpet_get_main_cnt();
    uint64_t first_tsc = read_tsc();
    uint64_t next = first;
    uint64_t eps = hpetFreq / 10;

    while (next - first < eps) {
        next = hpet_get_main_cnt();
    }
    uint64_t next_tsc = read_tsc();
    cpu_freq = (next_tsc - first_tsc) * 10;
    return cpu_freq;
}

uint32_t
pmtimer_get_timeval(void) {
    FADT *fadt = get_fadt();
    return inl(fadt->PMTimerBlock);
}

/* Calculate CPU frequency in Hz with the help with ACPI PowerManagement timer.
 * HINT Use pmtimer_get_timeval function and do not forget that ACPI PM timer
 *      can be 24-bit or 32-bit. */
uint64_t
pmtimer_cpu_frequency(void) {
    // LAB 5: Your code here
    uint64_t cpu_freq;
    uint32_t first = pmtimer_get_timeval();
    uint64_t first_tsc = read_tsc();

    uint32_t next = first;
    uint64_t d = 0;
    uint64_t eps = PM_FREQ / 10;
    while (d < eps) {
        next = pmtimer_get_timeval();
        // 24-bit ACPI PM timer
        if (first - next <= 0xFFFFFF) {
            d = next - first + 0xFFFFFF;
        } else if (first - next > 0) {
            d = next - first + 0xFFFFFFFF;
        } else {
            d = next - first;
        }
    }
    uint64_t next_tsc = read_tsc();
    cpu_freq = (next_tsc - first_tsc) * 10;
    return cpu_freq;
}
