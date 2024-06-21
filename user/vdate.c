#include <inc/types.h>
#include <inc/time.h>
#include <inc/stdio.h>
#include <inc/lib.h>

void
umain(int argc, char **argv) {
    char time[20];
    /**
     * Виртуальный системный вызов времени vdate.
     * Его реализовывали поверх волатайл и интеджер.
     * Объясните, какой ордеринг памяти будет применим с
     * атомиками без волатайла.
     * Собственно, надо переписать и объяснить, почему работает
    */
    int now = vsys_gettime();
    struct tm tnow;

    mktime(now, &tnow);

    snprint_datetime(time, 20, &tnow);
    cprintf("VDATE: %s\n", time);
}