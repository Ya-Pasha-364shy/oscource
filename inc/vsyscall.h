#ifndef JOS_INC_VSYSCALL_H
#define JOS_INC_VSYSCALL_H

#include <stdatomic.h>

/* system call numbers */
enum {
    VSYS_gettime,
    NVSYSCALLS
};

#endif /* !JOS_INC_VSYSCALL_H */
