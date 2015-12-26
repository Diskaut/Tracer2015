#include <asm/unistd.h>

/* Код, который мы будем внедрять в жертву. */
.text

/* Это - две рукоятки, чтобы было удобно этот код зачерпнуть из injector.c без лишних затруднений */
.global PAYLOAD_AMD64
.global PAYLOAD_AMD64_END

PAYLOAD_AMD64:
/* Ставим жертву на паузу перед своим выполнением, чтобы мы могли сохранить регистры жертвы */
    int $3
/* Выводим "I am inside now!\n" на stdout */
    jmp payload_end
payload: .ascii "I am inside now!\n"
payload_end:
    movq $__NR_getpid,%rax
    syscall
    pushq %rax
    movq $__NR_mmap,%rax
    movq $0x10000,%rdi
    movq $14,%rsi
    movq $0x5,%rdx
    movq $0x12,%r10
    movq $512,%r8
    movq $0,%r9
    syscall
    pushq %rax
    movq $1,%rdi
/* Нам будет сложно заставить работать инъекцию, зависящую от абсолютных адресов, используем адресацию относительно rip*/
    leaq payload(%rip),%rsi
    leaq payload_end(%rip),%rdx
    subq %rsi,%rdx
    movq $__NR_write,%rax
    syscall

/* И снова ставим жертву на паузу, чтобы мы могли восстановить код и регистры жертвы. */
    int $3
PAYLOAD_AMD64_END:
