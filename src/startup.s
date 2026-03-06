# RISC-V startup para programas C en bare-metal
# Inicializa el stack pointer y llama a main()

.section .text
.globl _start

_start:
    # Inicializar stack pointer al tope definido en el linker script
    la   sp, _stack_top

    # Llamar a main()
    call main

    # Si main retorna, loop infinito
_halt:
    j _halt
