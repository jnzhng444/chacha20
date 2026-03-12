#!/usr/bin/env bash
# =============================================================================
# run-qemu.sh - Lanza QEMU con servidor GDB para depurar chacha20.elf
# =============================================================================
#
# Uso:
#   Terminal 1:  ./run-qemu.sh
#   Terminal 2:  gdb-multiarch chacha20.elf
#                (gdb) target remote :1234
#                (gdb) break main
#                (gdb) continue
#
# Comandos GDB útiles para este proyecto:
#   break chacha20_quarter_round   - parar al entrar al quarter round
#   info registers                 - ver todos los registros
#   x/16xw <dirección>             - ver 16 palabras del estado en hex
#   print/x $t0                    - ver registro t0 en hex
#   stepi                          - avanzar instrucción por instrucción
#   continue                       - continuar hasta el siguiente breakpoint
# =============================================================================

echo "Iniciando QEMU (rv32im, virt) con servidor GDB en puerto 1234..."
echo ""
echo "En otra terminal, ejecuta:"
echo "  docker exec -it rvqemu /bin/bash"
echo "  gdb-multiarch chacha20.elf"
echo "  (gdb) target remote :1234"
echo "  (gdb) break main"
echo "  (gdb) continue"
echo ""

qemu-system-riscv32 \
    -machine virt \
    -nographic \
    -bios none \
    -kernel chacha20.elf \
    -S \
    -gdb tcp::1234
