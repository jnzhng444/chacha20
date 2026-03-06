#!/usr/bin/env bash
# =============================================================================
# build.sh - Compila el proyecto ChaCha20 (C + ensamblador RISC-V)
# Objetivo: rv32im, bare-metal, depurable con GDB
# =============================================================================
set -e

OUTPUT="chacha20.elf"
FLAGS="-march=rv32im -mabi=ilp32 -nostdlib -ffreestanding -g3 -gdwarf-4"

echo "=== Compilando ChaCha20 ==="

echo "[1/3] startup.s -> startup.o"
riscv64-unknown-elf-gcc $FLAGS -c startup.s -o startup.o

echo "[2/3] chacha20.s -> chacha20.o"
riscv64-unknown-elf-gcc $FLAGS -c chacha20.s -o chacha20.o

echo "[3/3] main.c -> main.o"
riscv64-unknown-elf-gcc $FLAGS -c main.c -o main.o

echo "[link] startup.o + chacha20.o + main.o -> $OUTPUT"
riscv64-unknown-elf-gcc $FLAGS \
    startup.o chacha20.o main.o \
    -T linker.ld \
    -o "$OUTPUT"

echo ""
echo "Build exitoso: $OUTPUT creado"
echo "Para ejecutar: ./run-qemu.sh"
