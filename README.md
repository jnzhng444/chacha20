# ChaCha20 — Implementación en Ensamblador RISC-V

Implementación del algoritmo de cifrado de flujo ChaCha20 (RFC 8439) en ensamblador RISC-V (rv32im), con un programa de pruebas en C. El proyecto corre en bare-metal sobre QEMU y es depurable con GDB dentro de un contenedor Docker.

---

## Estructura del repositorio

```
.
├── Dockerfile              # Imagen Docker con toolchain RISC-V y QEMU compilado desde fuente
├── README.md               # Este archivo
├── DOCUMENTACION.md        # Documentación técnica del diseño e implementación
├── docs/                   # Evidencias (capturas) para la documentación
│   └── img/                # PNGs usados en DOCUMENTACION.md
├── run.sh                  # Lanza el contenedor Docker/Podman de forma interactiva
└── src/
    ├── chacha20.s          # Implementación principal en ensamblador RISC-V
    │                       #   - chacha20_quarter_round
    │                       #   - inner_block (helper interno)
    │                       #   - chacha20_block
    │                       #   - chacha20_encrypt
    ├── main.c              # Programa principal: vectores de prueba del RFC 8439
    ├── startup.s           # Punto de entrada bare-metal (_start → main)
    ├── linker.ld           # Script de enlace: carga en 0x80000000, stack de 64 KB
    ├── build.sh            # Compila y enlaza todo el proyecto
    └── run-qemu.sh         # Inicia QEMU con servidor GDB en el puerto 1234
```

---

## Requisitos previos

| Herramienta | Propósito |
|---|---|
| Docker o Podman | Ejecutar el entorno de desarrollo con toolchain y QEMU |
| Git | Clonar el repositorio |

Todo lo demás (compilador `riscv64-unknown-elf-gcc`, `gdb-multiarch`, QEMU riscv32) está incluido en la imagen Docker. No se necesita instalar nada en el host.

---

## Instrucciones paso a paso

### 1. Clonar el repositorio

```bash
git clone <url-del-repo>
cd chacha20
```

### 2. Construir e iniciar el contenedor

```bash
chmod +x run.sh
./run.sh
```

El script detecta automáticamente Docker o Podman, construye la imagen `rvqemu` si no existe (solo la primera vez, puede tardar varios minutos porque compila QEMU desde fuente), y abre una shell interactiva dentro del contenedor con el proyecto montado en `/home/rvqemu-dev/workspace`.

### 3. Compilar el proyecto (dentro del contenedor)

```bash
cd /home/rvqemu-dev/workspace/src
./build.sh
```

Esto genera `chacha20.elf` con símbolos de depuración DWARF 4 (`-g3`).

**Flags de compilación utilizados:**
| Flag | Descripción |
|---|---|
| `-march=rv32im` | RISC-V 32 bits con extensiones enteras y multiplicación |
| `-mabi=ilp32` | ABI ILP32: enteros de 32 bits, sin FPU |
| `-nostdlib -ffreestanding` | Entorno bare-metal sin biblioteca estándar |
| `-g3 -gdwarf-4` | Símbolos de depuración completos para GDB |

### 4. Ejecutar con QEMU (modo depuración con GDB)

```bash
# Dentro del contenedor, en src/
./run-qemu.sh
```

`run-qemu.sh` inicia QEMU con servidor GDB en `:1234` y deja la CPU detenida (`-S`) esperando a que GDB se conecte. La salida por UART (tests) aparece después de ejecutar `continue` en GDB.

Salida esperada (resumen):

```
========================================
  ChaCha20 - RISC-V (RFC 8439)
========================================


...

========================================
Resultado: 117/117 tests pasaron
Estado: OK
========================================
```

### 5. Abrir una sesión de depuración (GDB)

En otra terminal del host (con el contenedor ya corriendo):

```bash
docker exec -it rvqemu /bin/bash
```

Dentro de esa shell del contenedor:

```bash
cd /home/rvqemu-dev/workspace/src
gdb-multiarch chacha20.elf
```

Y dentro de GDB:

```gdb
target remote :1234

# breakpoints (elige los que necesites)
break main
break chacha20_block
break chacha20_encrypt

continue
```

---

## Ejecutar los casos de prueba y verificar vectores del RFC

Los tests están en `src/main.c` y combinan:

- Tests incrementales (quarter round, block, encrypt/decrypt, multi-bloque)
- Vectores oficiales del RFC 8439 (Apéndice A.1 y A.2)

| Grupo | Qué se verifica |
|---|---|
| Tests 1–5 | Correctitud incremental y roundtrip (encrypt==decrypt), incluyendo multi-bloque |
| RFC 8439 A.1 (Vectores #1–#5) | `chacha20_block`: keystream de 64 bytes (16 palabras) por vector |
| RFC 8439 A.2 (Vectores #1–#3) | `chacha20_encrypt`: ciphertext completo para longitudes 64, 375 y 127 bytes |

Para correr los tests (con GDB, usando el flujo recomendado del repo):

```bash
# 1) En el host
cd chacha20
./run.sh

# 2) En el contenedor
cd /home/rvqemu-dev/workspace/src
./build.sh
./run-qemu.sh

# 3) En otra terminal del host
docker exec -it rvqemu /bin/bash

# 4) En esa shell
cd /home/rvqemu-dev/workspace/src
gdb-multiarch chacha20.elf
```

En GDB, ejecuta `target remote :1234`, coloca breakpoints si quieres, y luego `continue`. Si todos los vectores pasan verás al final `Estado: OK`.

> **Nota:** El programa termina en un loop infinito. Para salir de QEMU: `Ctrl+A` y luego `X`.

---

## Comandos GDB de referencia

```gdb
# Conectarse al servidor QEMU
target remote :1234

# Puntos de ruptura en las funciones del algoritmo
break chacha20_quarter_round
break inner_block
break chacha20_block
break chacha20_encrypt

# Iniciar ejecución
continue

# Navegación
step                    # instrucción a instrucción
continue                # hasta el próximo breakpoint

# Inspección de registros
info registers          # todos los registros
p/x $t0                 # registro t0 en hex
p/x $s0                 # registro s0 en hex

# Inspección de memoria
x/16xw $a3              # 16 palabras a partir de a3 (estado del bloque)
x/16xw $sp              # 16 palabras a partir del stack pointer

# Vistas TUI
layout asm              # vista de ensamblador
layout regs             # vista de registros

# Salir
monitor quit
```

### Ejemplo: verificar el estado antes y después de las 20 rondas

```gdb
target remote :1234
break add_initial_state      # justo antes de la suma con el estado inicial
continue
x/16xw $s3                   # imprimir working_state después de las rondas
```

### Ejemplo: correr todos los tests de un solo

```gdb
target remote :1234
break main                # imprimir working_state
continue
continue

#deberia mostrarse todos los tests de una en la otra terminal.
```