# ChaCha20 — Implementación en Ensamblador RISC-V

Implementación del algoritmo de cifrado de flujo ChaCha20 (RFC 8439) en ensamblador RISC-V (rv32im), con un programa de pruebas en C. El proyecto corre en bare-metal sobre QEMU y es depurable con GDB dentro de un contenedor Docker.

---

## Estructura del repositorio

```
.
├── Dockerfile              # Imagen Docker con toolchain RISC-V y QEMU compilado desde fuente
├── README.md               # Este archivo
├── DOCUMENTACION.md        # Documentación técnica del diseño e implementación
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

### 4. Ejecutar con QEMU

```bash
# Dentro del contenedor, en src/
./run-qemu.sh
```

QEMU arranca la máquina virtual RISC-V, ejecuta `chacha20.elf` y muestra la salida de los tests por UART en la terminal. La ejecución termina en un loop infinito al finalizar todos los tests.

Salida esperada:

```
========================================
  ChaCha20 - RISC-V
========================================

[Test 1] Quarter Round - RFC 8439 sec 2.1.1
  a: got=0xea2a92f4  expected=0xea2a92f4  [PASS]
  b: got=0xcb1cf8ce  expected=0xcb1cf8ce  [PASS]
  c: got=0x4581472e  expected=0x4581472e  [PASS]
  d: got=0x5881c4bb  expected=0x5881c4bb  [PASS]

[Test 2] Quarter Round en estado 4x4 - RFC 8439 sec 2.2.1
  ...

[Test 3] chacha20_block - RFC 8439 sec 2.3.2
  ...

[Test 4] chacha20_encrypt - RFC 8439 sec 2.4.2
  ...

========================================
Resultado: 26/26 tests pasaron
Estado: OK
========================================
```

---

## Ejecutar los casos de prueba y verificar vectores del RFC

Los tests están en `src/main.c` y verifican cuatro vectores del Apéndice A del RFC 8439:

| Test | Sección RFC | Qué verifica |
|---|---|---|
| Test 1 | §2.1.1 | `chacha20_quarter_round`: 4 palabras aisladas |
| Test 2 | §2.2.1 | `chacha20_quarter_round`: índices (2,7,8,13) en estado 4×4 |
| Test 3 | §2.3.2 | `chacha20_block`: 16 palabras del keystream completo |
| Test 4 | §2.4.2 | `chacha20_encrypt`: 8 bytes del texto cifrado "Sunscreen" |

Para correr los tests:

```bash
# Compilar
cd /home/rvqemu-dev/workspace/src
./build.sh

# Ejecutar (QEMU sin GDB, sale solo)
qemu-system-riscv32 -machine virt -nographic -bios none -kernel chacha20.elf
```

> **Nota:** Presionar `Ctrl+A` seguido de `X` para salir de QEMU si el programa no termina.

---

## Depuración con GDB

Se necesitan **dos terminales** dentro del contenedor.

### Terminal 1 — Iniciar QEMU en modo GDB

```bash
cd /home/rvqemu-dev/workspace/src
./run-qemu.sh
```

QEMU queda detenido en `0x80000000` esperando la conexión de GDB.

### Terminal 2 — Conectar GDB

```bash
# Abrir otra shell en el contenedor (desde el host)
docker exec -it rvqemu /bin/bash
# o si usas Podman:
podman exec -it rvqemu /bin/bash

cd /home/rvqemu-dev/workspace/src
gdb-multiarch chacha20.elf
```

### Comandos GDB de referencia

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
