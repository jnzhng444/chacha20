# =============================================================================
# ChaCha20 - Implementación en ensamblador RISC-V (rv32im)
# Referencia: RFC 8439 (https://datatracker.ietf.org/doc/html/rfc8439)
# =============================================================================
#
# Convenciones de llamada RISC-V usadas en este archivo:
#   a0-a7  : argumentos / valor de retorno (caller-saved)
#   t0-t6  : registros temporales (caller-saved)
#   s0-s11 : registros guardados entre llamadas (callee-saved)
#   ra     : dirección de retorno (caller-saved en funciones hoja está OK)
#
# =============================================================================

.section .text

# =============================================================================
# chacha20_quarter_round
#
# Aplica una operación quarter round in-place sobre cuatro palabras del estado.
# RFC 8439, Sección 2.1:
#
#   a += b;  d ^= a;  d <<<= 16;
#   c += d;  b ^= c;  b <<<= 12;
#   a += b;  d ^= a;  d <<<=  8;
#   c += d;  b ^= c;  b <<<=  7;
#
# Prototipo C:
#   void chacha20_quarter_round(uint32_t *state, int x, int y, int z, int w);
#
# Parámetros:
#   a0 = uint32_t *state   puntero al array de 16 palabras del estado
#   a1 = int x             índice de a
#   a2 = int y             índice de b
#   a3 = int z             índice de c
#   a4 = int w             índice de d
#
# Retorna: void
# Registros modificados: t0-t5, a1-a4 (todos caller-saved, no se necesita stack)
# Función hoja: no llama a otras funciones.
# =============================================================================
.globl chacha20_quarter_round
chacha20_quarter_round:
    # ------------------------------------------------------------------
    # Convertir índices a offsets de byte (índice * 4) y calcular
    # direcciones absolutas dentro del array state[].
    # Reutilizamos a1-a4 para guardar las direcciones: son caller-saved
    # y ya no necesitamos los valores originales de índice.
    # ------------------------------------------------------------------
    slli a1, a1, 2          # a1 = x * 4
    add  a1, a0, a1         # a1 = &state[x]

    slli a2, a2, 2          # a2 = y * 4
    add  a2, a0, a2         # a2 = &state[y]

    slli a3, a3, 2          # a3 = z * 4
    add  a3, a0, a3         # a3 = &state[z]

    slli a4, a4, 2          # a4 = w * 4
    add  a4, a0, a4         # a4 = &state[w]

    # ------------------------------------------------------------------
    # Cargar los cuatro valores: a→t0, b→t1, c→t2, d→t3
    # ------------------------------------------------------------------
    lw   t0, 0(a1)          # t0 = a = state[x]
    lw   t1, 0(a2)          # t1 = b = state[y]
    lw   t2, 0(a3)          # t2 = c = state[z]
    lw   t3, 0(a4)          # t3 = d = state[w]

    # ------------------------------------------------------------------
    # Línea 1:  a += b;  d ^= a;  d <<<= 16
    # ------------------------------------------------------------------
    add  t0, t0, t1         # a += b
    xor  t3, t3, t0         # d ^= a
    # rotl(d, 16): (d << 16) | (d >> 16)
    slli t4, t3, 16
    srli t5, t3, 16
    or   t3, t4, t5         # d <<<= 16

    # ------------------------------------------------------------------
    # Línea 2:  c += d;  b ^= c;  b <<<= 12
    # ------------------------------------------------------------------
    add  t2, t2, t3         # c += d
    xor  t1, t1, t2         # b ^= c
    # rotl(b, 12): (b << 12) | (b >> 20)
    slli t4, t1, 12
    srli t5, t1, 20
    or   t1, t4, t5         # b <<<= 12

    # ------------------------------------------------------------------
    # Línea 3:  a += b;  d ^= a;  d <<<= 8
    # ------------------------------------------------------------------
    add  t0, t0, t1         # a += b
    xor  t3, t3, t0         # d ^= a
    # rotl(d, 8): (d << 8) | (d >> 24)
    slli t4, t3, 8
    srli t5, t3, 24
    or   t3, t4, t5         # d <<<= 8

    # ------------------------------------------------------------------
    # Línea 4:  c += d;  b ^= c;  b <<<= 7
    # ------------------------------------------------------------------
    add  t2, t2, t3         # c += d
    xor  t1, t1, t2         # b ^= c
    # rotl(b, 7): (b << 7) | (b >> 25)
    slli t4, t1, 7
    srli t5, t1, 25
    or   t1, t4, t5         # b <<<= 7

    # ------------------------------------------------------------------
    # Escribir resultados de vuelta al estado
    # ------------------------------------------------------------------
    sw   t0, 0(a1)          # state[x] = a
    sw   t1, 0(a2)          # state[y] = b
    sw   t2, 0(a3)          # state[z] = c
    sw   t3, 0(a4)          # state[w] = d

    ret
