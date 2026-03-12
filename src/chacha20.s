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

# =============================================================================
# inner_block
#
# Aplica 8 quarter rounds sobre el estado: 4 de columna + 4 de diagonal.
# RFC 8439, Sección 2.3.1:
#
#   Column rounds:
#     QUARTERROUND(0,  4,  8, 12)
#     QUARTERROUND(1,  5,  9, 13)
#     QUARTERROUND(2,  6, 10, 14)
#     QUARTERROUND(3,  7, 11, 15)
#   Diagonal rounds:
#     QUARTERROUND(0,  5, 10, 15)
#     QUARTERROUND(1,  6, 11, 12)
#     QUARTERROUND(2,  7,  8, 13)
#     QUARTERROUND(3,  4,  9, 14)
#
# Prototipo C:
#   void inner_block(uint32_t state[16]);
#
# Parámetros:
#   a0 = uint32_t *state   puntero al estado de 16 palabras (modificado in-place)
#
# Registros callee-saved usados: s0 (para preservar el puntero state entre llamadas)
# =============================================================================
.globl inner_block
inner_block:
    addi sp, sp, -8
    sw   ra, 4(sp)
    sw   s0, 0(sp)

    mv   s0, a0             # s0 = state (preservado durante todas las llamadas)

    # ------------------------------------------------------------------
    # Column rounds
    # ------------------------------------------------------------------

    # QUARTERROUND(0, 4, 8, 12)
    mv   a0, s0
    li   a1, 0;  li a2,  4;  li a3,  8;  li a4, 12
    call chacha20_quarter_round

    # QUARTERROUND(1, 5, 9, 13)
    mv   a0, s0
    li   a1, 1;  li a2,  5;  li a3,  9;  li a4, 13
    call chacha20_quarter_round

    # QUARTERROUND(2, 6, 10, 14)
    mv   a0, s0
    li   a1, 2;  li a2,  6;  li a3, 10;  li a4, 14
    call chacha20_quarter_round

    # QUARTERROUND(3, 7, 11, 15)
    mv   a0, s0
    li   a1, 3;  li a2,  7;  li a3, 11;  li a4, 15
    call chacha20_quarter_round

    # ------------------------------------------------------------------
    # Diagonal rounds
    # ------------------------------------------------------------------

    # QUARTERROUND(0, 5, 10, 15)
    mv   a0, s0
    li   a1, 0;  li a2,  5;  li a3, 10;  li a4, 15
    call chacha20_quarter_round

    # QUARTERROUND(1, 6, 11, 12)
    mv   a0, s0
    li   a1, 1;  li a2,  6;  li a3, 11;  li a4, 12
    call chacha20_quarter_round

    # QUARTERROUND(2, 7, 8, 13)
    mv   a0, s0
    li   a1, 2;  li a2,  7;  li a3,  8;  li a4, 13
    call chacha20_quarter_round

    # QUARTERROUND(3, 4, 9, 14)
    mv   a0, s0
    li   a1, 3;  li a2,  4;  li a3,  9;  li a4, 14
    call chacha20_quarter_round

    lw   s0, 0(sp)
    lw   ra, 4(sp)
    addi sp, sp, 8
    ret

# =============================================================================
# chacha20_block
#
# Genera 64 bytes de keystream a partir de key, counter y nonce.
# RFC 8439, Sección 2.3.
#
# Prototipo C:
#   void chacha20_block(const uint32_t *key, uint32_t counter,
#                       const uint32_t *nonce, uint32_t *output);
#
# Parámetros:
#   a0 = const uint32_t *key    puntero a 8 palabras (256-bit key)
#   a1 = uint32_t counter       contador de bloque (32-bit)
#   a2 = const uint32_t *nonce  puntero a 3 palabras (96-bit nonce)
#   a3 = uint32_t *output       puntero al buffer de salida (64 bytes)
#
# Layout del estado (16 palabras x 4 bytes = 64 bytes):
#   state[ 0.. 3] = constantes "expa nd 3 2-by te k"
#   state[ 4..11] = key[0..7]
#   state[12]     = counter
#   state[13..15] = nonce[0..2]
#
# Stack frame (88 bytes):
#   sp+ 0..63 : initial_state[16]
#   sp+64     : s4
#   sp+68     : s3
#   sp+72     : s2
#   sp+76     : s1
#   sp+80     : s0
#   sp+84     : ra
#
# Estado actual: completo (inicialización + 10 rondas + suma estado inicial).
# =============================================================================
.globl chacha20_block
chacha20_block:
    addi sp, sp, -88
    sw   ra,  84(sp)
    sw   s0,  80(sp)
    sw   s1,  76(sp)
    sw   s2,  72(sp)
    sw   s3,  68(sp)
    sw   s4,  64(sp)

    mv   s0, a0             # s0 = key
    mv   s1, a1             # s1 = counter
    mv   s2, a2             # s2 = nonce
    mv   s3, a3             # s3 = output (working_state)

    # ------------------------------------------------------------------
    # Constantes ASCII "expa nd 3 2-by te k" (RFC 8439, sec 2.3)
    # ------------------------------------------------------------------
    li   t0, 0x61707865;  sw t0,  0(s3)   # "expa"
    li   t0, 0x3320646e;  sw t0,  4(s3)   # "nd 3"
    li   t0, 0x79622d32;  sw t0,  8(s3)   # "2-by"
    li   t0, 0x6b206574;  sw t0, 12(s3)   # "te k"

    # ------------------------------------------------------------------
    # Key[0..7] → state[4..11]
    # ------------------------------------------------------------------
    lw   t0,  0(s0);  sw t0, 16(s3)
    lw   t0,  4(s0);  sw t0, 20(s3)
    lw   t0,  8(s0);  sw t0, 24(s3)
    lw   t0, 12(s0);  sw t0, 28(s3)
    lw   t0, 16(s0);  sw t0, 32(s3)
    lw   t0, 20(s0);  sw t0, 36(s3)
    lw   t0, 24(s0);  sw t0, 40(s3)
    lw   t0, 28(s0);  sw t0, 44(s3)

    # ------------------------------------------------------------------
    # Counter → state[12]
    # ------------------------------------------------------------------
    sw   s1, 48(s3)

    # ------------------------------------------------------------------
    # Nonce[0..2] → state[13..15]
    # ------------------------------------------------------------------
    lw   t0,  0(s2);  sw t0, 52(s3)
    lw   t0,  4(s2);  sw t0, 56(s3)
    lw   t0,  8(s2);  sw t0, 60(s3)

    # ------------------------------------------------------------------
    # Copiar estado inicial al stack: initial_state = sp+0..sp+63
    # ------------------------------------------------------------------
    li   t1, 0
copy_initial_state:
    slli t2, t1, 2
    add  t3, s3, t2         # &output[i]
    lw   t0, 0(t3)
    add  t3, sp, t2         # &initial_state[i]
    sw   t0, 0(t3)
    addi t1, t1, 1
    li   t2, 16
    blt  t1, t2, copy_initial_state

    # ------------------------------------------------------------------
    # Ejecutar inner_block 10 veces sobre working_state
    # ------------------------------------------------------------------
    li   s4, 10
rounds_loop:
    mv   a0, s3
    call inner_block
    addi s4, s4, -1
    bnez s4, rounds_loop

    # ------------------------------------------------------------------
    # working_state += initial_state  (mod 2^32, palabra a palabra)
    # RFC 8439: "add the original input words to the output words"
    # ------------------------------------------------------------------
    li   t1, 0
add_initial_state:
    slli t2, t1, 2
    add  t3, s3, t2         # &working_state[i]
    lw   t0, 0(t3)
    add  t4, sp, t2         # &initial_state[i]
    lw   t5, 0(t4)
    add  t0, t0, t5         # working_state[i] += initial_state[i] mod 2^32
    sw   t0, 0(t3)
    addi t1, t1, 1
    li   t2, 16
    blt  t1, t2, add_initial_state

    # output ya contiene los 64 bytes del keystream en little-endian

    lw   s4,  64(sp)
    lw   s3,  68(sp)
    lw   s2,  72(sp)
    lw   s1,  76(sp)
    lw   s0,  80(sp)
    lw   ra,  84(sp)
    addi sp, sp, 88
    ret

# =============================================================================
# chacha20_encrypt
#
# Cifra (o descifra) un mensaje de longitud arbitraria.
# RFC 8439, Sección 2.4:
#   - Por cada bloque de 64 bytes: generar keystream con chacha20_block
#   - XOR del keystream con el bloque de plaintext → ciphertext
#
# Prototipo C:
#   void chacha20_encrypt(const uint32_t *key, uint32_t counter,
#                         const uint32_t *nonce,
#                         const uint8_t *plaintext, uint8_t *ciphertext,
#                         uint32_t len);
#
# Parámetros:
#   a0 = const uint32_t *key
#   a1 = uint32_t counter
#   a2 = const uint32_t *nonce
#   a3 = const uint8_t  *plaintext
#   a4 = uint8_t        *ciphertext
#   a5 = uint32_t        len         (longitud en bytes)
#
# Stack frame (92 bytes):
#   sp+ 0..63 : keystream[64]   buffer temporal del keystream
#   sp+64     : s5
#   sp+68     : s4
#   sp+72     : s3
#   sp+76     : s2
#   sp+80     : s1
#   sp+84     : s0
#   sp+88     : ra
# =============================================================================
.globl chacha20_encrypt
chacha20_encrypt:
    addi sp, sp, -92
    sw   ra,  88(sp)
    sw   s0,  84(sp)
    sw   s1,  80(sp)
    sw   s2,  76(sp)
    sw   s3,  72(sp)
    sw   s4,  68(sp)
    sw   s5,  64(sp)

    mv   s0, a0             # s0 = key
    mv   s1, a1             # s1 = counter
    mv   s2, a2             # s2 = nonce
    mv   s3, a3             # s3 = plaintext
    mv   s4, a4             # s4 = ciphertext
    mv   s5, a5             # s5 = len (bytes restantes)

encrypt_block_loop:
    beqz s5, encrypt_done   # si len == 0 terminar

    # generar keystream para este bloque

    mv   a0, s0             # key
    mv   a1, s1             # counter 
    mv   a2, s2             # nonce
    addi a3, sp, 0          # &keystream (en el stack)
    call chacha20_block

    # XOR byte a byte: ciphertext[i] = plaintext[i] ^ keystream[i]
    li   t0, 0              # i = 0
    li   t1, 64             # tamaño de un bloque

xor_loop:
    bgeu t0, s5, xor_done   # si i >= bytes_restantes terminar
    bge  t0, t1, xor_done   # si i >= 64 terminar bloque

    add  t2, s3, t0         # &plaintext[i]
    lbu  t3, 0(t2)          # t3 = plaintext[i]

    add  t2, sp, t0         # &keystream[i]
    lbu  t4, 0(t2)          # t4 = keystream[i]

    xor  t3, t3, t4         # t3 = plaintext[i] ^ keystream[i]

    add  t2, s4, t0         # &ciphertext[i]
    sb   t3, 0(t2)          # ciphertext[i] = resultado

    addi t0, t0, 1
    j    xor_loop

xor_done:
    # avanzar punteros y reducir bytes restantes
    add  s3, s3, t0         # plaintext  += bytes_procesados
    add  s4, s4, t0         # ciphertext += bytes_procesados
    sub  s5, s5, t0         # len        -= bytes_procesados

    j    encrypt_block_loop

encrypt_done:
    lw   s5,  64(sp)
    lw   s4,  68(sp)
    lw   s3,  72(sp)
    lw   s2,  76(sp)
    lw   s1,  80(sp)
    lw   s0,  84(sp)
    lw   ra,  88(sp)
    addi sp, sp, 92
    ret
