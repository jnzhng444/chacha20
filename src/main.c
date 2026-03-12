/* main.c - Programa principal ChaCha20 en RISC-V */

#include <stdint.h>

/* =========================================================================
 * Declaraciones de funciones en ensamblador (chacha20.s)
 * ========================================================================= */
extern void chacha20_quarter_round(uint32_t *state, int x, int y, int z, int w);
extern void chacha20_block(const uint32_t *key, uint32_t counter,
                           const uint32_t *nonce, uint32_t *output);
extern void chacha20_encrypt(const uint32_t *key, uint32_t counter,
                             const uint32_t *nonce,
                             const uint8_t *plaintext, uint8_t *ciphertext,
                             uint32_t len);

/* Salida por UART - dirección 0x10000000 en QEMU virt */
static volatile uint8_t * const UART = (volatile uint8_t *)0x10000000;

static void uart_putc(char c) {
    *UART = (uint8_t)c;
}

static void uart_puts(const char *s) {
    while (*s) uart_putc(*s++);
}

static void uart_puthex32(uint32_t v) {
    const char hex[] = "0123456789abcdef";
    uart_puts("0x");
    for (int i = 28; i >= 0; i -= 4)
        uart_putc(hex[(v >> i) & 0xF]);
}

static void uart_putu(uint32_t n) {
    if (n == 0) { uart_putc('0'); return; }
    char buf[10];
    int i = 0;
    while (n > 0) { buf[i++] = '0' + (n % 10); n /= 10; }
    while (i > 0) uart_putc(buf[--i]);
}

/* =========================================================================
 * Framework de tests
 * ========================================================================= */
static int tests_run    = 0;
static int tests_passed = 0;

static void check(const char *label, uint32_t got, uint32_t expected) {
    tests_run++;
    uart_puts("  ");
    uart_puts(label);
    uart_puts(": got=");
    uart_puthex32(got);
    uart_puts("  expected=");
    uart_puthex32(expected);
    if (got == expected) {
        uart_puts("  [PASS]\n");
        tests_passed++;
    } else {
        uart_puts("  [FAIL]\n");
    }
}

/* =========================================================================
 * Test 1: Quarter Round aislado - RFC 8439, sección 2.1.1
 *
 *   Entrada:  a=0x11111111  b=0x01020304  c=0x9b8d6f43  d=0x01234567
 *   Esperado: a=0xea2a92f4  b=0xcb1cf8ce  c=0x4581472e  d=0x5881c4bb
 * ========================================================================= */
static void test_quarter_round_basico(void) {
    uart_puts("\n[Test 1] Quarter Round - RFC 8439 sec 2.1.1\n");

    static uint32_t state[4] = {
        0x11111111,
        0x01020304,
        0x9b8d6f43,
        0x01234567
    };

    chacha20_quarter_round(state, 0, 1, 2, 3);

    check("a", state[0], 0xea2a92f4);
    check("b", state[1], 0xcb1cf8ce);
    check("c", state[2], 0x4581472e);
    check("d", state[3], 0x5881c4bb);
}

/* =========================================================================
 * Test 2: Quarter Round sobre estado 4x4 - RFC 8439, sección 2.2.1
 *
 *   Aplica QUARTERROUND(2, 7, 8, 13) sobre un estado de 16 palabras.
 *   Solo cambian las posiciones 2, 7, 8 y 13.
 *
 *   Esperado:
 *     pos 2  → 0xbdb886dc
 *     pos 7  → 0xcfacafd2
 *     pos 8  → 0xe46bea80
 *     pos 13 → 0xccc07c79
 * ========================================================================= */
static void test_quarter_round_estado(void) {
    uart_puts("\n[Test 2] Quarter Round en estado 4x4 - RFC 8439 sec 2.2.1\n");

    static uint32_t state[16] = {
        0x879531e0, 0xc5ecf37d, 0x516461b1, 0xc9a62f8a,
        0x44c20ef3, 0x3390af7f, 0xd9fc690b, 0x2a5f714c,
        0x53372767, 0xb00a5631, 0x974c541a, 0x359e9963,
        0x5c971061, 0x3d631689, 0x2098d9d6, 0x91dbd320
    };

    chacha20_quarter_round(state, 2, 7, 8, 13);

    check("state[ 2]", state[2],  0xbdb886dc);
    check("state[ 7]", state[7],  0xcfacafd2);
    check("state[ 8]", state[8],  0xe46bea80);
    check("state[13]", state[13], 0xccc07c79);
}

/* =========================================================================
 * Test 3: chacha20_block - RFC 8439, sección 2.3.2
 *
 *   Key     = 00 01 02 ... 1f  (32 bytes)
 *   Counter = 1
 *   Nonce   = 00 00 00 09  00 00 00 4a  00 00 00 00
 *
 *   Salida esperada (16 palabras en little-endian):
 *     e4e7f110  15593bd1  1fdd0f50  c47120a3
 *     c7f4d1c7  0368c033  9aaa2204  4e6cd4c3
 *     466482d2  09aa9f07  05d7c214  a2028bd9
 *     d19c12b5  b94e16de  e883d0cb  4e3c50a2
 * ========================================================================= */
static void test_chacha20_block(void) {
    uart_puts("\n[Test 3] chacha20_block - RFC 8439 sec 2.3.2\n");

    static const uint32_t key[8] = {
        0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
        0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c
    };
    static const uint32_t nonce[3] = {
        0x09000000, 0x4a000000, 0x00000000
    };
    static uint32_t output[16];

    chacha20_block(key, 1, nonce, output);

    static const uint32_t expected[16] = {
        0xe4e7f110, 0x15593bd1, 0x1fdd0f50, 0xc47120a3,
        0xc7f4d1c7, 0x0368c033, 0x9aaa2204, 0x4e6cd4c3,
        0x466482d2, 0x09aa9f07, 0x05d7c214, 0xa2028bd9,
        0xd19c12b5, 0xb94e16de, 0xe883d0cb, 0x4e3c50a2
    };

    for (int i = 0; i < 16; i++) {
        check("word", output[i], expected[i]);
    }
}

/* =========================================================================
 * Test 4: chacha20_encrypt - RFC 8439, sección 2.4.2
 *
 * Cifra el texto "Sunscreen" (114 bytes, 2 bloques) y verifica los
 * primeros bytes del resultado contra el ciphertext del RFC.
 *
 * Key     = 00 01 02 ... 1f
 * Nonce   = 00 00 00 00  00 00 00 4a  00 00 00 00
 * Counter = 1
 * ========================================================================= */
static void test_chacha20_encrypt(void) {
    uart_puts("\n[Test 4] chacha20_encrypt - RFC 8439 sec 2.4.2\n");

    static const uint32_t key[8] = {
        0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
        0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c
    };
    static const uint32_t nonce[3] = {
        0x00000000, 0x4a000000, 0x00000000
    };

    /* Plaintext "Ladies and Gentlemen of the class of '99..." (RFC 8439) */
    static const uint8_t plaintext[114] = {
        0x4c,0x61,0x64,0x69,0x65,0x73,0x20,0x61,0x6e,0x64,0x20,0x47,0x65,0x6e,0x74,0x6c,
        0x65,0x6d,0x65,0x6e,0x20,0x6f,0x66,0x20,0x74,0x68,0x65,0x20,0x63,0x6c,0x61,0x73,
        0x73,0x20,0x6f,0x66,0x20,0x27,0x39,0x39,0x3a,0x20,0x49,0x66,0x20,0x49,0x20,0x63,
        0x6f,0x75,0x6c,0x64,0x20,0x6f,0x66,0x66,0x65,0x72,0x20,0x79,0x6f,0x75,0x20,0x6f,
        0x6e,0x6c,0x79,0x20,0x6f,0x6e,0x65,0x20,0x74,0x69,0x70,0x20,0x66,0x6f,0x72,0x20,
        0x74,0x68,0x65,0x20,0x66,0x75,0x74,0x75,0x72,0x65,0x2c,0x20,0x73,0x75,0x6e,0x73,
        0x63,0x72,0x65,0x65,0x6e,0x20,0x77,0x6f,0x75,0x6c,0x64,0x20,0x62,0x65,0x20,0x69,
        0x74,0x2e
    };
    static uint8_t ciphertext[114];

    chacha20_encrypt(key, 1, nonce, plaintext, ciphertext, 114);

    /* Primeros 4 bytes esperados del bloque 1 (RFC 8439): 6e 2e 35 9a */
    check("ct[0]", ciphertext[0],  0x6e);
    check("ct[1]", ciphertext[1],  0x2e);
    check("ct[2]", ciphertext[2],  0x35);
    check("ct[3]", ciphertext[3],  0x9a);

    /* Primeros 4 bytes esperados del bloque 2 (RFC 8439): 07 ca 0d bf */
    check("ct[64]", ciphertext[64], 0x07);
    check("ct[65]", ciphertext[65], 0xca);
    check("ct[66]", ciphertext[66], 0x0d);
    check("ct[67]", ciphertext[67], 0xbf);
}

/* =========================================================================
 * Entry point
 * ========================================================================= */
void main(void) {
    uart_puts("========================================\n");
    uart_puts("  ChaCha20 - RISC-V\n");
    uart_puts("========================================\n");

    test_quarter_round_basico();
    test_quarter_round_estado();
    test_chacha20_block();
    test_chacha20_encrypt();

    uart_puts("\n========================================\n");
    uart_puts("Resultado: ");
    uart_putu((uint32_t)tests_passed);
    uart_putc('/');
    uart_putu((uint32_t)tests_run);
    uart_puts(" tests pasaron\n");
    uart_puts(tests_passed == tests_run ? "Estado: OK\n" : "Estado: FALLO\n");
    uart_puts("========================================\n");

    /* Loop infinito */
    while (1) {
        __asm__ volatile ("nop");
    }
}
