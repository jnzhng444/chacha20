/* main.c - Programa principal ChaCha20 en RISC-V */

#include <stdint.h>

/* =========================================================================
 * Declaraciones de funciones en ensamblador (chacha20.s)
 * ========================================================================= */
extern void chacha20_quarter_round(uint32_t *state, int x, int y, int z, int w);

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
 * Entry point
 * ========================================================================= */
void main(void) {
    uart_puts("========================================\n");
    uart_puts("  ChaCha20 - RISC-V\n");
    uart_puts("========================================\n");

    test_quarter_round_basico();
    test_quarter_round_estado();

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
