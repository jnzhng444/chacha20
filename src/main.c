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

/* Imprime uint32 en hex SIN prefijo "0x" (estilo RFC: e4e7f110) */
static void uart_puthex32_bare(uint32_t v) {
    const char hex[] = "0123456789abcdef";
    for (int i = 28; i >= 0; i -= 4)
        uart_putc(hex[(v >> i) & 0xF]);
}

/* Imprime uint32 en hex CON prefijo "0x" (estilo checks: 0xe4e7f110) */
static void uart_puthex32(uint32_t v) {
    uart_puts("0x");
    uart_puthex32_bare(v);
}

/* Imprime uint8 en hex de 2 dígitos (sin prefijo) */
static void uart_puthex8(uint8_t v) {
    const char hex[] = "0123456789abcdef";
    uart_putc(hex[(v >> 4) & 0xF]);
    uart_putc(hex[v & 0xF]);
}

static void uart_putu(uint32_t n) {
    if (n == 0) { uart_putc('0'); return; }
    char buf[10];
    int i = 0;
    while (n > 0) { buf[i++] = '0' + (n % 10); n /= 10; }
    while (i > 0) uart_putc(buf[--i]);
}

/* Imprime 16 palabras en formato 4x4 (estilo RFC, sin prefijo 0x) */
static void uart_print_state(const uint32_t *s) {
    for (int row = 0; row < 4; row++) {
        uart_puts("    ");
        for (int col = 0; col < 4; col++) {
            uart_puthex32_bare(s[row * 4 + col]);
            if (col < 3) uart_puts("  ");
        }
        uart_putc('\n');
    }
}

/* Imprime N bytes en hex, 16 por fila */
static void uart_print_bytes(const uint8_t *data, uint32_t len) {
    for (uint32_t i = 0; i < len; i++) {
        if (i % 16 == 0) uart_puts("    ");
        uart_puthex8(data[i]);
        if (i % 16 == 15 || i == len - 1)
            uart_putc('\n');
        else
            uart_putc(' ');
    }
}

/* Imprime N bytes como texto ASCII (no imprimibles se muestran como '.') */
static void uart_print_ascii(const uint8_t *data, uint32_t len) {
    uart_puts("    \"");
    for (uint32_t i = 0; i < len; i++) {
        uint8_t c = data[i];
        uart_putc((c >= 0x20 && c <= 0x7e) ? (char)c : '.');
    }
    uart_puts("\"\n");
}

/* =========================================================================
 * Framework de tests
 * ========================================================================= */
static int tests_run    = 0;
static int tests_passed = 0;

static void check(const char *label, uint32_t got, uint32_t expected) {
    tests_run++;
    uart_puts("    ");
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

/* Igual que check pero para bytes (imprime en 2 dígitos hex) */
static void check_byte(const char *label, uint8_t got, uint8_t expected) {
    tests_run++;
    uart_puts("    ");
    uart_puts(label);
    uart_puts(": got=0x");
    uart_puthex8(got);
    uart_puts("  expected=0x");
    uart_puthex8(expected);
    if (got == expected) {
        uart_puts("  [PASS]\n");
        tests_passed++;
    } else {
        uart_puts("  [FAIL]\n");
    }
}

/* =========================================================================
 * Test 1: Quarter Round aislado - RFC 8439, sección 2.1.1
 * ========================================================================= */
static void test_quarter_round_basico(void) {
    uart_puts("\n[Test 1] Quarter Round aislado - RFC 8439 sec 2.1.1\n");

    static uint32_t state[4] = {
        0x11111111,
        0x01020304,
        0x9b8d6f43,
        0x01234567
    };

    uart_puts("  Entrada:\n");
    uart_puts("    a="); uart_puthex32(state[0]);
    uart_puts("  b="); uart_puthex32(state[1]);
    uart_puts("  c="); uart_puthex32(state[2]);
    uart_puts("  d="); uart_puthex32(state[3]);
    uart_putc('\n');

    chacha20_quarter_round(state, 0, 1, 2, 3);

    uart_puts("  Salida:\n");
    uart_puts("    a="); uart_puthex32(state[0]);
    uart_puts("  b="); uart_puthex32(state[1]);
    uart_puts("  c="); uart_puthex32(state[2]);
    uart_puts("  d="); uart_puthex32(state[3]);
    uart_putc('\n');

    uart_puts("  Verificacion:\n");
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
 * ========================================================================= */
static void test_quarter_round_estado(void) {
    uart_puts("\n[Test 2] Quarter Round en estado 4x4 - RFC 8439 sec 2.2.1\n");

    static uint32_t state[16] = {
        0x879531e0, 0xc5ecf37d, 0x516461b1, 0xc9a62f8a,
        0x44c20ef3, 0x3390af7f, 0xd9fc690b, 0x2a5f714c,
        0x53372767, 0xb00a5631, 0x974c541a, 0x359e9963,
        0x5c971061, 0x3d631689, 0x2098d9d6, 0x91dbd320
    };

    uart_puts("  Estado antes (QUARTERROUND(2, 7, 8, 13)):\n");
    uart_print_state(state);

    chacha20_quarter_round(state, 2, 7, 8, 13);

    uart_puts("  Estado despues:\n");
    uart_print_state(state);

    uart_puts("  Verificacion (posiciones 2, 7, 8, 13):\n");
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

    /* Reconstruir el estado inicial para mostrarlo (RFC 8439 sec 2.3) */
    static const uint32_t init_state[16] = {
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
        0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
        0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c,
        0x00000001, 0x09000000, 0x4a000000, 0x00000000
    };

    uart_puts("  Estado inicial:\n");
    uart_print_state(init_state);

    chacha20_block(key, 1, nonce, output);

    uart_puts("  Keystream generado (64 bytes):\n");
    uart_print_state(output);

    static const uint32_t expected[16] = {
        0xe4e7f110, 0x15593bd1, 0x1fdd0f50, 0xc47120a3,
        0xc7f4d1c7, 0x0368c033, 0x9aaa2204, 0x4e6cd4c3,
        0x466482d2, 0x09aa9f07, 0x05d7c214, 0xa2028bd9,
        0xd19c12b5, 0xb94e16de, 0xe883d0cb, 0x4e3c50a2
    };

    uart_puts("  Verificacion (16 palabras):\n");
    for (int i = 0; i < 16; i++) {
        /* Formato: "word[ 0]" o "word[15]" */
        char label[9] = "word[  ]";
        label[5] = (i < 10) ? ' ' : ('0' + i / 10);
        label[6] = '0' + (i % 10);
        check(label, output[i], expected[i]);
    }
}

/* =========================================================================
 * Test 4: chacha20_encrypt/decrypt - RFC 8439, sección 2.4.2
 *
 * Cifra el texto "Sunscreen" (114 bytes), verifica el ciphertext del RFC,
 * luego descifra y demuestra que se recupera el mensaje original.
 * Key     = 00 01 02 ... 1f
 * Nonce   = 00 00 00 00  00 00 00 4a  00 00 00 00
 * Counter = 1
 * ========================================================================= */
static void test_chacha20_encrypt(void) {
    uart_puts("\n[Test 4] chacha20_encrypt/decrypt - RFC 8439 sec 2.4.2\n");

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
    static uint8_t keystream[128];   /* 2 bloques de 64 bytes */
    static uint8_t ciphertext[114];
    static uint8_t decrypted[114];

    /* Generar keystream: bloque 1 (counter=1) y bloque 2 (counter=2) */
    chacha20_block(key, 1, nonce, (uint32_t *)(keystream +  0));
    chacha20_block(key, 2, nonce, (uint32_t *)(keystream + 64));

    /* --- Plaintext --- */
    uart_puts("  Plaintext (texto original):\n");
    uart_print_ascii(plaintext, 114);
    uart_puts("  Plaintext (hex):\n");
    uart_print_bytes(plaintext, 114);

    /* --- Keystream --- */
    uart_puts("\n  Keystream (hex, 2 bloques = 128 bytes):\n");
    uart_print_bytes(keystream, 128);

    chacha20_encrypt(key, 1, nonce, plaintext, ciphertext, 114);

    uart_puts("\n  --- Cifrado ---\n");
    uart_puts("  Ciphertext (hex):\n");
    uart_print_bytes(ciphertext, 114);
    uart_puts("  Ciphertext (ascii):\n");
    uart_print_ascii(ciphertext, 114);

    /* --- Descifrado (ChaCha20 es simetrico: encrypt == decrypt) --- */
    chacha20_encrypt(key, 1, nonce, ciphertext, decrypted, 114);

    uart_puts("\n  --- Descifrado ---\n");
    uart_puts("  Decrypted (texto recuperado):\n");
    uart_print_ascii(decrypted, 114);

    /* --- Verificacion RFC: bytes del ciphertext --- */
    uart_puts("\n  Verificacion RFC (ciphertext):\n");
    check_byte("ct[  0]", ciphertext[0],  0x6e);
    check_byte("ct[  1]", ciphertext[1],  0x2e);
    check_byte("ct[  2]", ciphertext[2],  0x35);
    check_byte("ct[  3]", ciphertext[3],  0x9a);
    check_byte("ct[ 64]", ciphertext[64], 0x07);
    check_byte("ct[ 65]", ciphertext[65], 0xca);
    check_byte("ct[ 66]", ciphertext[66], 0x0d);
    check_byte("ct[ 67]", ciphertext[67], 0xbf);

    /* --- Verificacion roundtrip: decrypted == plaintext --- */
    uart_puts("\n  Verificacion roundtrip (decrypt == plaintext):\n");
    int all_ok = 1;
    for (int i = 0; i < 114; i++) {
        if (decrypted[i] != plaintext[i]) { all_ok = 0; break; }
    }
    tests_run++;
    uart_puts("    decrypt(encrypt(plaintext)) == plaintext (114 bytes): ");
    if (all_ok) {
        uart_puts("[PASS]\n");
        tests_passed++;
    } else {
        uart_puts("[FAIL]\n");
    }
}

/* =========================================================================
 * Test 5: cifrado/descifrado multi-bloque (3 bloques)
 *
 * Mensaje de 189 bytes → 3 bloques de keystream (counter 0, 1, 2).
 * No hay vector RFC para este test: solo verifica el roundtrip.
 * ========================================================================= */
static void test_multi_block(void) {
    uart_puts("\n[Test 5] Multi-bloque (3 bloques) - mensaje personalizado\n");

    static const uint32_t key[8] = {
        0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
        0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c
    };
    static const uint32_t nonce[3] = {
        0x00000000, 0x4a000000, 0x00000000
    };

    /* Mensaje de 189 bytes: ocupa 3 bloques (0-63, 64-127, 128-188) */
    static const uint8_t plaintext[] =
        "Hola profe, este es un test de ChaCha20 en RISC-V. "
        "Si usted puede leer esto despues de desencriptar, "
        "significa que el algoritmo funciona correctamente "
        "con tres bloques de 64 bytes cada uno!";
    const uint32_t len = (uint32_t)(sizeof(plaintext) - 1);

    static uint8_t keystream[192];   /* 3 bloques de 64 bytes */
    static uint8_t ciphertext[192];
    static uint8_t decrypted[192];

    /* Generar keystream: bloques con counter 0, 1, 2 */
    chacha20_block(key, 0, nonce, (uint32_t *)(keystream +   0));
    chacha20_block(key, 1, nonce, (uint32_t *)(keystream +  64));
    chacha20_block(key, 2, nonce, (uint32_t *)(keystream + 128));

    uart_puts("  Longitud: ");
    uart_putu(len);
    uart_puts(" bytes → bloque 1 (0-63), bloque 2 (64-127), bloque 3 (128-");
    uart_putu(len - 1);
    uart_puts(")\n");

    uart_puts("\n  Plaintext:\n");
    uart_print_ascii(plaintext, len);

    uart_puts("\n  Keystream (hex, 3 bloques = 192 bytes):\n");
    uart_print_bytes(keystream, 192);

    chacha20_encrypt(key, 0, nonce, plaintext, ciphertext, len);

    uart_puts("\n  --- Cifrado ---\n");
    uart_puts("  Ciphertext (hex):\n");
    uart_print_bytes(ciphertext, len);
    uart_puts("  Ciphertext (ascii):\n");
    uart_print_ascii(ciphertext, len);

    chacha20_encrypt(key, 0, nonce, ciphertext, decrypted, len);

    uart_puts("\n  --- Descifrado ---\n");
    uart_puts("  Decrypted:\n");
    uart_print_ascii(decrypted, len);

    uart_puts("\n  Verificacion roundtrip:\n");
    int all_ok = 1;
    for (uint32_t i = 0; i < len; i++) {
        if (decrypted[i] != plaintext[i]) { all_ok = 0; break; }
    }
    tests_run++;
    uart_puts("    decrypt(encrypt(plaintext)) == plaintext (");
    uart_putu(len);
    uart_puts(" bytes, 3 bloques): ");
    if (all_ok) {
        uart_puts("[PASS]\n");
        tests_passed++;
    } else {
        uart_puts("[FAIL]\n");
    }
}

/* =========================================================================
 * Entry point
 * ========================================================================= */
void main(void) {
    uart_puts("========================================\n");
    uart_puts("  ChaCha20 - RISC-V (RFC 8439)\n");
    uart_puts("========================================\n");

    test_quarter_round_basico();
    test_quarter_round_estado();
    test_chacha20_block();
    test_chacha20_encrypt();
    test_multi_block();

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
