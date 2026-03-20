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
 * RFC 8439 Appendix A.1: ChaCha20 Block Functions
 * ========================================================================= */

/* Test Vector #1: All zeros, counter=0 */
static void test_rfc_a1_vec1(void) {
    uart_puts("\n[RFC A.1 Vector #1] Block Function - zeros, counter=0\n");

    static const uint32_t key[8] = {0};
    static const uint32_t nonce[3] = {0};
    static uint32_t output[16];

    chacha20_block(key, 0, nonce, output);

    uart_puts("  Keystream generado:\n");
    uart_print_bytes((uint8_t *)output, 64);

    static const uint32_t expected[16] = {
        0xade0b876, 0x903df1a0, 0xe56a5d40, 0x28bd8653,
        0xb819d2bd, 0x1aed8da0, 0xccef36a8, 0xc70d778b,
        0x7c5941da, 0x8d485751, 0x3fe02477, 0x374ad8b8,
        0xf4b8436a, 0x1ca11815, 0x69b687c3, 0x8665eeb2
    };

    uart_puts("  Verificacion:\n");
    for (int i = 0; i < 16; i++) {
        char label[9] = "word[  ]";
        label[5] = (i < 10) ? ' ' : ('0' + i / 10);
        label[6] = '0' + (i % 10);
        check(label, output[i], expected[i]);
    }
}

/* Test Vector #2: All zeros, counter=1 */
static void test_rfc_a1_vec2(void) {
    uart_puts("\n[RFC A.1 Vector #2] Block Function - zeros, counter=1\n");

    static const uint32_t key[8] = {0};
    static const uint32_t nonce[3] = {0};
    static uint32_t output[16];

    chacha20_block(key, 1, nonce, output);

    uart_puts("  Keystream generado:\n");
    uart_print_bytes((uint8_t *)output, 64);

    static const uint32_t expected[16] = {
        0xbee7079f, 0x7a385155, 0x7c97ba98, 0x0d082d73,
        0xa0290fcb, 0x6965e348, 0x3e53c612, 0xed7aee32,
        0x7621b729, 0x434ee69c, 0xb03371d5, 0xd539d874,
        0x281fed31, 0x45fb0a51, 0x1f0ae1ac, 0x6f4d794b
    };

    uart_puts("  Verificacion:\n");
    for (int i = 0; i < 16; i++) {
        char label[9] = "word[  ]";
        label[5] = (i < 10) ? ' ' : ('0' + i / 10);
        label[6] = '0' + (i % 10);
        check(label, output[i], expected[i]);
    }
}

/* Test Vector #3: Key last byte = 0x01, counter=1 */
static void test_rfc_a1_vec3(void) {
    uart_puts("\n[RFC A.1 Vector #3] Block Function - key[31]=0x01, counter=1\n");

    static const uint32_t key[8] = {
        0, 0, 0, 0, 0, 0, 0, 0x01000000
    };
    static const uint32_t nonce[3] = {0};
    static uint32_t output[16];

    chacha20_block(key, 1, nonce, output);

    uart_puts("  Keystream generado:\n");
    uart_print_bytes((uint8_t *)output, 64);

    static const uint32_t expected[16] = {
        0x2452eb3a, 0x9249f8ec, 0x8d829d9b, 0xddd4ceb1,
        0xe8252083, 0x60818b01, 0xf38422b8, 0x5aaa49c9,
        0xbb00ca8e, 0xda3ba7b4, 0xc4b592d1, 0xfdf2732f,
        0x4436274e, 0x2561b3c8, 0xebdd4aa6, 0xa0136c00
    };

    uart_puts("  Verificacion:\n");
    for (int i = 0; i < 16; i++) {
        char label[9] = "word[  ]";
        label[5] = (i < 10) ? ' ' : ('0' + i / 10);
        label[6] = '0' + (i % 10);
        check(label, output[i], expected[i]);
    }
}

/* Test Vector #4: Key byte[1]=0xff, counter=2 */
static void test_rfc_a1_vec4(void) {
    uart_puts("\n[RFC A.1 Vector #4] Block Function - key[1]=0xff, counter=2\n");

    static const uint32_t key[8] = {
        0x0000ff00, 0, 0, 0, 0, 0, 0, 0
    };
    static const uint32_t nonce[3] = {0};
    static uint32_t output[16];

    chacha20_block(key, 2, nonce, output);

    uart_puts("  Keystream generado:\n");
    uart_print_bytes((uint8_t *)output, 64);

    static const uint32_t expected[16] = {
        0xfb4dd572, 0x4bc42ef1, 0xdf922636, 0x327f1394,
        0xa78dea8f, 0x5e269039, 0xa1bebbc1, 0xcaf09aae,
        0xa25ab213, 0x48a6b46c, 0x1b9d9bcb, 0x092c5be6,
        0x546ca624, 0x1bec45d5, 0x87f47473, 0x96f0992e
    };

    uart_puts("  Verificacion:\n");
    for (int i = 0; i < 16; i++) {
        char label[9] = "word[  ]";
        label[5] = (i < 10) ? ' ' : ('0' + i / 10);
        label[6] = '0' + (i % 10);
        check(label, output[i], expected[i]);
    }
}

/* Test Vector #5: Nonce last byte=0x02, counter=0 */
static void test_rfc_a1_vec5(void) {
    uart_puts("\n[RFC A.1 Vector #5] Block Function - nonce[11]=0x02, counter=0\n");

    static const uint32_t key[8] = {0};
    static const uint32_t nonce[3] = {
        0, 0, 0x02000000
    };
    static uint32_t output[16];

    chacha20_block(key, 0, nonce, output);

    uart_puts("  Keystream generado:\n");
    uart_print_bytes((uint8_t *)output, 64);

    static const uint32_t expected[16] = {
        0x374dc6c2, 0x3736d58c, 0xb904e24a, 0xcd3f93ef,
        0x88228b1a, 0x96a4dfb3, 0x5b76ab72, 0xc727ee54,
        0x0e0e978a, 0xf3145c95, 0x1b748ea8, 0xf786c297,
        0x99c28f5f, 0x628314e8, 0x398a19fa, 0x6ded1b53
    };

    uart_puts("  Verificacion:\n");
    for (int i = 0; i < 16; i++) {
        char label[9] = "word[  ]";
        label[5] = (i < 10) ? ' ' : ('0' + i / 10);
        label[6] = '0' + (i % 10);
        check(label, output[i], expected[i]);
    }
}

/* =========================================================================
 * RFC 8439 Appendix A.2: ChaCha20 Encryption
 * ========================================================================= */

/* Test Vector #1: All zeros plaintext, all zeros key/nonce */
static void test_rfc_a2_vec1(void) {
    uart_puts("\n[RFC A.2 Vector #1] Encryption - zeros plaintext\n");

    static const uint32_t key[8] = {0};
    static const uint32_t nonce[3] = {0};
    static const uint8_t plaintext[64] = {0};
    static uint8_t ciphertext[64];

    chacha20_encrypt(key, 0, nonce, plaintext, ciphertext, 64);

    uart_puts("  Ciphertext generado:\n");
    uart_print_bytes(ciphertext, 64);

    static const uint8_t expected[64] = {
        0x76,0xb8,0xe0,0xad,0xa0,0xf1,0x3d,0x90,0x40,0x5d,0x6a,0xe5,0x53,0x86,0xbd,0x28,
        0xbd,0xd2,0x19,0xb8,0xa0,0x8d,0xed,0x1a,0xa8,0x36,0xef,0xcc,0x8b,0x77,0x0d,0xc7,
        0xda,0x41,0x59,0x7c,0x51,0x57,0x48,0x8d,0x77,0x24,0xe0,0x3f,0xb8,0xd8,0x4a,0x37,
        0x6a,0x43,0xb8,0xf4,0x15,0x18,0xa1,0x1c,0xc3,0x87,0xb6,0x69,0xb2,0xee,0x65,0x86
    };

    uart_puts("  Verificacion:\n");
    int all_ok = 1;
    for (int i = 0; i < 64; i++) {
        if (ciphertext[i] != expected[i]) { all_ok = 0; break; }
    }
    tests_run++;
    uart_puts("    Ciphertext match (64 bytes): ");
    if (all_ok) {
        uart_puts("[PASS]\n");
        tests_passed++;
    } else {
        uart_puts("[FAIL]\n");
    }
}

/* Test Vector #2: "Any submission to the IETF..." */
static void test_rfc_a2_vec2(void) {
    uart_puts("\n[RFC A.2 Vector #2] Encryption - IETF submission text\n");

    static const uint32_t key[8] = {
        0, 0, 0, 0, 0, 0, 0, 0x01000000
    };
    static const uint32_t nonce[3] = {
        0, 0, 0x02000000
    };

    static const uint8_t plaintext[375] = {
        0x41,0x6e,0x79,0x20,0x73,0x75,0x62,0x6d,0x69,0x73,0x73,0x69,0x6f,0x6e,0x20,0x74,
        0x6f,0x20,0x74,0x68,0x65,0x20,0x49,0x45,0x54,0x46,0x20,0x69,0x6e,0x74,0x65,0x6e,
        0x64,0x65,0x64,0x20,0x62,0x79,0x20,0x74,0x68,0x65,0x20,0x43,0x6f,0x6e,0x74,0x72,
        0x69,0x62,0x75,0x74,0x6f,0x72,0x20,0x66,0x6f,0x72,0x20,0x70,0x75,0x62,0x6c,0x69,
        0x63,0x61,0x74,0x69,0x6f,0x6e,0x20,0x61,0x73,0x20,0x61,0x6c,0x6c,0x20,0x6f,0x72,
        0x20,0x70,0x61,0x72,0x74,0x20,0x6f,0x66,0x20,0x61,0x6e,0x20,0x49,0x45,0x54,0x46,
        0x20,0x49,0x6e,0x74,0x65,0x72,0x6e,0x65,0x74,0x2d,0x44,0x72,0x61,0x66,0x74,0x20,
        0x6f,0x72,0x20,0x52,0x46,0x43,0x20,0x61,0x6e,0x64,0x20,0x61,0x6e,0x79,0x20,0x73,
        0x74,0x61,0x74,0x65,0x6d,0x65,0x6e,0x74,0x20,0x6d,0x61,0x64,0x65,0x20,0x77,0x69,
        0x74,0x68,0x69,0x6e,0x20,0x74,0x68,0x65,0x20,0x63,0x6f,0x6e,0x74,0x65,0x78,0x74,
        0x20,0x6f,0x66,0x20,0x61,0x6e,0x20,0x49,0x45,0x54,0x46,0x20,0x61,0x63,0x74,0x69,
        0x76,0x69,0x74,0x79,0x20,0x69,0x73,0x20,0x63,0x6f,0x6e,0x73,0x69,0x64,0x65,0x72,
        0x65,0x64,0x20,0x61,0x6e,0x20,0x22,0x49,0x45,0x54,0x46,0x20,0x43,0x6f,0x6e,0x74,
        0x72,0x69,0x62,0x75,0x74,0x69,0x6f,0x6e,0x22,0x2e,0x20,0x53,0x75,0x63,0x68,0x20,
        0x73,0x74,0x61,0x74,0x65,0x6d,0x65,0x6e,0x74,0x73,0x20,0x69,0x6e,0x63,0x6c,0x75,
        0x64,0x65,0x20,0x6f,0x72,0x61,0x6c,0x20,0x73,0x74,0x61,0x74,0x65,0x6d,0x65,0x6e,
        0x74,0x73,0x20,0x69,0x6e,0x20,0x49,0x45,0x54,0x46,0x20,0x73,0x65,0x73,0x73,0x69,
        0x6f,0x6e,0x73,0x2c,0x20,0x61,0x73,0x20,0x77,0x65,0x6c,0x6c,0x20,0x61,0x73,0x20,
        0x77,0x72,0x69,0x74,0x74,0x65,0x6e,0x20,0x61,0x6e,0x64,0x20,0x65,0x6c,0x65,0x63,
        0x74,0x72,0x6f,0x6e,0x69,0x63,0x20,0x63,0x6f,0x6d,0x6d,0x75,0x6e,0x69,0x63,0x61,
        0x74,0x69,0x6f,0x6e,0x73,0x20,0x6d,0x61,0x64,0x65,0x20,0x61,0x74,0x20,0x61,0x6e,
        0x79,0x20,0x74,0x69,0x6d,0x65,0x20,0x6f,0x72,0x20,0x70,0x6c,0x61,0x63,0x65,0x2c,
        0x20,0x77,0x68,0x69,0x63,0x68,0x20,0x61,0x72,0x65,0x20,0x61,0x64,0x64,0x72,0x65,
        0x73,0x73,0x65,0x64,0x20,0x74,0x6f
    };
    static uint8_t ciphertext[375];

    chacha20_encrypt(key, 1, nonce, plaintext, ciphertext, 375);

    uart_puts("  Ciphertext generado:\n");
    uart_print_bytes(ciphertext, 375);

    static const uint8_t expected[375] = {
        0xa3,0xfb,0xf0,0x7d,0xf3,0xfa,0x2f,0xde,0x4f,0x37,0x6c,0xa2,0x3e,0x82,0x73,0x70,
        0x41,0x60,0x5d,0x9f,0x4f,0x4f,0x57,0xbd,0x8c,0xff,0x2c,0x1d,0x4b,0x79,0x55,0xec,
        0x2a,0x97,0x94,0x8b,0xd3,0x72,0x29,0x15,0xc8,0xf3,0xd3,0x37,0xf7,0xd3,0x70,0x05,
        0x0e,0x9e,0x96,0xd6,0x47,0xb7,0xc3,0x9f,0x56,0xe0,0x31,0xca,0x5e,0xb6,0x25,0x0d,
        0x40,0x42,0xe0,0x27,0x85,0xec,0xec,0xfa,0x4b,0x4b,0xb5,0xe8,0xea,0xd0,0x44,0x0e,
        0x20,0xb6,0xe8,0xdb,0x09,0xd8,0x81,0xa7,0xc6,0x13,0x2f,0x42,0x0e,0x52,0x79,0x50,
        0x42,0xbd,0xfa,0x77,0x73,0xd8,0xa9,0x05,0x14,0x47,0xb3,0x29,0x1c,0xe1,0x41,0x1c,
        0x68,0x04,0x65,0x55,0x2a,0xa6,0xc4,0x05,0xb7,0x76,0x4d,0x5e,0x87,0xbe,0xa8,0x5a,
        0xd0,0x0f,0x84,0x49,0xed,0x8f,0x72,0xd0,0xd6,0x62,0xab,0x05,0x26,0x91,0xca,0x66,
        0x42,0x4b,0xc8,0x6d,0x2d,0xf8,0x0e,0xa4,0x1f,0x43,0xab,0xf9,0x37,0xd3,0x25,0x9d,
        0xc4,0xb2,0xd0,0xdf,0xb4,0x8a,0x6c,0x91,0x39,0xdd,0xd7,0xf7,0x69,0x66,0xe9,0x28,
        0xe6,0x35,0x55,0x3b,0xa7,0x6c,0x5c,0x87,0x9d,0x7b,0x35,0xd4,0x9e,0xb2,0xe6,0x2b,
        0x08,0x71,0xcd,0xac,0x63,0x89,0x39,0xe2,0x5e,0x8a,0x1e,0x0e,0xf9,0xd5,0x28,0x0f,
        0xa8,0xca,0x32,0x8b,0x35,0x1c,0x3c,0x76,0x59,0x89,0xcb,0xcf,0x3d,0xaa,0x8b,0x6c,
        0xcc,0x3a,0xaf,0x9f,0x39,0x79,0xc9,0x2b,0x37,0x20,0xfc,0x88,0xdc,0x95,0xed,0x84,
        0xa1,0xbe,0x05,0x9c,0x64,0x99,0xb9,0xfd,0xa2,0x36,0xe7,0xe8,0x18,0xb0,0x4b,0x0b,
        0xc3,0x9c,0x1e,0x87,0x6b,0x19,0x3b,0xfe,0x55,0x69,0x75,0x3f,0x88,0x12,0x8c,0xc0,
        0x8a,0xaa,0x9b,0x63,0xd1,0xa1,0x6f,0x80,0xef,0x25,0x54,0xd7,0x18,0x9c,0x41,0x1f,
        0x58,0x69,0xca,0x52,0xc5,0xb8,0x3f,0xa3,0x6f,0xf2,0x16,0xb9,0xc1,0xd3,0x00,0x62,
        0xbe,0xbc,0xfd,0x2d,0xc5,0xbc,0xe0,0x91,0x19,0x34,0xfd,0xa7,0x9a,0x86,0xf6,0xe6,
        0x98,0xce,0xd7,0x59,0xc3,0xff,0x9b,0x64,0x77,0x33,0x8f,0x3d,0xa4,0xf9,0xcd,0x85,
        0x14,0xea,0x99,0x82,0xcc,0xaf,0xb3,0x41,0xb2,0x38,0x4d,0xd9,0x02,0xf3,0xd1,0xab,
        0x7a,0xc6,0x1d,0xd2,0x9c,0x6f,0x21,0xba,0x5b,0x86,0x2f,0x37,0x30,0xe3,0x7c,0xfd,
        0xc4,0xfd,0x80,0x6c,0x22,0xf2,0x21
    };

    uart_puts("  Verificacion:\n");
    int all_ok = 1;
    for (int i = 0; i < 375; i++) {
        if (ciphertext[i] != expected[i]) { all_ok = 0; break; }
    }
    tests_run++;
    uart_puts("    Ciphertext match (375 bytes): ");
    if (all_ok) {
        uart_puts("[PASS]\n");
        tests_passed++;
    } else {
        uart_puts("[FAIL]\n");
    }
}

/* Test Vector #3: "'Twas brillig..." (Jabberwocky) */
static void test_rfc_a2_vec3(void) {
    uart_puts("\n[RFC A.2 Vector #3] Encryption - Jabberwocky, counter=42\n");

    static const uint32_t key[8] = {
        0xa540921c, 0x8ad355eb, 0x868833f3, 0xf0b5f604,
        0xc1173947, 0x09802b40, 0xbc5cca9d, 0xc0757020
    };
    static const uint32_t nonce[3] = {
        0, 0, 0x02000000
    };

    static const uint8_t plaintext[127] = {
        0x27,0x54,0x77,0x61,0x73,0x20,0x62,0x72,0x69,0x6c,0x6c,0x69,0x67,0x2c,0x20,0x61,
        0x6e,0x64,0x20,0x74,0x68,0x65,0x20,0x73,0x6c,0x69,0x74,0x68,0x79,0x20,0x74,0x6f,
        0x76,0x65,0x73,0x0a,0x44,0x69,0x64,0x20,0x67,0x79,0x72,0x65,0x20,0x61,0x6e,0x64,
        0x20,0x67,0x69,0x6d,0x62,0x6c,0x65,0x20,0x69,0x6e,0x20,0x74,0x68,0x65,0x20,0x77,
        0x61,0x62,0x65,0x3a,0x0a,0x41,0x6c,0x6c,0x20,0x6d,0x69,0x6d,0x73,0x79,0x20,0x77,
        0x65,0x72,0x65,0x20,0x74,0x68,0x65,0x20,0x62,0x6f,0x72,0x6f,0x67,0x6f,0x76,0x65,
        0x73,0x2c,0x0a,0x41,0x6e,0x64,0x20,0x74,0x68,0x65,0x20,0x6d,0x6f,0x6d,0x65,0x20,
        0x72,0x61,0x74,0x68,0x73,0x20,0x6f,0x75,0x74,0x67,0x72,0x61,0x62,0x65,0x2e
    };
    static uint8_t ciphertext[127];

    chacha20_encrypt(key, 42, nonce, plaintext, ciphertext, 127);

    uart_puts("  Plaintext:\n");
    uart_print_ascii(plaintext, 127);

    uart_puts("\n  Ciphertext generado:\n");
    uart_print_bytes(ciphertext, 127);

    static const uint8_t expected[127] = {
        0x62,0xe6,0x34,0x7f,0x95,0xed,0x87,0xa4,0x5f,0xfa,0xe7,0x42,0x6f,0x27,0xa1,0xdf,
        0x5f,0xb6,0x91,0x10,0x04,0x4c,0x0d,0x73,0x11,0x8e,0xff,0xa9,0x5b,0x01,0xe5,0xcf,
        0x16,0x6d,0x3d,0xf2,0xd7,0x21,0xca,0xf9,0xb2,0x1e,0x5f,0xb1,0x4c,0x61,0x68,0x71,
        0xfd,0x84,0xc5,0x4f,0x9d,0x65,0xb2,0x83,0x19,0x6c,0x7f,0xe4,0xf6,0x05,0x53,0xeb,
        0xf3,0x9c,0x64,0x02,0xc4,0x22,0x34,0xe3,0x2a,0x35,0x6b,0x3e,0x76,0x43,0x12,0xa6,
        0x1a,0x55,0x32,0x05,0x57,0x16,0xea,0xd6,0x96,0x25,0x68,0xf8,0x7d,0x3f,0x3f,0x77,
        0x04,0xc6,0xa8,0xd1,0xbc,0xd1,0xbf,0x4d,0x50,0xd6,0x15,0x4b,0x6d,0xa7,0x31,0xb1,
        0x87,0xb5,0x8d,0xfd,0x72,0x8a,0xfa,0x36,0x75,0x7a,0x79,0x7a,0xc1,0x88,0xd1
    };

    uart_puts("  Verificacion:\n");
    int all_ok = 1;
    for (int i = 0; i < 127; i++) {
        if (ciphertext[i] != expected[i]) { all_ok = 0; break; }
    }
    tests_run++;
    uart_puts("    Ciphertext match (127 bytes): ");
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

    /* Tests originales */
    test_quarter_round_basico();
    test_quarter_round_estado();
    test_chacha20_block();
    test_chacha20_encrypt();
    test_multi_block();

    /* RFC 8439 Appendix A.1 - Block Functions */
    uart_puts("\n========================================\n");
    uart_puts("  RFC 8439 Appendix A.1 Tests\n");
    uart_puts("========================================\n");
    test_rfc_a1_vec1();
    test_rfc_a1_vec2();
    test_rfc_a1_vec3();
    test_rfc_a1_vec4();
    test_rfc_a1_vec5();

    /* RFC 8439 Appendix A.2 - Encryption */
    uart_puts("\n========================================\n");
    uart_puts("  RFC 8439 Appendix A.2 Tests\n");
    uart_puts("========================================\n");
    test_rfc_a2_vec1();
    test_rfc_a2_vec2();
    test_rfc_a2_vec3();

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
