#pragma once

unsigned char xor_key = 0x55;

// XOR-encoded string: "calc.exe"
unsigned char xor_calc_exe[] = {
    0x36, 0x30, 0x39, 0x36, 0x1b, 0x3d, 0x31, 0x30, 0x00
};

// Función para decodificar la string en runtime
void decode_xor_string(unsigned char* str) {
    for (int i = 0; str[i] != 0x00; i++) {
        str[i] ^= xor_key;
    }
}