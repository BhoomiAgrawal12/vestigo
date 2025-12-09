/*
    Improved Crypto Detection YARA Rules
    Higher specificity to reduce false positives
    Focused on unique cryptographic constants and combinations
*/

// ======================== AES/Rijndael ========================

rule AES_Sbox {
    meta:
        description = "AES/Rijndael Forward S-Box"
        author = "CryptoDetect"
        algorithm = "AES"
        confidence = 95
    strings:
        // Complete AES S-Box (256 bytes) - highly specific
        $sbox_full = {
            63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76
            CA 82 C9 7D FA 59 47 F0 AD D4 A2 AF 9C A4 72 C0
            B7 FD 93 26 36 3F F7 CC 34 A5 E5 F1 71 D8 31 15
            04 C7 23 C3 18 96 05 9A 07 12 80 E2 EB 27 B2 75
            09 83 2C 1A 1B 6E 5A A0 52 3B D6 B3 29 E3 2F 84
            53 D1 00 ED 20 FC B1 5B 6A CB BE 39 4A 4C 58 CF
            D0 EF AA FB 43 4D 33 85 45 F9 02 7F 50 3C 9F A8
            51 A3 40 8F 92 9D 38 F5 BC B6 DA 21 10 FF F3 D2
            CD 0C 13 EC 5F 97 44 17 C4 A7 7E 3D 64 5D 19 73
            60 81 4F DC 22 2A 90 88 46 EE B8 14 DE 5E 0B DB
            E0 32 3A 0A 49 06 24 5C C2 D3 AC 62 91 95 E4 79
            E7 C8 37 6D 8D D5 4E A9 6C 56 F4 EA 65 7A AE 08
            BA 78 25 2E 1C A6 B4 C6 E8 DD 74 1F 4B BD 8B 8A
            70 3E B5 66 48 03 F6 0E 61 35 57 B9 86 C1 1D 9E
            E1 F8 98 11 69 D9 8E 94 9B 1E 87 E9 CE 55 28 DF
            8C A1 89 0D BF E6 42 68 41 99 2D 0F B0 54 BB 16
        }
        
        // Longer partial match (128 bytes minimum) to reduce false positives
        $sbox_partial = {
            63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76
            CA 82 C9 7D FA 59 47 F0 AD D4 A2 AF 9C A4 72 C0
            B7 FD 93 26 36 3F F7 CC 34 A5 E5 F1 71 D8 31 15
            04 C7 23 C3 18 96 05 9A 07 12 80 E2 EB 27 B2 75
            09 83 2C 1A 1B 6E 5A A0 52 3B D6 B3 29 E3 2F 84
            53 D1 00 ED 20 FC B1 5B 6A CB BE 39 4A 4C 58 CF
            D0 EF AA FB 43 4D 33 85 45 F9 02 7F 50 3C 9F A8
            51 A3 40 8F 92 9D 38 F5 BC B6 DA 21 10 FF F3 D2
        }
    condition:
        any of them
}

rule AES_InvSbox {
    meta:
        description = "AES/Rijndael Inverse S-Box"
        author = "CryptoDetect"
        algorithm = "AES"
        confidence = 95
    strings:
        $inv_sbox = {
            52 09 6A D5 30 36 A5 38 BF 40 A3 9E 81 F3 D7 FB
            7C E3 39 82 9B 2F FF 87 34 8E 43 44 C4 DE E9 CB
            54 7B 94 32 A6 C2 23 3D EE 4C 95 0B 42 FA C3 4E
            08 2E A1 66 28 D9 24 B2 76 5B A2 49 6D 8B D1 25
            72 F8 F6 64 86 68 98 16 D4 A4 5C CC 5D 65 B6 92
            6C 70 48 50 FD ED B9 DA 5E 15 46 57 A7 8D 9D 84
            90 D8 AB 00 8C BC D3 0A F7 E4 58 05 B8 B3 45 06
            D0 2C 1E 8F CA 3F 0F 02 C1 AF BD 03 01 13 8A 6B
        }
    condition:
        $inv_sbox
}

rule AES_Combined_Indicators {
    meta:
        description = "Multiple AES indicators for higher confidence"
        author = "CryptoDetect"
        algorithm = "AES"
        confidence = 98
    strings:
        $rcon = { 01 02 04 08 10 20 40 80 1B 36 }
        $sbox_start = { 63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76 }
        $te0 = { C6 63 63 A5 F8 7C 7C 84 }
    condition:
        2 of them
}

// ======================== DES ========================

rule DES_Complete {
    meta:
        description = "DES S-Boxes and Permutation Tables"
        author = "CryptoDetect"
        algorithm = "DES/3DES"
        confidence = 95
    strings:
        // DES S-Box 1 (complete)
        $sbox1 = {
            0E 04 0D 01 02 0F 0B 08 03 0A 06 0C 05 09 00 07
            00 0F 07 04 0E 02 0D 01 0A 06 0C 0B 09 05 03 08
            04 01 0E 08 0D 06 02 0B 0F 0C 09 07 03 0A 05 00
            0F 0C 08 02 04 09 01 07 05 0B 03 0E 0A 00 06 0D
        }
        
        // DES Initial Permutation
        $ip = {
            3A 32 2A 22 1A 12 0A 02 3C 34 2C 24 1C 14 0C 04
            3E 36 2E 26 1E 16 0E 06 40 38 30 28 20 18 10 08
        }
        
        // DES PC1 permutation
        $pc1 = {
            39 31 29 21 19 11 09 01 3A 32 2A 22 1A 12 0A 02
        }
    condition:
        any of them
}

// ======================== SHA Family ========================

rule SHA1_Constants {
    meta:
        description = "SHA-1 Initialization Vector and Constants"
        author = "CryptoDetect"
        algorithm = "SHA-1"
        confidence = 95
    strings:
        // SHA-1 IV (H0-H4) in big-endian - full constant
        $h_be = { 67 45 23 01 EF CD AB 89 98 BA DC FE 10 32 54 76 C3 D2 E1 F0 }
        
        // SHA-1 IV in little-endian
        $h_le = { 01 23 45 67 89 AB CD EF FE DC BA 98 76 54 32 10 F0 E1 D2 C3 }
        
        // Combination of K constants (more specific)
        $k_combo = { 5A 82 79 99 [0-16] 6E D9 EB A1 }
    condition:
        any of them
}

rule SHA256_Constants {
    meta:
        description = "SHA-256 Initial Hash Values and Round Constants"
        author = "CryptoDetect"
        algorithm = "SHA-256"
        confidence = 95
    strings:
        // SHA-256 IV (H0-H7) - complete 32 bytes
        $h_be = {
            6A 09 E6 67 BB 67 AE 85 3C 6E F3 72 A5 4F F5 3A
            51 0E 52 7F 9B 05 68 8C 1F 83 D9 AB 5B E0 CD 19
        }
        
        // First 16 K constants (64 bytes) - much more specific
        $k_extended = {
            42 8A 2F 98 71 37 44 91 B5 C0 FB CF E9 B5 DB A5
            39 56 C2 5B 59 F1 11 F1 92 3F 82 A4 AB 1C 5E D5
            D8 07 AA 98 12 83 5B 01 24 31 85 BE 55 0C 7D C3
            72 BE 5D 74 80 DE B1 FE 9B DC 06 A7 C1 9B F1 74
        }
    condition:
        any of them
}

rule SHA512_Constants {
    meta:
        description = "SHA-512 Initial Hash Values"
        author = "CryptoDetect"
        algorithm = "SHA-512"
        confidence = 95
    strings:
        // SHA-512 IV (H0-H7) - first 32 bytes is unique enough
        $h_be = {
            6A 09 E6 67 F3 BC C9 08 BB 67 AE 85 84 CA A7 3B
            3C 6E F3 72 FE 94 F8 2B A5 4F F5 3A 5F 1D 36 F1
        }
        
        // Complete first two H values (16 bytes)
        $h_full_start = {
            6A 09 E6 67 F3 BC C9 08 BB 67 AE 85 84 CA A7 3B
        }
    condition:
        any of them
}

// ======================== MD5 ========================

rule MD5_Constants {
    meta:
        description = "MD5 Initialization Vector"
        author = "CryptoDetect"
        algorithm = "MD5"
        confidence = 95
    strings:
        // MD5 IV in little-endian (complete 16 bytes)
        $iv_le = { 01 23 45 67 89 AB CD EF FE DC BA 98 76 54 32 10 }
        
        // MD5 IV in big-endian
        $iv_be = { 67 45 23 01 EF CD AB 89 98 BA DC FE 10 32 54 76 }
    condition:
        any of them
}

// ======================== ChaCha20 / Salsa20 ========================

rule ChaCha20_Constants {
    meta:
        description = "ChaCha20 Magic Constants"
        author = "CryptoDetect"
        algorithm = "ChaCha20"
        confidence = 100
    strings:
        // "expand 32-byte k" in little-endian (complete constant)
        $magic_32 = { 65 78 70 61 6E 64 20 33 32 2D 62 79 74 65 20 6B }
        
        // "expand 16-byte k"
        $magic_16 = { 65 78 70 61 6E 64 20 31 36 2D 62 79 74 65 20 6B }
    condition:
        any of them
}

rule Salsa20_Constants {
    meta:
        description = "Salsa20 Magic Constants"
        author = "CryptoDetect"
        algorithm = "Salsa20"
        confidence = 100
    strings:
        $magic_32 = { 65 78 70 61 6E 64 20 33 32 2D 62 79 74 65 20 6B }
        $magic_16 = { 65 78 70 61 6E 64 20 31 36 2D 62 79 74 65 20 6B }
    condition:
        any of them
}

// ======================== RC4 ========================

rule RC4_Identity_Permutation {
    meta:
        description = "RC4 Identity Permutation (extended for specificity)"
        author = "CryptoDetect"
        algorithm = "RC4/ARC4"
        confidence = 90
    strings:
        // Extended to 64 bytes for higher confidence
        $identity_64 = {
            00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
            10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F
            20 21 22 23 24 25 26 27 28 29 2A 2B 2C 2D 2E 2F
            30 31 32 33 34 35 36 37 38 39 3A 3B 3C 3D 3E 3F
        }
        
        // Or at least 32 bytes
        $identity_32 = {
            00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
            10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F
        }
    condition:
        any of them
}

// ======================== Blowfish ========================

rule Blowfish_PArray {
    meta:
        description = "Blowfish P-Array Initial Values (extended)"
        author = "CryptoDetect"
        algorithm = "Blowfish"
        confidence = 95
    strings:
        // Extended P-array (32 bytes minimum)
        $parray_ext = {
            24 3F 6A 88 85 A3 08 D3 13 19 8A 2E 03 70 73 44
            A4 09 38 22 29 9F 31 D0 08 2E FA 98 EC 4E 6C 89
        }
    condition:
        $parray_ext
}

// ======================== RSA / Big Number (FIXED) ========================

rule RSA_PublicExponent_Context {
    meta:
        description = "RSA Public Exponents with additional context"
        author = "CryptoDetect"
        algorithm = "RSA"
        confidence = 85
    strings:
        // Look for 65537 near ASN.1 INTEGER tags or modulus patterns
        // RSA public key in DER format context
        $asn1_seq = { 30 [1-2] 30 0D 06 09 2A 86 48 86 F7 0D 01 01 01 }
        
        // Common RSA key structure patterns
        $pubkey_header = { 30 82 [2] 30 0D }
        
        // e=65537 in ASN.1 INTEGER format (proper encoding)
        $e_65537_asn1 = { 02 03 01 00 01 }
        
        // Large modulus indicator (RSA keys are typically 2048-4096 bits)
        $modulus_size = { 02 82 01 01 } // 257 byte integer
        $modulus_size2 = { 02 82 02 01 } // 513 byte integer
    condition:
        // Require ASN.1 context + exponent, or modulus size indicator
        ($asn1_seq or $pubkey_header) and $e_65537_asn1
        or
        ($modulus_size or $modulus_size2) and $e_65537_asn1
}

// ======================== Elliptic Curve ========================

rule ECC_NIST_P256 {
    meta:
        description = "NIST P-256 Curve Parameters (extended)"
        author = "CryptoDetect"
        algorithm = "ECC-P256"
        confidence = 90
    strings:
        // P-256 prime field (complete 32 bytes)
        $p256_p = {
            FF FF FF FF 00 00 00 01 00 00 00 00 00 00 00 00
            00 00 00 00 FF FF FF FF FF FF FF FF FF FF FF FF
        }
        
        // P-256 order n (complete 32 bytes)
        $p256_n = {
            FF FF FF FF 00 00 00 00 FF FF FF FF FF FF FF FF
            BC E6 FA AD A7 17 9E 84 F3 B9 CA C2 FC 63 25 51
        }
        
        // P-256 generator point X coordinate
        $p256_gx = {
            6B 17 D1 F2 E1 2C 42 47 F8 BC E6 E5 63 A4 40 F2
            77 03 7D 81 2D EB 33 A0 F4 A1 39 45 D8 98 C2 96
        }
    condition:
        any of them
}

rule ECC_NIST_P384 {
    meta:
        description = "NIST P-384 Curve Parameters"
        author = "CryptoDetect"
        algorithm = "ECC-P384"
        confidence = 90
    strings:
        // P-384 prime (first 24 bytes)
        $p384_p = {
            FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
            FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FE
        }
    condition:
        $p384_p
}

// ======================== HMAC ========================

rule HMAC_IPAD_OPAD {
    meta:
        description = "HMAC Inner/Outer Padding (extended for specificity)"
        author = "CryptoDetect"
        algorithm = "HMAC"
        confidence = 80
    strings:
        // Extended IPAD (32 bytes)
        $ipad_ext = {
            36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36
            36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36
        }
        
        // Extended OPAD (32 bytes)
        $opad_ext = {
            5C 5C 5C 5C 5C 5C 5C 5C 5C 5C 5C 5C 5C 5C 5C 5C
            5C 5C 5C 5C 5C 5C 5C 5C 5C 5C 5C 5C 5C 5C 5C 5C
        }
    condition:
        any of them
}

// ======================== CRC / Checksums ========================

rule CRC32_Table {
    meta:
        description = "CRC32 Lookup Table"
        author = "CryptoDetect"
        algorithm = "CRC32"
        confidence = 85
    strings:
        // First 8 entries of CRC32 table (32 bytes)
        $crc32_table = {
            00 00 00 00 96 30 07 77 2C 61 0E EE BA 51 09 99
            19 C4 6D 07 8F F4 6A 70 35 A5 63 E9 A3 95 64 9E
        }
    condition:
        $crc32_table
}

// ======================== Combined Detection Rules ========================

rule Multiple_Crypto_Algorithms {
    meta:
        description = "Multiple cryptographic algorithms detected"
        author = "CryptoDetect"
        confidence = 95
    strings:
        $aes_sbox = { 63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76 }
        $sha256_iv = { 6A 09 E6 67 BB 67 AE 85 3C 6E F3 72 A5 4F F5 3A }
        $md5_iv = { 01 23 45 67 89 AB CD EF FE DC BA 98 76 54 32 10 }
        $chacha_magic = { 65 78 70 61 6E 64 20 33 32 2D 62 79 74 65 20 6B }
    condition:
        2 of them
}