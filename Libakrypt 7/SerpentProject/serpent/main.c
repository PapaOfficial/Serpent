#include <stdio.h>
#include <libakrypt.h>
#include <sys/types.h>
#include <ak_bckey.h>
#include "serpent.h"




int main() {
    
    struct bckey key;
    ak_uint8 out[32];
    ak_uint8 out1[32];
    
    ak_uint8 in[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
        0x1c, 0x1d, 0x1e, 0x1f};
        
    ak_uint8 const_key[32] = {
        0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x1c, 0x1d, 0x1e, 0x1f};
    
    
    ak_libakrypt_create(ak_function_log_stderr);
    
    printf("%s\n", "Ключ:");
    for(int i = 0; i < 32; i++){printf(" %02X", const_key[i]);}
    printf("\n");
    
    ak_bckey_context_create_serpent(&key);
    
    ak_bckey_context_set_key(&key, const_key, 32, ak_true);
    
    printf("%s\n", "Открытый текст:");
    for(int i = 0; i < 32; i++){printf(" %02X", in[i]);}
    printf("\n");
    
    ak_bckey_context_encrypt_ecb(&key, in, out, sizeof(in));
    
    ak_bckey_context_decrypt_ecb(&key, out, out1, sizeof(out));
    
    printf("%s\n", "Расшифрованный текст после зашифрования открытого текста:");
    for(int i = 0; i < 32; i++){printf(" %02X", out1[i]);}
    printf("\n");
    
    ak_bckey_context_destroy(&key);
    ak_libakrypt_destroy();
        
    return 0;
}


