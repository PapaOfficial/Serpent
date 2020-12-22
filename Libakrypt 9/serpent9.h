
#ifndef serpent_h
#define serpent_h

#include <libakrypt-internal.h>



//освобождение памяти, занимаемой развернутыми ключами алгоритма serpent
static int ak_serpent_delete_keys(ak_skey skey){
    int error = ak_error_ok;
    //выполняем стандартные проверки
    if( skey == NULL ) return ak_error_message( ak_error_null_pointer,
                                                   __func__ , "using a null pointer to secret key" );
    
    if( skey->data != NULL ) {
     //теперь очистка и освобождение памяти
      if(( error = ak_ptr_wipe( skey->data, 544, &skey->generator )) != ak_error_ok ) {
        ak_error_message( error, __func__, "incorrect wiping an internal data" );
        memset( skey->data, 0, 544);
      }
      free( skey->data );
      skey->data = NULL;
    }
   return error;
}




//развертка ключей для алгоритма serpent
static int ak_serpent_schedule_keys(ak_skey skey){
    //стандартные проверки
    if( skey == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                              "using a null pointer to secret key" );
    if( skey->key_size != 32 ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                                "unsupported length of secret key" );
    
    //проверяем целостность ключа
    if( skey->check_icode( skey ) != ak_true ) return ak_error_message( ak_error_wrong_key_icode,
                                                  __func__ , "using key with wrong integrity code" );
    
    //удаляем былое
    if( skey->data != NULL ) ak_serpent_delete_keys( skey );
    
    //далее, по-возможности, выделяем выравненную память
    if(( skey->data = ak_aligned_malloc(544)) == NULL )
      return ak_error_message( ak_error_out_of_memory, __func__ ,
                                                               "wrong allocation of internal data" );
    
    //дальше сама развертка ключей
    ak_uint32 f = 0x9e3779b9;
    ak_uint32 w[140];
    ak_uint32* lkey = (ak_uint32*)skey->key;
    ak_uint32* rkey = (ak_uint32*)(skey->key + skey->key_size);
    
    w[0] = lkey[0]^rkey[0];
    w[1] = lkey[1]^rkey[1];
    w[2] = lkey[2]^rkey[2];
    w[3] = lkey[3]^rkey[3];
    w[4] = lkey[4]^rkey[4];
    w[5] = lkey[5]^rkey[5];
    w[6] = lkey[6]^rkey[6];
    w[7] = lkey[7]^rkey[7];
    
    for (int i = 8; i < 140; ++i){
        w[i] = (w[i-8]^w[i-5]^w[i-3]^w[i-1]^f^i);
        w[i] = (w[i] << 11) | (w[i] >> 21);
    }
    
    ak_uint32* key = (ak_uint32*)skey->data;
    
    for (int i = 0; i < 132; ++i){
        key[i] = w[i+8];
    }
    
    return ak_error_ok;
}




//зашифрование одного блока информации шифром serpent
static void ak_serpent_encrypt(ak_skey skey, ak_pointer in, ak_pointer out){
    ak_uint64 x[2];
    x[0] = ((ak_uint64*) in)[0];
    x[1] = ((ak_uint64*) in)[1];
    ak_uint32* a = (ak_uint32*) x;
    ak_uint8* b = (ak_uint8*) x;
    
    ak_uint64* key = (ak_uint64*)skey->data;
    
    int i, j;
    
    //начальная перестановка
    ak_uint32 p[4] = {0};
    p[0] |= ((a[0] >> 0) & 0x1) << 0;
    p[3] |= ((a[3] >> 31) & 0x1) << 31;
    for (i = 1; i < 127; ++i){
        p[i/32] |= ((a[((i*32)%127)/32] >> (((i*32)%127)%32)) & 1) << (i%32);
    }
    a[0] = p[0];
    a[1] = p[1];
    a[2] = p[2];
    a[3] = p[3];
    
    
    //таблица замены
    ak_int8 S[8][16] = {{3,8,15,1,10,6,5,11,14,13,4,2,7,0,9,12},
                        {15,12,2,7,9,0,5,10,1,11,14,8,6,13,3,4},
                        {8,6,7,9,3,12,10,15,13,1,14,4,0,11,5,2},
                        {0,15,11,8,12,9,6,3,13,1,2,4,10,7,5,14},
                        {1,15,8,3,12,0,11,6,2,5,4,10,9,14,7,13},
                        {15,5,2,11,4,10,9,12,0,3,14,8,13,6,7,1},
                        {7,2,12,5,8,4,6,11,14,9,1,15,13,3,10,0},
                        {1,13,15,0,14,8,2,11,7,4,12,10,9,3,5,6}};
    
    
    //раунды 0-30
    for (i = 0; i < 31; ++i){
        
        //сложение по модулю 2 с раундовым ключом
        x[0] = x[0] ^ key[i*2];
        x[1] = x[1] ^ key[i*2 + 1];
        
        //табличная замена
        for (j = 0; j < 16; ++j){
            b[j] = S[i % 8][b[j] % 16] + 16 * (S[i % 8][b[j] / 16]);
        }
        
        //линейное преобразование
        a[0] = (a[0] << 13) | (a[0] >> 19);
        a[2] = (a[2] << 3) | (a[2] >> 29);
        a[1] = a[1] ^ a[0] ^ a[2];
        a[3] = a[3] ^ a[2] ^ (a[0] << 3);
        a[1] = (a[1] << 1) | (a[1] >> 31);
        a[3] = (a[3] << 7) | (a[3] >> 25);
        a[0] = a[0] ^ a[1] ^ a[3];
        a[2] = a[2] ^ a[3] ^ (a[1] << 7);
        a[0] = (a[0] << 5) | (a[0] >> 27);
        a[2] = (a[2] << 22) | (a[2] >> 10);
    }
    
    //раунд 31
    x[0] = x[0] ^ key[62];
    x[1] = x[1] ^ key[63];
    for (j = 0; j < 16; ++j){
        b[j] = S[7][b[j] % 16] + 16 * (S[7][b[j] / 16]);
    }
    x[0] = x[0] ^ key[64];
    x[1] = x[1] ^ key[65];
    
    
    //конечная перестановка
    ak_uint32 fp[4] = {0};
    fp[0] |= ((a[0] >> 0) & 0x1) << 0;
    fp[3] |= ((a[3] >> 31) & 0x1) << 31;
    for (i = 1; i < 127; ++i){
        fp[i/32] |= ((a[((i*4)%127)/32] >> (((i*4)%127)%32)) & 1) << (i%32);
    }
    a[0] = fp[0];
    a[1] = fp[1];
    a[2] = fp[2];
    a[3] = fp[3];
    
    
    //на выход
    ((ak_uint64*) out)[0] = x[0];
    ((ak_uint64*) out)[1] = x[1];
    
}



//расшифрование одного блока информации шифра serpent
static void ak_serpent_decrypt(ak_skey skey, ak_pointer in, ak_pointer out){
    ak_uint64 x[2];
    x[0] = ((ak_uint64*) in)[0];
    x[1] = ((ak_uint64*) in)[1];
    ak_uint32* a = (ak_uint32*) x;
    ak_uint8* b = (ak_uint8*) x;
    
    ak_uint64* key = (ak_uint64*)skey->data;
    
    int i, j;
    
    //начальная перестановка
    ak_uint32 p[4] = {0};
    p[0] |= ((a[0] >> 0) & 0x1) << 0;
    p[3] |= ((a[3] >> 31) & 0x1) << 31;
    for (i = 0; i < 127; ++i){
        p[((4*i)%127)/32] |= ((a[i/32] >> (i%32)) & 1) << (((4*i)%127)%32);
    }
    a[0] = p[0];
    a[1] = p[1];
    a[2] = p[2];
    a[3] = p[3];
    
    
    //инверсная таблица замены
    ak_int8 InvS[8][16] = {{13,3,11,0,10,6,5,12,1,14,4,7,15,9,8,2},
                           {5,8,2,14,15,6,12,3,11,4,7,9,1,13,10,0},
                           {12,9,15,4,11,14,1,2,0,3,6,13,5,8,10,7},
                           {0,9,10,7,11,14,6,13,3,5,12,2,4,8,15,1},
                           {5,0,8,3,10,9,7,14,2,12,11,6,4,15,13,1},
                           {8,15,2,9,4,1,13,14,11,6,5,3,7,12,10,0},
                           {15,10,1,13,5,3,6,0,4,9,14,7,2,12,8,11},
                           {3,0,6,13,9,14,15,8,5,12,11,7,10,1,4,2}};
    
    
    //раунд 0 расшифрования
    x[0] = x[0] ^ key[64];
    x[1] = x[1] ^ key[65];
    for (j = 0; j < 16; ++j){
        b[j] = InvS[7][b[j] % 16] + 16 * (InvS[7][b[j] / 16]);
    }
    x[0] = x[0] ^ key[62];
    x[1] = x[1] ^ key[63];
    
    
    //раунды 1-31 расшифрования
    for (i = 1; i < 32; ++i){
        
        //линейное преобразование
        a[2] = (a[2] >> 22) | (a[2] << 10);
        a[0] = (a[0] >> 5) | (a[0] << 27);
        a[2] = a[2] ^ a[3] ^ (a[1] << 7);
        a[0] = a[0] ^ a[1] ^ a[3];
        a[3] = (a[3] >> 7) | (a[3] << 25);
        a[1] = (a[1] >> 1) | (a[1] << 31);
        a[3] = a[3] ^ a[2] ^ (a[0] << 3);
        a[1] = a[1] ^ a[0] ^ a[2];
        a[2] = (a[2] >> 3) | (a[2] << 29);
        a[0] = (a[0] >> 13) | (a[0] << 19);
        
        //табличная замена
        for (j = 0; j < 16; ++j){
            b[j] = InvS[7 - (i % 8)][b[j] % 16] + 16 * (InvS[7 - (i % 8)][b[j] / 16]);
        }
        
        //сложение по модулю 2 с раундовым ключом
        x[0] = x[0] ^ key[62 - i*2];
        x[1] = x[1] ^ key[63 - i*2];
    }
    
    //конечная перестановка
    ak_uint32 fp[4] = {0};
    fp[0] |= ((a[0] >> 0) & 0x1) << 0;
    fp[3] |= ((a[3] >> 31) & 0x1) << 31;
    for (i = 0; i < 127; ++i){
        fp[((32*i)%127)/32] |= ((a[i/32] >> (i%32)) & 1) << (((32*i)%127)%32);
    }
    a[0] = fp[0];
    a[1] = fp[1];
    a[2] = fp[2];
    a[3] = fp[3];
    
    
    //на выход
    ((ak_uint64*) out)[0] = x[0];
    ((ak_uint64*) out)[1] = x[1];
    
}




//инициализация контекста секретного ключа алгоритма блочного шифрования serpent
int ak_bckey_create_serpent(ak_bckey bkey){
    int error = ak_error_ok;
    
    if( bkey == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                 "using null pointer to block cipher key context" );
    
    if(( error = ak_bckey_create( bkey, 32, 16 )) != ak_error_ok )
      return ak_error_message( error, __func__, "wrong initalization of block cipher key context" );
    
    if(( bkey->key.oid = ak_oid_find_by_name( "kuznechik" )) == NULL ) {
      ak_error_message( error = ak_error_get_value(), __func__,
                                          "wrong search of predefined kuznechik block cipher OID" );
      ak_bckey_destroy( bkey );
      return error;
    }
    
    bkey->key.oid->id = "1.3.6.1.4.1.11591.13.2";
    bkey->key.oid->name = "serpent";
    
    bkey->schedule_keys = ak_serpent_schedule_keys;
    bkey->delete_keys = ak_serpent_delete_keys;
    bkey->encrypt = ak_serpent_encrypt;
    bkey->decrypt = ak_serpent_decrypt;
    
    return error;
}



#endif
