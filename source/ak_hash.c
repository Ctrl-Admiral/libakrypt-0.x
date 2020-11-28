/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2014 - 2019 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_hash.c                                                                                 */
/*  - содержит реализацию алгоритмов итерационного сжатия                                          */
/* ----------------------------------------------------------------------------------------------- */
 #include <ak_hash.h>
 #include <ak_tools.h>
 #include <ak_parameters.h>
 #include <ak_context_manager.h>

/* ----------------------------------------------------------------------------------------------- */
#ifdef LIBAKRYPT_HAVE_STDLIB_H
 #include <stdlib.h>
#else
 #error Library cannot be compiled without stdlib.h header
#endif
#ifdef LIBAKRYPT_HAVE_STRING_H
 #include <string.h>
#else
 #error Library cannot be compiled without string.h header
#endif

#if defined(_MSC_VER)
#define SHA3_CONST(x) x
#else
#define SHA3_CONST(x) x##L
#endif

/*! Для алгоритма sha3 */
#define SHA3_ROTL64(x, y) \
        (((x) << (y)) | ((x) >> ((sizeof(ak_uint64)*8) - (y))))

/* ----------------------------------------------------------------------------------------------- */
/*                            Реализация функции хеширования SHA-3                                 */
/* ----------------------------------------------------------------------------------------------- */

static const ak_uint64 keccakf_rndc[24] = {
    SHA3_CONST(0x0000000000000001UL), SHA3_CONST(0x0000000000008082UL),
    SHA3_CONST(0x800000000000808aUL), SHA3_CONST(0x8000000080008000UL),
    SHA3_CONST(0x000000000000808bUL), SHA3_CONST(0x0000000080000001UL),
    SHA3_CONST(0x8000000080008081UL), SHA3_CONST(0x8000000000008009UL),
    SHA3_CONST(0x000000000000008aUL), SHA3_CONST(0x0000000000000088UL),
    SHA3_CONST(0x0000000080008009UL), SHA3_CONST(0x000000008000000aUL),
    SHA3_CONST(0x000000008000808bUL), SHA3_CONST(0x800000000000008bUL),
    SHA3_CONST(0x8000000000008089UL), SHA3_CONST(0x8000000000008003UL),
    SHA3_CONST(0x8000000000008002UL), SHA3_CONST(0x8000000000000080UL),
    SHA3_CONST(0x000000000000800aUL), SHA3_CONST(0x800000008000000aUL),
    SHA3_CONST(0x8000000080008081UL), SHA3_CONST(0x8000000000008080UL),
    SHA3_CONST(0x0000000080000001UL), SHA3_CONST(0x8000000080008008UL)
};

static const ak_uint8 keccakf_rotc[24] = {
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62,
    18, 39, 61, 20, 44
};

static const ak_uint8 keccakf_piln[24] = {
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20,
    14, 22, 9, 6, 1
};

/*! \brief Функция перестановок в алгоритме keccak */
static inline void ak_hash_keccakf(ak_uint64 s[25])
{
    int i, j, round;
    ak_uint64 t, bc[5];
    const ak_uint8 keccak_rounds = 24;

    for(round = 0; round < keccak_rounds; round++)
    {
        /* Theta */
        for(i = 0; i < 5; i++)
            bc[i] = s[i] ^ s[i + 5] ^ s[i + 10] ^ s[i + 15] ^ s[i + 20];

        for(i = 0; i < 5; i++) {
            t = bc[(i + 4) % 5] ^ SHA3_ROTL64(bc[(i + 1) % 5], 1);
            for(j = 0; j < 25; j += 5)
                s[j + i] ^= t;
        }

        /* Rho Pi */
        t = s[1];
        for(i = 0; i < 24; i++) {
            j = keccakf_piln[i];
            bc[0] = s[j];
            s[j] = SHA3_ROTL64(t, keccakf_rotc[i]);
            t = bc[0];
        }

        /* Chi */
        for(j = 0; j < 25; j += 5) {
            for(i = 0; i < 5; i++)
                bc[i] = s[j + i];
            for(i = 0; i < 5; i++)
                s[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
        }

        /* Iota */
        s[0] ^= keccakf_rndc[round];
    }
}

/**
 * @brief Обновление контекста хэширования sha-3
 * @param[in, out] cx -- контекст функции хэширования
 * @param[in] in -- Указатель на входные данные, для которых вычисляется хеш-код.
 * @param[in] len -- длина сообщения
 * @return В случае успеха функция возвращает ноль (\ref ak_error_ok). В противном случае
    возвращается код ошибки.
 */
int ak_hash_context_update_sha3( ak_pointer cx, const void* in, size_t len)
{
    ak_sha3 ctx = (ak_sha3) cx;

    if( ctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                 "using null pointer to internal sha3 context" );

    /* Сколько осталось необработанного сообщения */
    unsigned old_tail = (8 - ctx->byteIndex) & 7;

    size_t words;
    unsigned tail;
    size_t i;

    const ak_uint8 *buf = in;

    if(len < old_tail)
    {
        while (len--)
            ctx->saved |= (ak_uint64) (*(buf++)) << ((ctx->byteIndex++) * 8);
        return ak_error_ok;
    }

    if(old_tail)
    {
        len -= old_tail;
        while (old_tail--)
            ctx->saved |= (ak_uint64) (*(buf++)) << ((ctx->byteIndex++) * 8);

        ctx->s[ctx->wordIndex] ^= ctx->saved;
        ctx->byteIndex = 0;
        ctx->saved = 0;

        if(++ctx->wordIndex == (SHA3_KECCAK_SPONGE_WORDS - ctx->capacityWords))
        {
            ak_hash_keccakf(ctx->s);
            ctx->wordIndex = 0;
        }
    }

    words = len / sizeof(ak_uint64);
    tail = len - words * sizeof(ak_uint64);

    for(i = 0; i < words; i++, buf += sizeof(ak_uint64))
    {
        const ak_uint64 t = (ak_uint64) (buf[0]) |
                 ((ak_uint64) (buf[1]) << 8 * 1) |
                 ((ak_uint64) (buf[2]) << 8 * 2) |
                 ((ak_uint64) (buf[3]) << 8 * 3) |
                 ((ak_uint64) (buf[4]) << 8 * 4) |
                 ((ak_uint64) (buf[5]) << 8 * 5) |
                 ((ak_uint64) (buf[6]) << 8 * 6) |
                 ((ak_uint64) (buf[7]) << 8 * 7);

        ctx->s[ctx->wordIndex] ^= t;

        if(++ctx->wordIndex == (SHA3_KECCAK_SPONGE_WORDS - ctx->capacityWords))
        {
            ak_hash_keccakf(ctx->s);
            ctx->wordIndex = 0;
        }
    }

    while (tail--)
    {
        ctx->saved |= (ak_uint64) (*(buf++)) << ((ctx->byteIndex++) * 8);
    }
    return ak_error_ok;
}

/**
 * @param[in] cx -- контекст функции хэширования
 * @param[out] out -- Область памяти, куда будет помещен результат.
 * @return В случае успеха функция возвращает ноль (\ref ak_error_ok). В противном случае
    возвращается код ошибки.
 */
int ak_hash_context_finalize_sha3(ak_pointer cx, ak_pointer out)
{
    ak_sha3 ctx = ( ak_sha3 ) cx;
    if( ctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                 "using null pointer to internal sha3 context" );
    if( out == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                 "using null pointer to external result buffer" );
    ak_uint64 t;

    t = (ak_uint64)(((ak_uint64)(0x02 | (1 << 2))) << ((ctx->byteIndex) * 8));

    ctx->s[ctx->wordIndex] ^= ctx->saved ^ t;

    ctx->s[SHA3_KECCAK_SPONGE_WORDS - ctx->capacityWords - 1] ^= SHA3_CONST(0x8000000000000000UL);

    ak_hash_keccakf(ctx->s);

#ifdef LIBAKRYPT_LITTLE_ENDIAN
    {
        unsigned i;
        for(i = 0; i < SHA3_KECCAK_SPONGE_WORDS; i++)
        {
            const unsigned t1 = (ak_uint32) ctx->s[i];
            const unsigned t2 = (ak_uint32) ((ctx->s[i] >> 16) >> 16);
            ctx->sb[i * 8 + 0] = (ak_uint8) (t1);
            ctx->sb[i * 8 + 1] = (ak_uint8) (t1 >> 8);
            ctx->sb[i * 8 + 2] = (ak_uint8) (t1 >> 16);
            ctx->sb[i * 8 + 3] = (ak_uint8) (t1 >> 24);
            ctx->sb[i * 8 + 4] = (ak_uint8) (t2);
            ctx->sb[i * 8 + 5] = (ak_uint8) (t2 >> 8);
            ctx->sb[i * 8 + 6] = (ak_uint8) (t2 >> 16);
            ctx->sb[i * 8 + 7] = (ak_uint8) (t2 >> 24);
        }
    }
#endif
    unsigned outBytes = sizeof(ctx->sb);
    memcpy(out, ctx->sb, outBytes);
    return ak_error_ok;
}

/**
 * @param[in] bitSize -- версия sha-3 (256, 384, 512)
 * @param[in] in -- Указатель на входные данные, для которых вычисляется хеш-код.
 * @param[in] inSize -- размер входных данных
 * @param[out] out Область памяти, куда будет помещен результат.
 * @param[in] outSize -- размер области памяти, куда будет помещен результат
 * @return В случае успеха функция возвращает ноль (\ref ak_error_ok). В противном случае
    возвращается код ошибки.
 */
int ak_hash_context_ptr_sha3( unsigned bitSize, const void* in, size_t inSize, ak_pointer out, size_t outSize )
{
    int error;
    struct sha3_context c;
    ak_uint8 buf[bitSize];
    if(( error = ak_hash_context_create_sha3( &c, bitSize )) != ak_error_ok )
    {
        ak_error_message( error, __func__ , "wrong initialization of sha3 context" );
        return ak_false;
    }
    ak_hash_context_update_sha3(&c, in, inSize);
    ak_hash_context_finalize_sha3(&c, buf);

    if(outSize > bitSize/8) outSize = bitSize/8;
    memcpy(out, buf, outSize);
    return ak_error_ok;
}


/* ----------------------------------------------------------------------------------------------- */
/*                            Реализация функции хеширования Стрибог                               */
/* ----------------------------------------------------------------------------------------------- */
/*! \brief Преобразование LPS.
    \note Мы предполагаем, что данные содержат 64 байта.                                           */
/* ----------------------------------------------------------------------------------------------- */
 static inline void ak_hash_context_streebog_lps( ak_uint64 *result, const ak_uint64 *data )
{
  size_t idx = 0, idx2 = 0;
  const unsigned char *a = ( const unsigned char*) data; /* приводим к массиву байт */

  /* Все три преобразования вместе                           */
  /* (этот очень короткий код был предложен Павлом Лебедевым */
  for( idx = 0; idx < 8; idx++ ) {
    ak_uint64 sidx = idx, c = 0;
    for( idx2 = 0; idx2 < 8; idx2++, sidx += 8 ) {
      c ^= streebog_Areverse_expand[idx2][gost_pi[a[sidx]]];
    }
    result[idx] = c;
  }
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Преобразование X.
    \note Мы предполагаем, что данные содержат 64 байта.                                           */
/* ----------------------------------------------------------------------------------------------- */
 static inline void ak_hash_context_streebog_x( ak_uint64 *r, const ak_uint64 *k, const ak_uint64 *a )
{
  int idx = 0;
  for( idx = 0; idx < 8; idx++ ) r[idx] = k[idx] ^ a[idx];
}


/* ----------------------------------------------------------------------------------------------- */
/*! \brief Преобразование G
    \note Мы предполагаем, что массивы n и m содержат по 64 байта.                                 */
/* ----------------------------------------------------------------------------------------------- */
 static inline void ak_hash_context_streebog_g( ak_streebog ctx, ak_uint64 *n, const ak_uint64 *m )
{
   int idx = 0;
   ak_uint64 K[8], T[8], B[8];

       if( n != NULL ) {
         ak_hash_context_streebog_x( B, ctx->h, n );
         ak_hash_context_streebog_lps( K, B );
       }
        else
         ak_hash_context_streebog_lps( K, ctx->h );

       /* K - ключ K1 */
       for( idx = 0; idx < 8; idx++ ) T[idx] = m[idx]; /* memcpy( T, m, 64 ); */

       for( idx = 0; idx < 12; idx++ ) {
          ak_hash_context_streebog_x( B, T, K );
          ak_hash_context_streebog_lps( T, B ); /* преобразуем текст */

          ak_hash_context_streebog_x( B, K, streebog_c[idx] );
          ak_hash_context_streebog_lps( K, B );   /* новый ключ */
       }
       /* изменяем значение переменной h */
       for ( idx = 0; idx < 8; idx++ ) ctx->h[idx] ^= T[idx] ^ K[idx] ^ m[idx];
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Преобразование Add (увеличение счетчика длины обработаного сообщения).                  */
/* ----------------------------------------------------------------------------------------------- */
 static inline void ak_hash_context_streebog_add( ak_streebog ctx, ak_uint64 size )
{
 #ifdef LIBAKRYPT_LITTLE_ENDIAN
   ak_uint64 tmp = size + ctx->n[0];
   if( tmp < ctx->n[0] ) ctx->n[1]++;
   ctx->n[0] = tmp;  /* такой код позволяет обработать сообщения, длиной не более 2^125 байт */
 #else
     ak_uint64 val = bswap_64( ctx->n[0] ),
               tmp = size + val;
     if( tmp < val ) {
       val = bswap_64( ctx->n[1] );
       val++;
       ctx->n[1] = bswap_64( val );
     }
     ctx->n[0] = bswap_64(tmp);
 #endif
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Преобразование SAdd (Прибавление к массиву S вектора по модулю \f$ 2^{512} \f$).        */
/* ----------------------------------------------------------------------------------------------- */
 static inline void ak_hash_context_streebog_sadd( ak_streebog ctx,  const ak_uint64 *data )
{
   int i = 0;
   ak_uint64 carry = 0;
   for( i = 0; i < 8; i++ )
   {
    #ifdef LIBAKRYPT_LITTLE_ENDIAN
      if( carry ) {
                    ctx->sigma[i] ++;
                    if( ctx->sigma[i] ) carry = 0;
      }
      ctx->sigma[i] += data[i];
      if( ctx->sigma[i] < data[i] ) carry = 1;
    #else
      ak_uint64 val_data = bswap_64( data[i] ),
               val_sigma = bswap_64( ctx->sigma[i] );
      if( carry ) {
                    val_sigma++;
                    if( val_sigma ) carry = 0;
      }
      val_sigma += val_data;
      if( val_sigma < val_data ) carry = 1;
      ctx->sigma[i] = bswap_64( val_sigma );
    #endif
   }
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_hash_context_clean_streebog( ak_pointer sctx )
{
  ak_streebog cx = ( ak_streebog ) sctx;
  if( cx == NULL ) return ak_error_null_pointer;

  memset( cx->n, 0, 64 );
  memset( cx->sigma, 0, 64 );
  if( cx->hsize == 32 ) memset( cx->h, 1, 64 );
    else memset( cx->h, 0, 64 );

 return ak_error_ok;
}


/* ----------------------------------------------------------------------------------------------- */
 int ak_hash_context_update_streebog( ak_pointer sctx, const ak_pointer in, const size_t size )
{
  ak_streebog cx = ( ak_streebog ) sctx;
  ak_uint64 quot = size >> 6, *dt = ( ak_uint64 *) in;

  if( cx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                               "using null pointer to internal streebog context" );
  if(( !size ) || ( in == NULL )) return ak_error_ok;
  if(( size - ( quot << 6 )) != 0 ) return ak_error_message( ak_error_wrong_length, __func__,
                                      "data length is not a multiple of the length of the block" );
  do{
      ak_hash_context_streebog_g( cx, cx->n, dt );
      ak_hash_context_streebog_add( cx, 512 );
      ak_hash_context_streebog_sadd( cx, dt );
      quot--; dt += 8;
  } while( quot > 0 );

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_hash_context_finalize_streebog( ak_pointer sctx,
                   const ak_pointer in, const size_t size, ak_pointer out, const size_t out_size )
{
  ak_uint64 m[8];
  int result = ak_error_ok;
  ak_uint8 *mhide = NULL;
  ak_streebog cx = ( ak_streebog )sctx;
  struct streebog sx; /* структура для хранения копии текущего состояния контекста */

  if( cx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                               "using null pointer to internal streebog context" );
  if( out == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                   "using null pointer to externl result buffer" );
  if( size >= 64 ) return ak_error_message( ak_error_wrong_length, __func__,
                                                                      "input length is too huge" );
  /* формируем временный текст */
  memset( m, 0, 64 );
  if( in != NULL )
    memcpy( m, in, ( ak_uint32 )size ); /* здесь приведение типов корректно, поскольку 0 <= size < 64 */
  mhide = ( ak_uint8 * )m;
  mhide[size] = 1; /* дополнение */

  /* при финализации мы изменяем копию существующей структуры */
  memcpy( &sx, cx, sizeof( struct streebog ));
  ak_hash_context_streebog_g( &sx, sx.n, m );
  ak_hash_context_streebog_add( &sx, size << 3 );
  ak_hash_context_streebog_sadd( &sx, m );
  ak_hash_context_streebog_g( &sx, NULL, sx.n );
  ak_hash_context_streebog_g( &sx, NULL, sx.sigma );

 /* копируем нужную часть результирующего массива или выдаем сообщение об ошибке */
    if( cx->hsize == 64 ) memcpy( out, sx.h, ak_min( 64, out_size ));
      else memcpy( out, sx.h+4, ak_min( 32, out_size ));
 return result;
}

/* ----------------------------------------------------------------------------------------------- */
/*                               Реализация функций класса ak_sha3 (контекст sha3)                 */
/* ----------------------------------------------------------------------------------------------- */
int ak_hash_context_create_sha3( ak_sha3 ctx, unsigned bitSize)
{
 if ( ctx == NULL) return ak_error_message( ak_error_null_pointer, __func__,
                                             "using null pointer to hash context" );
 if(bitSize != 256 && bitSize != 384 && bitSize != 512 )
     return ak_error_message( ak_error_invalid_value, __func__,
                              "incorrect size of sha3's output" );
 memset(ctx, 0, sizeof(*ctx));
 ctx->capacityWords = 2 * bitSize / (8 * sizeof(ak_uint64));
 return ak_error_ok;
}

int ak_hash_context_create_sha3_256( ak_sha3 ctx )
{
 return ak_hash_context_create_sha3(ctx, 256);
}

int ak_hash_context_create_sha3_384( ak_sha3 ctx )
{
 return ak_hash_context_create_sha3(ctx, 384);
}

int ak_hash_context_create_sha3_512( ak_sha3 ctx )
{
 return ak_hash_context_create_sha3(ctx, 512);
}

/* ----------------------------------------------------------------------------------------------- */
/*                               Реализация функция класса hash                                    */
/* ----------------------------------------------------------------------------------------------- */
/*! Функция инициализирует контекст алгоритма бесключевого хеширования, регламентируемого стандартом
    ГОСТ Р 34.11-2012, с длиной хешкода, равной 256 бит (функция Стрибог256).

    @param hctx Контекст функции хеширования
    @return Функция возвращает код ошибки или \ref ak_error_ok (в случае успеха)                   */
/* ----------------------------------------------------------------------------------------------- */
 int ak_hash_context_create_streebog256( ak_hash hctx )
{
  int error = ak_error_ok;
  if( hctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                            "using null pointer to hash context" );
  hctx->data.sctx.hsize = 32;
  if(( hctx->oid = ak_oid_context_find_by_name( "streebog256" )) == NULL )
    return ak_error_message( ak_error_wrong_oid, __func__,
                                           "incorrect internal search of streebog256 identifier" );
  if(( error = ak_mac_context_create( &hctx->mctx, 64, &hctx->data.sctx,
                                             ak_hash_context_clean_streebog,
                                             ak_hash_context_update_streebog,
                                             ak_hash_context_finalize_streebog )) != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect initialization of internal mac context" );

  return ak_hash_context_clean_streebog( &hctx->data.sctx );
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция инициализирует контекст алгоритма бесключевого хеширования, регламентируемого стандартом
    ГОСТ Р 34.11-2012, с длиной хэшкода, равной 512 бит (функция Стрибог512).

    @param hctx Контекст функции хеширования
    @return Функция возвращает код ошибки или \ref ak_error_ok (в случае успеха)                   */
/* ----------------------------------------------------------------------------------------------- */
 int ak_hash_context_create_streebog512( ak_hash hctx )
{
  int error = ak_error_ok;
  if( hctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                            "using null pointer to hash context" );
  hctx->data.sctx.hsize = 64;
  if(( hctx->oid = ak_oid_context_find_by_name( "streebog512" )) == NULL )
    return ak_error_message( ak_error_wrong_oid, __func__,
                                           "incorrect internal search of streebog256 identifier" );
  if(( error = ak_mac_context_create( &hctx->mctx, 64, &hctx->data.sctx,
                                             ak_hash_context_clean_streebog,
                                             ak_hash_context_update_streebog,
                                             ak_hash_context_finalize_streebog )) != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect initialization of internal mac context" );

  return ak_hash_context_clean_streebog( &hctx->data.sctx );
}

/* ----------------------------------------------------------------------------------------------- */
/*! В случае инициализации контекста алгоритма ГОСТ Р 34.11-94 (в настоящее время выведен из
    действия) используются фиксированные таблицы замен, определяемые константой
    `id-gosthash94-rfc4357-paramsetA`. Для создания контекста функции хеширования ГОСТ Р 34.11-94
    с другими таблицами замен нужно пользоваться функцией ak_hash_create_gosthash94().

    @param hctx Контекст функции хеширования
    @param oid OID алгоритма бесключевого хеширования.

    @return В случае успеха возвращается ak_error_ok (ноль). В случае возникновения ошибки
    возвращается ее код.                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_hash_context_create_oid( ak_hash hctx, ak_oid oid )
{
  int error = ak_error_ok;

 /* выполняем проверку */
  if( hctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                            "using null pointer to hash context" );
  if( oid == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                       "using null pointer to hash function OID" );
 /* проверяем, что OID от бесключевой функции хеширования */
  if( oid->engine != hash_function )
    return ak_error_message( ak_error_oid_engine, __func__ , "using oid with wrong engine" );
 /* проверяем, что OID от алгоритма, а не от параметров */
  if( oid->mode != algorithm )
    return ak_error_message( ak_error_oid_mode, __func__ , "using oid with wrong mode" );
 /* проверяем, что производящая функция определена */
  if( oid->func.create == NULL )
    return ak_error_message( ak_error_undefined_function, __func__ ,
                                                          "using oid with undefined constructor" );
 /* инициализируем контекст */
  if(( error = (( ak_function_hash_context_create *)oid->func.create )( hctx )) != ak_error_ok )
      return ak_error_message( error, __func__, "invalid creation of hash function context");

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция очищает значения полей структуры struct hash.

  @param hctx Контекст функции хеширования
  @return В случае успеха возвращается ak_error_ok (ноль). В случае возникновения ошибки
  возвращается ее код.                                                                             */
/* ----------------------------------------------------------------------------------------------- */
 int ak_hash_context_destroy( ak_hash hctx )
{
  if( hctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                       "destroying null pointer to hash context" );
  hctx->oid = NULL;
  memset( &hctx->data.sctx, 0, sizeof( struct streebog ));
  if( ak_mac_context_destroy( &hctx->mctx ) != ak_error_ok )
    ak_error_message( ak_error_get_value(), __func__,
                                                    "incorrect cleaning of internal mac context" );
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param hctx Контекст функции хеширования
    @return Функция возвращает NULL. В случае возникновения ошибки, ее код может быть получен с
    помощью вызова функции ak_error_get_value().                                                   */
/* ----------------------------------------------------------------------------------------------- */
 ak_pointer ak_hash_context_delete( ak_pointer hctx )
{
  if( hctx != NULL ) {
      ak_hash_context_destroy(( ak_hash ) hctx );
      free( hctx );
     } else ak_error_message( ak_error_null_pointer, __func__ ,
                                                            "using null pointer to hash context" );
 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param hctx Контекст функции хеширования
    @return Функция возвращает длину хеш-кода в октетах. В случае возникновения ошибки,
    возвращается ноль. Код ошибки может быть получен с помощью вызова функции ak_error_get_value().*/
/* ----------------------------------------------------------------------------------------------- */
 size_t ak_hash_context_get_tag_size( ak_hash hctx )
{
  if( hctx == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using null pointer to hash context" );
    return 0;
  }

 return hctx->data.sctx.hsize;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param hctx Контекст функции хеширования
    @return Функция возвращает длину блока в октетах. В случае возникновения ошибки,
    возвращается ноль. Код ошибки может быть получен с помощью вызова функции ak_error_get_value().*/
/* ----------------------------------------------------------------------------------------------- */
 size_t ak_hash_context_get_block_size( ak_hash hctx )
{
  if( hctx == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using null pointer to hash context" );
    return 0;
  }

 return hctx->mctx.bsize;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Конечный результат применения сжимающего отображения помещается в область памяти,
    на которую указывает out. Если out равен NULL, то возвращается ошибка.
    \note Внутренняя структура, хранящая промежуточные данные, очищается.

    @param hctx Контекст функции хеширования
    @param in Указатель на входные данные для которых вычисляется хеш-код.
    @param size Размер входных данных в байтах.
    @param out Область памяти, куда будет помещен результат. Память должна быть заранее выделена.
    Размер выделяемой памяти должен быть не менее значения поля hsize и может
    быть определен с помощью вызова функции ak_hash_context_get_tag_size().
    @param out_size Размер области памяти (в октетах), в которую будет помещен результат.

    @return В случае успеха функция возвращает ноль (\ref ak_error_ok). В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_hash_context_ptr( ak_hash hctx, const ak_pointer in,
                                         const size_t size, ak_pointer out, const size_t out_size )
{
  if( hctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                            "using null pointer to hash context" );
 return ak_mac_context_ptr( &hctx->mctx, in, size, out, out_size );
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param hctx Контекст функции хеширования
    @param filename Имя файла, для котрого вычисляется хеш-код.
    @param out Область памяти, куда будет помещен результат. Память должна быть заранее выделена.
    Размер выделяемой памяти должен быть не менее значения поля hsize и может
    быть определен с помощью вызова функции ak_hash_context_get_tag_size().
    @param out_size Размер области памяти (в октетах), в которую будет помещен результат.

    @return В случае успеха функция возвращает ноль (\ref ak_error_ok). В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_hash_context_file( ak_hash hctx, const char * filename,
                                                           ak_pointer out, const size_t out_size )
{
  if( hctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                            "using null pointer to hash context" );
 return ak_mac_context_file( &hctx->mctx, filename, out, out_size );
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param hctx Контекст функции хеширования
    @return В случае успеха функция возвращает ноль (\ref ak_error_ok). В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_hash_context_clean( ak_hash hctx )
{
  if( hctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                         "cleaning null pointer to hash context" );
 return ak_mac_context_clean( &hctx->mctx );
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param hctx Контекст функции хеширования
    @param in Указатель на входные данные для которых вычисляется хеш-код.
    @param size Размер входных данных в байтах. Размер может принимать произвольное,
    натуральное значение.

    @return В случае успеха функция возвращает ноль (\ref ak_error_ok). В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_hash_context_update( ak_hash hctx, const ak_pointer in, const size_t size )
{
  if( hctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                         "updating null pointer to hash context" );
 return ak_mac_context_update( &hctx->mctx, in, size );
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param hctx Контекст функции хеширования
    @param in Указатель на входные данные для которых вычисляется хеш-код.
    @param size Размер входных данных в байтах.
    @param out Область памяти, куда будет помещен результат. Память должна быть заранее выделена.
    Размер выделяемой памяти должен быть не менее значения поля hsize и может
    быть определен с помощью вызова функции ak_hash_context_get_tag_size().
    @param out_size Размер области памяти (в октетах), в которую будет помещен результат.

    @return В случае успеха функция возвращает ноль (\ref ak_error_ok). В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_hash_context_finalize( ak_hash hctx, const ak_pointer in, const size_t size,
                                                           ak_pointer out, const size_t out_size )
{
  if( hctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                       "finalizing null pointer to hash context" );
 return ak_mac_context_finalize( &hctx->mctx, in, size, out, out_size );
}

/* ----------------------------------------------------------------------------------------------- */
/*                          Функции тестирования алгоритмов работы                                 */
/* ----------------------------------------------------------------------------------------------- */


 /* ------------------------- Функции тестирования алгоритма SHA3 --------------------------------- */


 /* Сообщение из документации NIST */
 const ak_uint8 sha3_test_message = 0xa3;

 /* Результаты хэширования сообщения sha3_test_message алгоритмом SHA-3 */

 const static ak_uint8 sha3_256_lazy_dog[256 / 8] = {
     0x69, 0x07, 0x0d, 0xda, 0x01, 0x97, 0x5c, 0x8c, 0x12, 0x0c, 0x3a, 0xad, 0xa1, 0xb2, 0x82, 0x39,
     0x4e, 0x7f, 0x03, 0x2f, 0xa9, 0xcf, 0x32, 0xf4, 0xcb, 0x22, 0x59, 0xa0, 0x89, 0x7d, 0xfc, 0x04
 };
 const static ak_uint8 sha3_256_empty[256 / 8] = {
     0xa7, 0xff, 0xc6, 0xf8, 0xbf, 0x1e, 0xd7, 0x66, 0x51, 0xc1, 0x47, 0x56, 0xa0, 0x61, 0xd6, 0x62,
     0xf5, 0x80, 0xff, 0x4d, 0xe4, 0x3b, 0x49, 0xfa, 0x82, 0xd8, 0x0a, 0x4b, 0x80, 0xf8, 0x43, 0x4a
 };
 const static ak_uint8 sha3_256_NIST_test[256 / 8] = {
     0x79, 0xf3, 0x8a, 0xde, 0xc5, 0xc2, 0x03, 0x07, 0xa9, 0x8e, 0xf7, 0x6e, 0x83, 0x24, 0xaf, 0xbf,
     0xd4, 0x6c, 0xfd, 0x81, 0xb2, 0x2e, 0x39, 0x73, 0xc6, 0x5f, 0xa1, 0xbd, 0x9d, 0xe3, 0x17, 0x87
 };


 const static ak_uint8 sha3_384_empty[384 / 8] = {
     0x0C, 0x63, 0xA7, 0x5B, 0x84, 0x5E, 0x4F, 0x7D, 0x01, 0x10, 0x7D, 0x85, 0x2E, 0x4C, 0x24, 0x85,
     0xC5, 0x1A, 0x50, 0xAA, 0xAA, 0x94, 0xFC, 0x61, 0x99, 0x5E, 0x71, 0xBB, 0xEE, 0x98, 0x3A, 0x2A,
     0xC3, 0x71, 0x38, 0x31, 0x26, 0x4A, 0xDB, 0x47, 0xFB, 0x6B, 0xD1, 0xE0, 0x58, 0xD5, 0xF0, 0x04
 };
 const static ak_uint8 sha3_384_lazy_dog[384 / 8] = {
     0x70, 0x63, 0x46, 0x5e, 0x08, 0xa9, 0x3b, 0xce, 0x31, 0xcd, 0x89, 0xd2, 0xe3, 0xca, 0x8f, 0x60,
     0x24, 0x98, 0x69, 0x6e, 0x25, 0x35, 0x92, 0xed, 0x26, 0xf0, 0x7b, 0xf7, 0xe7, 0x03, 0xcf, 0x32,
     0x85, 0x81, 0xe1, 0x47, 0x1a, 0x7b, 0xa7, 0xab, 0x11, 0x9b, 0x1a, 0x9e, 0xbd, 0xf8, 0xbe, 0x41
 };
 const static ak_uint8  sha3_384_NIST_test[384 / 8] = {
     0x18, 0x81, 0xde, 0x2c, 0xa7, 0xe4, 0x1e, 0xf9, 0x5d, 0xc4, 0x73, 0x2b, 0x8f, 0x5f, 0x00, 0x2b,
     0x18, 0x9c, 0xc1, 0xe4, 0x2b, 0x74, 0x16, 0x8e, 0xd1, 0x73, 0x26, 0x49, 0xce, 0x1d, 0xbc, 0xdd,
     0x76, 0x19, 0x7a, 0x31, 0xfd, 0x55, 0xee, 0x98, 0x9f, 0x2d, 0x70, 0x50, 0xdd, 0x47, 0x3e, 0x8f
 };


 const static ak_uint8 sha3_512_empty[512 / 8] = {
     0xA6, 0x9F, 0x73, 0xCC, 0xA2, 0x3A, 0x9A, 0xC5, 0xC8, 0xB5, 0x67, 0xDC, 0x18, 0x5A, 0x75, 0x6E,
     0x97, 0xC9, 0x82, 0x16, 0x4F, 0xE2, 0x58, 0x59, 0xE0, 0xD1, 0xDC, 0xC1, 0x47, 0x5C, 0x80, 0xA6,
     0x15, 0xB2, 0x12, 0x3A, 0xF1, 0xF5, 0xF9, 0x4C, 0x11, 0xE3, 0xE9, 0x40, 0x2C, 0x3A, 0xC5, 0x58,
     0xF5, 0x00, 0x19, 0x9D, 0x95, 0xB6, 0xD3, 0xE3, 0x01, 0x75, 0x85, 0x86, 0x28, 0x1D, 0xCD, 0x26
 };
 const static ak_uint8 sha3_512_lazy_dog[512 / 8] = {
     0x01, 0xde, 0xdd, 0x5d, 0xe4, 0xef, 0x14, 0x64, 0x24, 0x45, 0xba, 0x5f, 0x5b, 0x97, 0xc1, 0x5e,
     0x47, 0xb9, 0xad, 0x93, 0x13, 0x26, 0xe4, 0xb0, 0x72, 0x7c, 0xd9, 0x4c, 0xef, 0xc4, 0x4f, 0xff,
     0x23, 0xf0, 0x7b, 0xf5, 0x43, 0x13, 0x99, 0x39, 0xb4, 0x91, 0x28, 0xca, 0xf4, 0x36, 0xdc, 0x1b,
     0xde, 0xe5, 0x4f, 0xcb, 0x24, 0x02, 0x3a, 0x08, 0xd9, 0x40, 0x3f, 0x9b, 0x4b, 0xf0, 0xd4, 0x50
 };
 const static ak_uint8  sha3_512_NIST_test[512 / 8] = {
     0xe7, 0x6d, 0xfa, 0xd2, 0x20, 0x84, 0xa8, 0xb1, 0x46, 0x7f, 0xcf, 0x2f, 0xfa, 0x58, 0x36, 0x1b,
     0xec, 0x76, 0x28, 0xed, 0xf5, 0xf3, 0xfd, 0xc0, 0xe4, 0x80, 0x5d, 0xc4, 0x8c, 0xae, 0xec, 0xa8,
     0x1b, 0x7c, 0x13, 0xc3, 0x0a, 0xdf, 0x52, 0xa3, 0x65, 0x95, 0x84, 0x73, 0x9a, 0x2d, 0xf4, 0x6b,
     0xe5, 0x89, 0xc5, 0x1c, 0xa1, 0xa4, 0xa8, 0x41, 0x6d, 0xf6, 0x54, 0x5a, 0x1c, 0xe8, 0xba, 0x00
 };



bool_t ak_hash_test_sha3_256( void )
{
    ak_uint8 buf[200];  /* 200 раз повторяется A3 в тестовом сообщении */
    struct sha3_context c;
    bool_t result = ak_true;
    ak_uint8 out[256 / 8];
    int error;
    if(( error = ak_hash_context_create_sha3( &c, 256 )) != ak_error_ok )
    {
        ak_error_message( error, __func__ , "wrong initialization of sha3 context" );
        result = ak_false;
    }

    /* Тестирование пустого буффера */
    ak_hash_context_finalize_sha3(&c, &out);
    if(ak_ptr_is_equal_with_log(sha3_256_empty, out, sizeof(sha3_256_empty)) != ak_true)
    {
         ak_error_message( ak_error_not_equal_data, __func__ , "the zero length vector test is wrong" );
         result = ak_false;
    }

    /* Пример из Википедии */
    ak_hash_context_ptr_sha3(256, "The quick brown fox jumps over the lazy dog", 43, out, sizeof(out));

    if(ak_ptr_is_equal_with_log(sha3_256_lazy_dog, out, sizeof(sha3_256_lazy_dog)) != ak_true)
    {
         ak_error_message( ak_error_not_equal_data, __func__ , "incorrect hashing of \"...over the lazy dog\"" );
         result = ak_false;
    }

    /* Пример из стандарта FIPS[202] 1600-bit*/
    memset(buf, sha3_test_message, sizeof(buf));

    if(( error = ak_hash_context_create_sha3( &c, 256 )) != ak_error_ok )
    {
         ak_error_message( error, __func__ , "wrong initialization of sha3 context" );
         result = ak_false;
    }
    ak_hash_context_update_sha3(&c, buf, sizeof(buf));
    ak_hash_context_finalize_sha3(&c, out);

    if(ak_ptr_is_equal_with_log(sha3_256_NIST_test, out, sizeof(sha3_256_NIST_test)) != ak_true)
    {
         ak_error_message( ak_error_not_equal_data, __func__ , "incorrect hashing of NIST 1600-bit testing message" );
         result = ak_false;
    }
    return result;
}

bool_t ak_hash_test_sha3_384( void )
{
    ak_uint8 buf[200];  /* 200 раз повторяется A3 в тестовом сообщении */
    struct sha3_context c;
    bool_t result = ak_true;
    ak_uint8 out[384 / 8];
    int error;
    if(( error = ak_hash_context_create_sha3( &c, 384 )) != ak_error_ok )
    {
        ak_error_message( error, __func__ , "wrong initialization of sha3 context" );
        result = ak_false;
    }

    /* Тестирование пустого буффера */
    ak_hash_context_finalize_sha3(&c, &out);
    if(ak_ptr_is_equal_with_log(sha3_384_empty, out, sizeof(sha3_384_empty)) != ak_true)
    {
         ak_error_message( ak_error_not_equal_data, __func__ , "the zero length vector test is wrong" );
         result = ak_false;
    }

    /* Пример из Википедии */
    ak_hash_context_ptr_sha3(384, "The quick brown fox jumps over the lazy dog", 43, out, sizeof(out));

    if(ak_ptr_is_equal_with_log(sha3_384_lazy_dog, out, sizeof(sha3_384_lazy_dog)) != ak_true)
    {
         ak_error_message( ak_error_not_equal_data, __func__ , "incorrect hashing of \"...over the lazy dog\"" );
         result = ak_false;
    }

    /* Пример из стандарта FIPS[202] */
    memset(buf, sha3_test_message, sizeof(buf));

    if(( error = ak_hash_context_create_sha3( &c, 384 )) != ak_error_ok )
    {
         ak_error_message( error, __func__ , "wrong initialization of sha3 context" );
         result = ak_false;
    }

    ak_hash_context_update_sha3(&c, buf, sizeof(buf));
    ak_hash_context_finalize_sha3(&c, out);

    if(ak_ptr_is_equal_with_log(sha3_384_NIST_test, out, sizeof(sha3_384_NIST_test)) != ak_true)
    {
         ak_error_message( ak_error_not_equal_data, __func__ , "incorrect hashing of NIST testing message" );
         result = ak_false;
    }
    return result;
}

bool_t ak_hash_test_sha3_512( void )
{
    ak_uint8 buf[200];  /* 200 раз повторяется A3 в тестовом сообщении */
    struct sha3_context c;
    bool_t result = ak_true;
    ak_uint8 out[512 / 8];
    int error;
    if(( error = ak_hash_context_create_sha3( &c, 512 )) != ak_error_ok )
    {
        ak_error_message( error, __func__ , "wrong initialization of sha3 context" );
        result = ak_false;
    }

    /* Тестирование пустого буффера */
    ak_hash_context_finalize_sha3(&c, &out);
    if(ak_ptr_is_equal_with_log(sha3_512_empty, out, sizeof(sha3_512_empty)) != ak_true)
    {
         ak_error_message( ak_error_not_equal_data, __func__ , "the zero length vector test is wrong" );
         printf("512 empty\n");
         result = ak_false;
    }

    /* Пример из Википедии */
    ak_hash_context_ptr_sha3(512, "The quick brown fox jumps over the lazy dog", 43, out, sizeof(out));

    if(ak_ptr_is_equal_with_log(sha3_512_lazy_dog, out, sizeof(sha3_512_lazy_dog)) != ak_true)
    {
         ak_error_message( ak_error_not_equal_data, __func__ , "incorrect hashing of \"...over the lazy dog\"" );
         printf("512 lazy dog\n");
         result = ak_false;
    }

    /* Пример из стандарта FIPS[202] */
    memset(buf, sha3_test_message, sizeof(buf));

    if(( error = ak_hash_context_create_sha3( &c, 512 )) != ak_error_ok )
    {
         ak_error_message( error, __func__ , "wrong initialization of sha3 context" );
         result = ak_false;
    }

    ak_hash_context_update_sha3(&c, buf, sizeof(buf));
    ak_hash_context_finalize_sha3(&c, out);

    if(ak_ptr_is_equal_with_log(sha3_512_NIST_test, out, sizeof(sha3_512_NIST_test)) != ak_true)
    {
         ak_error_message( ak_error_not_equal_data, __func__ , "incorrect hashing of NIST testing message" );
         printf("512 nist\n");
         result = ak_false;
    }
    return result;
}


 /* ------------------------- Функции тестирования алгоритма Streebog ------------------------------- */

/*! первое тестовое сообщение (см. текст стандарта ГОСТ Р 34.11-2012, прил. А, пример 1) */
 static ak_uint8 streebog_M1_message[63] = {
   0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
   0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
   0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
   0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
   0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
   0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
   0x30, 0x31, 0x32 };

/*! второе тестовое сообщение (см. текст стандарта ГОСТ Р 34.11-2012, прил. А, пример 2) */
 static ak_uint8 streebog_M2_message[72] = {
   0xd1, 0xe5, 0x20, 0xe2, 0xe5, 0xf2, 0xf0, 0xe8, 0x2c, 0x20, 0xd1, 0xf2, 0xf0, 0xe8,
   0xe1, 0xee, 0xe6, 0xe8, 0x20, 0xe2, 0xed, 0xf3, 0xf6, 0xe8, 0x2c, 0x20, 0xe2, 0xe5,
   0xfe, 0xf2, 0xfa, 0x20, 0xf1, 0x20, 0xec, 0xee, 0xf0, 0xff, 0x20, 0xf1, 0xf2, 0xf0,
   0xe5, 0xeb, 0xe0, 0xec, 0xe8, 0x20, 0xed, 0xe0, 0x20, 0xf5, 0xf0, 0xe0, 0xe1, 0xf0,
   0xfb, 0xff, 0x20, 0xef, 0xeb, 0xfa, 0xea, 0xfb, 0x20, 0xc8, 0xe3, 0xee, 0xf0, 0xe5,
   0xe2, 0xfb };

 static ak_uint8 streebog256_testM1[32] = {
   0x9D, 0x15, 0x1E, 0xEF, 0xD8, 0x59, 0x0B, 0x89, 0xDA, 0xA6, 0xBA, 0x6C, 0xB7, 0x4A, 0xF9, 0x27,
   0x5D, 0xD0, 0x51, 0x02, 0x6B, 0xB1, 0x49, 0xA4, 0x52, 0xFD, 0x84, 0xE5, 0xE5, 0x7B, 0x55, 0x00
 };

 static ak_uint8 streebog256_testM2[32] = {
   0x9D, 0xD2, 0xFE, 0x4E, 0x90, 0x40, 0x9E, 0x5D, 0xA8, 0x7F, 0x53, 0x97, 0x6D, 0x74, 0x05, 0xB0,
   0xC0, 0xCA, 0xC6, 0x28, 0xFC, 0x66, 0x9A, 0x74, 0x1D, 0x50, 0x06, 0x3C, 0x55, 0x7E, 0x8F, 0x50
 };

 static ak_uint8 streebog256_testM3[32] = {
   0x3E, 0x7D, 0xEA, 0x7F, 0x23, 0x84, 0xB6, 0xC5, 0xA3, 0xD0, 0xE2, 0x4A, 0xAA, 0x29, 0xC0, 0x5E,
   0x89, 0xDD, 0xD7, 0x62, 0x14, 0x50, 0x30, 0xEC, 0x22, 0xC7, 0x1A, 0x6D, 0xB8, 0xB2, 0xC1, 0xF4
 };

 static ak_uint8 streebog256_testM4[32] = {
   0x36, 0x81, 0x6A, 0x82, 0x4D, 0xCB, 0xE7, 0xD6, 0x17, 0x1A, 0xA5, 0x85, 0x00, 0x74, 0x1F, 0x2E,
   0xA2, 0x75, 0x7A, 0xE2, 0xE1, 0x78, 0x4A, 0xB7, 0x2C, 0x5C, 0x3C, 0x6C, 0x19, 0x8D, 0x71, 0xDA
 };

 static ak_uint8 streebog256_testM5[32] = {
   0x3F, 0x53, 0x9A, 0x21, 0x3E, 0x97, 0xC8, 0x02, 0xCC, 0x22, 0x9D, 0x47, 0x4C, 0x6A, 0xA3, 0x2A,
   0x82, 0x5A, 0x36, 0x0B, 0x2A, 0x93, 0x3A, 0x94, 0x9F, 0xD9, 0x25, 0x20, 0x8D, 0x9C, 0xE1, 0xBB
 };

 static ak_uint8 streebog512_testM1[64] = {
   0x1B, 0x54, 0xD0, 0x1A, 0x4A, 0xF5, 0xB9, 0xD5, 0xCC, 0x3D, 0x86, 0xD6, 0x8D, 0x28, 0x54, 0x62,
   0xB1, 0x9A, 0xBC, 0x24, 0x75, 0x22, 0x2F, 0x35, 0xC0, 0x85, 0x12, 0x2B, 0xE4, 0xBA, 0x1F, 0xFA,
   0x00, 0xAD, 0x30, 0xF8, 0x76, 0x7B, 0x3A, 0x82, 0x38, 0x4C, 0x65, 0x74, 0xF0, 0x24, 0xC3, 0x11,
   0xE2, 0xA4, 0x81, 0x33, 0x2B, 0x08, 0xEF, 0x7F, 0x41, 0x79, 0x78, 0x91, 0xC1, 0x64, 0x6F, 0x48
 };

 static ak_uint8 streebog512_testM2[64] = {
   0x1E, 0x88, 0xE6, 0x22, 0x26, 0xBF, 0xCA, 0x6F, 0x99, 0x94, 0xF1, 0xF2, 0xD5, 0x15, 0x69, 0xE0,
   0xDA, 0xF8, 0x47, 0x5A, 0x3B, 0x0F, 0xE6, 0x1A, 0x53, 0x00, 0xEE, 0xE4, 0x6D, 0x96, 0x13, 0x76,
   0x03, 0x5F, 0xE8, 0x35, 0x49, 0xAD, 0xA2, 0xB8, 0x62, 0x0F, 0xCD, 0x7C, 0x49, 0x6C, 0xE5, 0xB3,
   0x3F, 0x0C, 0xB9, 0xDD, 0xDC, 0x2B, 0x64, 0x60, 0x14, 0x3B, 0x03, 0xDA, 0xBA, 0xC9, 0xFB, 0x28
 };

 static ak_uint8 streebog512_testM3[64] = {
   0x8E, 0x94, 0x5D, 0xA2, 0x09, 0xAA, 0x86, 0x9F, 0x04, 0x55, 0x92, 0x85, 0x29, 0xBC, 0xAE, 0x46,
   0x79, 0xE9, 0x87, 0x3A, 0xB7, 0x07, 0xB5, 0x53, 0x15, 0xF5, 0x6C, 0xEB, 0x98, 0xBE, 0xF0, 0xA7,
   0x36, 0x2F, 0x71, 0x55, 0x28, 0x35, 0x6E, 0xE8, 0x3C, 0xDA, 0x5F, 0x2A, 0xAC, 0x4C, 0x6A, 0xD2,
   0xBA, 0x3A, 0x71, 0x5C, 0x1B, 0xCD, 0x81, 0xCB, 0x8E, 0x9F, 0x90, 0xBF, 0x4C, 0x1C, 0x1A, 0x8A
 };

/* ----------------------------------------------------------------------------------------------- */
/*!  @return Если тестирование прошло успешно возвращается \ref ak_true (истина). В противном
     случае возвращается \ref ak_false.                                                            */
/* ----------------------------------------------------------------------------------------------- */
 bool_t ak_hash_test_streebog256( void )
{
  ak_uint32 steps;
  struct hash ctx; /* контекст функции хеширования */
  struct random rnd;
  int error = ak_error_ok;
  bool_t result = ak_true;
  size_t len, offset;
  int audit = ak_log_get_level();

 /* буффер длиной 32 байта (256 бит) для хранения результата */
  ak_uint8 buffer[512], out[32], out2[32], *ptr = buffer;

 /* инициализируем контекст функции хешиирования */
  if(( error = ak_hash_context_create_streebog256( &ctx )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "wrong initialization of streenbog256 context" );
    return ak_false;
  }

 /* первый пример из приложения А (ГОСТ Р 34.11-2012) */
  ak_hash_context_ptr( &ctx, streebog_M1_message, 63, out, sizeof( out ));
  if(( error = ak_error_get_value()) != ak_error_ok ) {
    ak_error_message( error, __func__ , "invalid calculation of streebog256 code" );
    result = ak_false;
    goto lab_exit;
  }

  if(( result = ak_ptr_is_equal_with_log( out, streebog256_testM1, 32 )) != ak_true ) {
    ak_error_message( ak_error_not_equal_data, __func__ ,
                                             "the 1st test from GOST R 34.11-2012 is wrong" );
    goto lab_exit;
  }
  if( audit >= ak_log_maximum )
    ak_error_message( ak_error_ok, __func__ , "the 1st test from GOST R 34.11-2012 is Ok" );


 /* второй пример из приложения А (ГОСТ Р 34.11-2012) */
  ak_hash_context_ptr( &ctx, streebog_M2_message, 72, out, sizeof( out ));
  if(( error = ak_error_get_value()) != ak_error_ok ) {
    ak_error_message( error, __func__ , "invalid calculation of streebog256 code" );
    result = ak_false;
    goto lab_exit;
  }

  if(( result = ak_ptr_is_equal_with_log( out, streebog256_testM2, 32 )) != ak_true ) {
      ak_error_message( ak_error_not_equal_data, __func__ ,
                                             "the 2nd test from GOST R 34.11-2012 is wrong" );
      goto lab_exit;
  }
  if( audit >= ak_log_maximum )
    ak_error_message( ak_error_ok, __func__ , "the 2nd test from GOST R 34.11-2012 is Ok" );

 /* первый пример из Википедии */
  ak_hash_context_ptr( &ctx, "The quick brown fox jumps over the lazy dog", 43, out, sizeof( out ));
  if(( error = ak_error_get_value()) != ak_error_ok ) {
    ak_error_message( error, __func__ , "invalid calculation of streebog256 code" );
    result = ak_false;
    goto lab_exit;
  }

  if(( result = ak_ptr_is_equal_with_log( out, streebog256_testM3, 32 )) != ak_true ) {
    ak_error_message( ak_error_not_equal_data, __func__ ,
                                             "the \"lazy dog\" test from Wikipedia is wrong" );
    goto lab_exit;
  }
  if( audit >= ak_log_maximum )
      ak_error_message( ak_error_ok, __func__ , "the \"lazy dog\" test from Wikipedia is Ok" );

 /* второй пример из Википедии */
  ak_hash_context_ptr( &ctx, "The quick brown fox jumps over the lazy dog.", 44, out, sizeof( out ));
  if(( error = ak_error_get_value()) != ak_error_ok ) {
    ak_error_message( error, __func__ , "invalid calculation of streebog256 code" );
    result = ak_false;
    goto lab_exit;
  }

  if(( result = ak_ptr_is_equal_with_log( out, streebog256_testM4, 32 )) != ak_true ) {
    ak_error_message( ak_error_not_equal_data, __func__ ,
                                        "the \"lazy dog with point\" test from Wikipedia is wrong" );
    goto lab_exit;
  }
  if( audit >= ak_log_maximum )
      ak_error_message( ak_error_ok, __func__ ,
                                           "the \"lazy dog with point\" test from Wikipedia is Ok" );

 /* хеширование пустого вектора */
  ak_hash_context_ptr( &ctx, "", 0, out, sizeof( out ));
  if(( error = ak_error_get_value()) != ak_error_ok ) {
    ak_error_message( error, __func__ , "invalid calculation of streebog256 code" );
    result = ak_false;
    goto lab_exit;
  }

  if(( result = ak_ptr_is_equal( out, streebog256_testM5, 32 )) != ak_true ) {
    ak_error_message( ak_error_not_equal_data, __func__ , "the zero length vector test is wrong" );
    goto lab_exit;
  }
  if( audit >= ak_log_maximum )
    ak_error_message( ak_error_ok, __func__ , "the zero length vector test is Ok" );

 /* тестирование алгоритма хеширования фрагментами произвольной длины */
  ak_random_context_create_lcg( &rnd );
  ak_random_context_random( &rnd, buffer, sizeof( buffer ));
  if(( error = ak_hash_context_ptr( &ctx, buffer, sizeof( buffer ),
                                                            out, sizeof( out ))) != ak_error_ok ) {
    ak_error_message_fmt( error, __func__,
                                        "incorrect hashing of random %u octets", sizeof( buffer ));
    result = ak_false;
    goto lab_exit;
  }

  steps = 0;
  offset = sizeof( buffer );
  ak_hash_context_clean( &ctx );
  do{
      ak_random_context_random( &rnd, &len, sizeof( len )); len = ak_min( len%16, offset );
      if( len > 0 ) {
        if(( error = ak_hash_context_update( &ctx, ptr, len )) != ak_error_ok ) {
           ak_error_message( error, __func__, "incorrect updating of hash context" );
           result = ak_false;
           goto lab_exit;
        }
        ptr += len;
        offset -= len;
        ++steps;
      }
  } while( offset );
  memset( out2, 0, sizeof( out2 ));
  ak_hash_context_finalize( &ctx, NULL, 0, out2, sizeof( out2 ));

  if(( result = ak_ptr_is_equal_with_log( out, out2, 32 )) != ak_true ) {
    ak_error_message_fmt( ak_error_not_equal_data, __func__ ,
                                            "the random walk test with %u steps is wrong", steps );
    goto lab_exit;
  }
  if( audit >= ak_log_maximum )
      ak_error_message_fmt( ak_error_ok, __func__ ,
                                               "the random walk test with %u steps is Ok", steps );
 /* уничтожаем контекст */
 lab_exit:
   ak_random_context_destroy( &rnd );
   ak_hash_context_destroy( &ctx );
 return result;
}

/* ----------------------------------------------------------------------------------------------- */
/*!  @return Если тестирование прошло успешно возвращается \ref ak_true (истина). В противном
     случае возвращается \ref ak_false.                                                            */
/* ----------------------------------------------------------------------------------------------- */
 bool_t ak_hash_test_streebog512( void )
{
  ak_uint32 steps;
  struct hash ctx; /* контекст функции хеширования */
  struct random rnd;
  size_t len, offset;
  int error = ak_error_ok;
  bool_t result = ak_true;
  int audit = ak_log_get_level();

 /* буффер длиной 64 байта (512 бит) для получения результата */
  ak_uint8 out[64], out2[64], buffer[512], *ptr = buffer;

 /* инициализируем контекст функции хешиирования */
  if(( error = ak_hash_context_create_streebog512( &ctx )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "wrong initialization of streenbog512 context" );
    return ak_false;
  }

 /* первый пример из приложения А (ГОСТ Р 34.11-2012) */
  ak_hash_context_ptr( &ctx, streebog_M1_message, 63, out, sizeof( out ));
  if(( error = ak_error_get_value()) != ak_error_ok ) {
    ak_error_message( error, __func__ , "invalid calculation of streebog512 code" );
    result = ak_false;
    goto lab_exit;
  }

  if(( result = ak_ptr_is_equal_with_log( out, streebog512_testM1, 64 )) != ak_true ) {
    ak_error_message( ak_error_not_equal_data, __func__ ,
                                             "the 1st test from GOST R 34.11-2012 is wrong" );
    goto lab_exit;
  }
  if( audit >= ak_log_maximum )
    ak_error_message( ak_error_ok, __func__ , "the 1st test from GOST R 34.11-2012 is Ok" );

 /* второй пример из приложения А (ГОСТ Р 34.11-2012) */
  ak_hash_context_ptr( &ctx, streebog_M2_message, 72, out, sizeof( out ));
  if(( error = ak_error_get_value()) != ak_error_ok ) {
    ak_error_message( error, __func__ , "invalid calculation of streebog512 code" );
    result = ak_false;
    goto lab_exit;
  }

  if(( result = ak_ptr_is_equal_with_log( out, streebog512_testM2, 64 )) != ak_true ) {
    ak_error_message( ak_error_not_equal_data, __func__ ,
                                             "the 2nd test from GOST R 34.11-2012 is wrong" );
    goto lab_exit;
  }
  if( audit >= ak_log_maximum )
      ak_error_message( ak_error_ok, __func__ , "the 2nd test from GOST R 34.11-2012 is Ok" );

 /* хеширование пустого вектора */
  ak_hash_context_ptr( &ctx, "", 0, out, sizeof( out ));
  if(( error = ak_error_get_value()) != ak_error_ok ) {
    ak_error_message( error, __func__ , "invalid calculation of streebog512 code" );
    result = ak_false;
    goto lab_exit;
  }

  if(( result = ak_ptr_is_equal_with_log( out, streebog512_testM3, 64 )) != ak_true ) {
    ak_error_message( ak_error_not_equal_data, __func__ , "the zero length vector test is wrong" );
    goto lab_exit;
  }
  if( audit >= ak_log_maximum )
      ak_error_message( ak_error_ok, __func__ , "the zero length vector test is Ok" );

 /* тестирование алгоритма хеширования фрагментами произвольной длины */
  ak_random_context_create_lcg( &rnd );
  ak_random_context_random( &rnd, buffer, sizeof( buffer ));
  if(( error = ak_hash_context_ptr( &ctx, buffer, sizeof( buffer ),
                                                            out, sizeof( out ))) != ak_error_ok ) {
    ak_error_message_fmt( error, __func__,
                                        "incorrect hashing of random %u octets", sizeof( buffer ));
    result = ak_false;
    goto lab_ex;
  }

  steps = 0;
  offset = sizeof( buffer );
  ak_hash_context_clean( &ctx );
  do{
      ak_random_context_random( &rnd, &len, sizeof( len )); len = ak_min( len%16, offset );
      if( len > 0 ) {
        if(( error = ak_hash_context_update( &ctx, ptr, len )) != ak_error_ok ) {
           ak_error_message( error, __func__, "incorrect updating of hash context" );
           result = ak_false;
           goto lab_ex;
        }
        ptr += len;
        offset -= len;
        ++steps;
      }
  } while( offset );
  memset( out2, 0, sizeof( out2 ));
  ak_hash_context_finalize( &ctx, NULL, 0, out2, sizeof( out2 ));

  if(( result = ak_ptr_is_equal_with_log( out, out2, 64 )) != ak_true ) {
    ak_error_message_fmt( ak_error_not_equal_data, __func__ ,
                                            "the random walk test with %u steps is wrong", steps );
    goto lab_ex;
  }
  if( audit >= ak_log_maximum )
    ak_error_message_fmt( ak_error_ok, __func__ ,
                                               "the random walk test with %u steps is Ok", steps );
 /* уничтожаем контекст */
 lab_ex:
   ak_random_context_destroy( &rnd );
 lab_exit:
   ak_hash_context_destroy( &ctx );
 return result;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                      ak_hash.c  */
/* ----------------------------------------------------------------------------------------------- */
