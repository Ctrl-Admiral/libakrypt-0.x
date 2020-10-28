/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2014 - 2019 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_mpzn.h                                                                                 */
/*  - содержит описания функций, реализующих операции с большими целыми числами                    */
/* ----------------------------------------------------------------------------------------------- */
#ifndef    __AK_MPZN_H__
#define    __AK_MPZN_H__

#ifdef __cplusplus
extern "C" {
#endif

/* ----------------------------------------------------------------------------------------------- */
 #include <ak_random.h>

/* ----------------------------------------------------------------------------------------------- */
#ifdef LIBAKRYPT_HAVE_GMP_H
 #include <gmp.h>
#endif

/* ----------------------------------------------------------------------------------------------- */
 #define ak_mpzn256_size     (4)
 #define ak_mpzn512_size     (8)
 #define ak_mpznmax_size    (18)

 #define ak_mpzn256_zero  { 0, 0, 0, 0 }
 #define ak_mpzn256_one   { 1, 0, 0, 0 }
 #define ak_mpzn512_zero  { 0, 0, 0, 0, 0, 0, 0, 0 }
 #define ak_mpzn512_one   { 1, 0, 0, 0, 0, 0, 0, 0 }
 #define ak_mpznmax_zero  { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }
 #define ak_mpznmax_one   { 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Элемент кольца вычетов по модулю \f$2^{256}\f$. */
 typedef ak_uint64 ak_mpzn256[ ak_mpzn256_size ];
/*! \brief Элемент кольца вычетов по модулю \f$2^{512}\f$. */
 typedef ak_uint64 ak_mpzn512[ ak_mpzn512_size ];
/*! \brief Тип данных для хранения максимально возможного большого числа. */
 typedef ak_uint64 ak_mpznmax[ ak_mpznmax_size ];

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Присвоение вычету другого вычета. */
 void ak_mpzn_set( ak_uint64 *, ak_uint64 * , const size_t );
/*! \brief Присвоение вычету беззнакового целого значения. */
 void ak_mpzn_set_ui( ak_uint64 *, const size_t , const ak_uint64 );
/*! \brief Присвоение вычету случайного значения. */
 int ak_mpzn_set_random( ak_uint64 *, const size_t , ak_random );
/*! \brief Присвоение вычету случайного значения по фиксированному модулю. */
 int ak_mpzn_set_random_modulo( ak_uint64 *, ak_uint64 *, const size_t , ak_random );
/*! \brief Присвоение вычету значения, записанного строкой шестнадцатеричных символов. */
 int ak_mpzn_set_hexstr( ak_uint64 *, const size_t , const char * );
/*! \brief Преобразование вычета в строку шестнадцатеричных символов. */
 const char *ak_mpzn_to_hexstr( ak_uint64 *, const size_t );
/*! \brief Преобразование вычета в строку шестнадцатеричных символов с выделением памяти. */
 const char *ak_mpzn_to_hexstr_alloc( ak_uint64 *, const size_t );
/*! \brief Сериализация вычета в последовательность октетов. */
 int ak_mpzn_to_little_endian( ak_uint64 * , const size_t , ak_pointer , const size_t , bool_t );
/*! \brief Присвоение вычету сериализованного значения. */
 int ak_mpzn_set_little_endian( ak_uint64 * , const size_t , const ak_pointer , const size_t , bool_t );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Сложение двух вычетов */
 ak_uint64 ak_mpzn_add( ak_uint64 *, ak_uint64 *, ak_uint64 *, const size_t );
/*! \brief Вычитание двух вычетов */
 ak_uint64 ak_mpzn_sub( ak_uint64 *, ak_uint64 *, ak_uint64 *, const size_t );
/*! \brief Сравнение двух вычетов */
 int ak_mpzn_cmp( ak_uint64 *, ak_uint64 *, const size_t );
/*! \brief Сравнение вычета с беззнаковым целым числом (типа ak_uint64) */
 bool_t ak_mpzn_cmp_ui( ak_uint64 *, const size_t , const ak_uint64 );
/*! \brief Умножение вычета на беззнаковое целое */
 ak_uint64 ak_mpzn_mul_ui( ak_uint64 *, ak_uint64 *, const size_t, const ak_uint64 );
/*! \brief Умножение двух вычетов как целых чисел */
 void ak_mpzn_mul( ak_uint64 *, ak_uint64 *, ak_uint64 *, const size_t );
/*! \brief Вычисление остатка от деления одного вычета на другой */
 void ak_mpzn_rem( ak_uint64 *, ak_uint64 *, ak_uint64 *, const size_t );
/*! \brief Вычисление остатка от деления вычета на одноразрядное число */
 ak_uint32 ak_mpzn_rem_uint32( ak_uint64 *, const size_t , ak_uint32 );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Сложение двух вычетов в представлении Монтгомери. */
 void ak_mpzn_add_montgomery( ak_uint64 *, ak_uint64 *, ak_uint64 *, ak_uint64 *, const size_t );
/*! \brief Удвоение на двойку в представлении Монтгомери. */
 void ak_mpzn_lshift_montgomery( ak_uint64 *, ak_uint64 *, ak_uint64 *, const size_t );
/*! \brief Умножение двух вычетов в представлении Монтгомери. */
 void ak_mpzn_mul_montgomery( ak_uint64 *, ak_uint64 *, ak_uint64 *,
                                                          ak_uint64 *, ak_uint64, const size_t );
/*! \brief Модульное возведение в степень в представлении Монтгомери. */
 void ak_mpzn_modpow_montgomery( ak_uint64 *, ak_uint64 *, ak_uint64 *,
                                                          ak_uint64 *, ak_uint64, const size_t );
/* ----------------------------------------------------------------------------------------------- */
#ifdef LIBAKRYPT_HAVE_GMP_H
/*! \brief Преобразование ak_mpznxxx в mpz_t. */
 void ak_mpzn_to_mpz( const ak_uint64 *, const size_t , mpz_t );
/*! \brief Преобразование mpz_t в ak_mpznxxx. */
 void ak_mpz_to_mpzn( const mpz_t , ak_uint64 *, const size_t );
#endif

#ifdef __cplusplus
} /* конец extern "C" */
#endif

#endif
/* ----------------------------------------------------------------------------------------------- */
/*                                                                                      ak_mpzn.h  */
/* ----------------------------------------------------------------------------------------------- */
