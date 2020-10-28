/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2014 - 2019 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*  Copyright (c) 2019 by Diffractee                                                               */
/*                                                                                                 */
/*  Файл ak_gf2n.h                                                                                 */
/*  - содержит описание функций умножения элементов конечных полей характеристики 2.               */
/* ----------------------------------------------------------------------------------------------- */
#ifndef    __AK_GF2N_H__
#define    __AK_GF2N_H__

#ifdef __cplusplus
extern "C" {
#endif

/* ----------------------------------------------------------------------------------------------- */
 #include <libakrypt.h>

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Умножение элемента поля на примитивный элемент.
    \details Макрос реализует умножение произвольного элемента поля \f$ \mathbb F_{2^{128}} \f$ на
    примитивный элемент поля. `s1` задает старшие 64 бита элемента, `s0` - младшие 64 бита.
    Степень расширения поля равняется 128, а многочлен,
    порождающий поле равен \f$ f(x) = x^{128} + x^7 + x^2 + x + 1 \in \mathbb F_2[x]\f$.           */
/* ----------------------------------------------------------------------------------------------- */
 #define ak_gf128_mul_theta(s1,s0) {\
   ak_uint64 n = s1&0x8000000000000000LL;\
   s1 <<= 1; s1 ^= ( s0 >> 63 ); s0 <<= 1;\
   if( n ) s0 ^= 0x87;\
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Умножение двух элементов поля \f$ \mathbb F_{2^{64}}\f$. */
 void ak_gf64_mul_uint64( ak_pointer z, ak_pointer x, ak_pointer y );
/*! \brief Умножение двух элементов поля \f$ \mathbb F_{2^{128}}\f$. */
 void ak_gf128_mul_uint64( ak_pointer z, ak_pointer x, ak_pointer y );
/*! \brief Умножение двух элементов поля \f$ \mathbb F_{2^{256}}\f$. */
 void ak_gf256_mul_uint64( ak_pointer z, ak_pointer x, ak_pointer y );
/*! \brief Умножение двух элементов поля \f$ \mathbb F_{2^{512}}\f$. */
 void ak_gf512_mul_uint64( ak_pointer z, ak_pointer x, ak_pointer y );

#ifdef LIBAKRYPT_HAVE_BUILTIN_CLMULEPI64
/*! \brief Умножение двух элементов поля \f$ \mathbb F_{2^{64}}\f$. */
 void ak_gf64_mul_pcmulqdq( ak_pointer z, ak_pointer x, ak_pointer y );
/*! \brief Умножение двух элементов поля \f$ \mathbb F_{2^{128}}\f$. */
 void ak_gf128_mul_pcmulqdq( ak_pointer z, ak_pointer a, ak_pointer b );
/*! \brief Умножение двух элементов поля \f$ \mathbb F_{2^{256}}\f$. */
 void ak_gf256_mul_pcmulqdq( ak_pointer z, ak_pointer a, ak_pointer b );
/*! \brief Умножение двух элементов поля \f$ \mathbb F_{2^{512}}\f$. */
 void ak_gf512_mul_pcmulqdq( ak_pointer z, ak_pointer a, ak_pointer b );

 #define ak_gf64_mul ak_gf64_mul_pcmulqdq
 #define ak_gf128_mul ak_gf128_mul_pcmulqdq
 #define ak_gf256_mul ak_gf256_mul_pcmulqdq
 #define ak_gf512_mul ak_gf512_mul_pcmulqdq

#else
 #define ak_gf64_mul ak_gf64_mul_uint64
 #define ak_gf128_mul ak_gf128_mul_uint64
 #define ak_gf256_mul ak_gf256_mul_uint64
 #define ak_gf512_mul ak_gf512_mul_uint64
#endif

/*! \brief Функция тестирования корректности реализации операций умножения в полях характеристики 2. */
 bool_t ak_gfn_multiplication_test( void );


#ifdef __cplusplus
} /* конец extern "C" */
#endif
/* ----------------------------------------------------------------------------------------------- */
#endif

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                      ak_gf2n.h  */
/* ----------------------------------------------------------------------------------------------- */
