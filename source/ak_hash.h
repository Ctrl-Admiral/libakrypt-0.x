/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2014 - 2019 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_hash.h                                                                                 */
/*  - содержит описания функций, реализующих бесключевые алгоритмы хеширования.                    */
/* ----------------------------------------------------------------------------------------------- */
#ifndef __AK_HASH_H__
#define __AK_HASH_H__

#ifdef __cplusplus
extern "C" {
#endif

/* ----------------------------------------------------------------------------------------------- */
 #include <ak_mac.h>

#define SHA3_KECCAK_SPONGE_WORDS \
    (((1600)/8)/sizeof(ak_uint64))

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Структура для хранения внутренних данных функций хеширования семейства Стрибог. */
/* ----------------------------------------------------------------------------------------------- */
 typedef struct streebog {
 /*! \brief Вектор h - временный */
  ak_uint64 h[8];
 /*! \brief Вектор n - временный */
  ak_uint64 n[8];
 /*! \brief Вектор  \f$ \Sigma \f$ - контрольная сумма */
  ak_uint64 sigma[8];
 /*! \brief Размер блока выходных данных (хеш-кода)*/
  size_t hsize;
} *ak_streebog;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Структура для хранения внутренних данных функции хеширования SHA-3 (Keccak) */
/* ----------------------------------------------------------------------------------------------- */
typedef struct sha3_context {
    ak_uint64 saved;
    union {                     // Состояние (из алгоритма Keccak)
        ak_uint64 s[SHA3_KECCAK_SPONGE_WORDS];
        ak_uint8 sb[SHA3_KECCAK_SPONGE_WORDS * 8];
    };
    unsigned byteIndex;         // Индекс бита (от 0 до 7), который идет после последнего отработанного
    unsigned wordIndex;         /*! Индекс слова (от 0 до 24), которое будет обрабатываться следующим */
    unsigned capacityWords;     // Увеличенная в два раза длина выходного хэша
} *ak_sha3;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция создания контекста хеширования. */
 typedef int ( ak_function_hash_context_create )( ak_pointer );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Бесключевая функция хеширования. */
/*! \details Класс предоставляет интерфейс для реализации бесключевых функций хеширования, построенных
    с использованием итеративных сжимающих отображений. В настоящее время
    с использованием класса \ref hash реализованы следующие отечественные алгоритмы хеширования
     - Стрибог256,
     - Стрибог512,
     - ГОСТ Р 34.11-94 (в настоящее время стандарт выведен из обращения).

  Перед началом работы контекст функции хэширования должен быть инициализирован
  вызовом одной из функций инициализации, например, функции ak_hash_context_create_streebog256()
  или функции ak_hash_context_create_streebog512().
  После завершения вычислений контекст должен быть освобожден с помощью функции
  ak_hash_context_destroy().                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 typedef struct hash {
  /*! \brief OID алгоритма хеширования */
   ak_oid oid;
  /*! \brief Контекст итерационного сжатия. */
   struct mac mctx;
  /*! \brief Внутренние данные контекста */
   union {
   /*! \brief Структура алгоритмов семейства Стрибог. */
    struct streebog sctx;
   } data;
 } *ak_hash;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Инициализация контекста функции бесключевого хеширования ГОСТ Р 34.11-2012 (Стрибог256). */
 int ak_hash_context_create_streebog256( ak_hash );
/*! \brief Инициализация контекста функции бесключевого хеширования ГОСТ Р 34.11-2012 (Стрибог512). */
 int ak_hash_context_create_streebog512( ak_hash );

/*! \brief Инициализация контекста функции хеширования SHA3 (Keccak). */
int ak_hash_context_create_sha3( ak_sha3 ctx, unsigned bitSize);

/*! \brief Обновление контекста функции хеширования SHA3 (Keccak). */
int ak_hash_context_update_sha3( ak_pointer cx, const void* in, size_t len);
/*! \brief Обновление состояния и вычисление результата применения функции хеширования SHA3 (Keccak). */
int ak_hash_context_finalize_sha3(ak_pointer cx, ak_pointer out);
/*! \brief Применение функции хеширования SHA3 (Keccak) для заданной области памяти. */
int ak_hash_context_ptr_sha3( unsigned bitSize, const void* in, size_t inSize, ak_pointer out, size_t outSize);
/*! \brief Тест функции хеширования SHA3-256 (Keccak). */
bool_t ak_hash_test_sha3_256( void );
/*! \brief Тест функции хеширования SHA3-384 (Keccak). */
bool_t ak_hash_test_sha3_384( void );
/*! \brief Тест функции хеширования SHA3-512 (Keccak). */
bool_t ak_hash_test_sha3_512( void );


/*! \brief Инициализация контекста функции бесключевого хеширования по заданному OID алгоритма. */
 int ak_hash_context_create_oid( ak_hash, ak_oid );
/*! \brief Уничтожение контекста функции хеширования. */
 int ak_hash_context_destroy( ak_hash );
/*! \brief Освобождение памяти из под контекста функции хеширования. */
 ak_pointer ak_hash_context_delete( ak_pointer );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция возвращает размер вырабатываемого хеш-кода (в октетах). */
 size_t ak_hash_context_get_tag_size( ak_hash );
/*! \brief Функция возвращает размер блока входных данных, обрабатываемого функцией хеширования (в октетах). */
 size_t ak_hash_context_get_block_size( ak_hash );
/*! \brief Очистка контекста алгоритма хеширования. */
 int ak_hash_context_clean( ak_hash );
/*! \brief Обновление состояния контекста хеширования. */
 int ak_hash_context_update( ak_hash , const ak_pointer , const size_t );
/*! \brief Обновление состояния и вычисление результата применения алгоритма хеширования. */
 int ak_hash_context_finalize( ak_hash , const ak_pointer , const size_t , ak_pointer , const size_t );
/*! \brief Хеширование заданной области памяти. */
 int ak_hash_context_ptr( ak_hash , const ak_pointer , const size_t , ak_pointer , const size_t );
/*! \brief Хеширование заданного файла. */
 int ak_hash_context_file( ak_hash , const char*, ak_pointer , const size_t );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Проверка корректной работы функции хеширования Стрибог-256 */
 bool_t ak_hash_test_streebog256( void );
/*! \brief Проверка корректной работы функции хеширования Стрибог-512 */
 bool_t ak_hash_test_streebog512( void );


#ifdef __cplusplus
} /* конец extern "C" */
#endif
#endif
/* ----------------------------------------------------------------------------------------------- */
/*                                                                                      ak_hash.h  */
/* ----------------------------------------------------------------------------------------------- */
