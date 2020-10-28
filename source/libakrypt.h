/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2014 - 2020 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл libakrypt.h                                                                               */
/*  - содержит перечень экспортируемых интерфейсов библиотеки libakrypt                            */
/* ----------------------------------------------------------------------------------------------- */
#ifndef    __LIBAKRYPT_H__
#define    __LIBAKRYPT_H__

/* ----------------------------------------------------------------------------------------------- */
#ifdef __cplusplus
extern "C" {
#endif

/* ----------------------------------------------------------------------------------------------- */
#ifdef DLL_EXPORT
 #define building_dll
#endif
#ifdef _MSC_VER
 #define building_dll
#endif
/* ----------------------------------------------------------------------------------------------- */
/* Обрабатываем вариант сборки библиотеки для работы под Windows (Win32)                           */
#ifdef building_dll
 #define dll_export __declspec (dllexport)
#else
/* ----------------------------------------------------------------------------------------------- */
/* Для остальных операционных систем символ теряет свой смысл ;)                                   */
 #define dll_export
#endif

/* ----------------------------------------------------------------------------------------------- */
/* Устанавливаем множество доступных заголовочных файлов.
   Данное множество зависит от используемой операционной системы, компилятора и
   формируется при вызове программы cmake                                                          */
/* ----------------------------------------------------------------------------------------------- */
#define LIBAKRYPT_HAVE_STDIO_H
#define LIBAKRYPT_HAVE_STDLIB_H
#define LIBAKRYPT_HAVE_STRING_H
#define LIBAKRYPT_HAVE_STRINGS_H
#define LIBAKRYPT_HAVE_CTYPE_H
#define LIBAKRYPT_HAVE_ENDIAN_H
/* #undef LIBAKRYPT_HAVE_SYSENDIAN_H */
#define LIBAKRYPT_HAVE_TIME_H
#define LIBAKRYPT_HAVE_SYSTIME_H
#define LIBAKRYPT_HAVE_SYSLOG_H
#define LIBAKRYPT_HAVE_UNISTD_H
#define LIBAKRYPT_HAVE_FCNTL_H
#define LIBAKRYPT_HAVE_LIMITS_H
#define LIBAKRYPT_HAVE_SYSMMAN_H
#define LIBAKRYPT_HAVE_SYSSTAT_H
#define LIBAKRYPT_HAVE_SYSTYPES_H
#define LIBAKRYPT_HAVE_SYSSOCKET_H
#define LIBAKRYPT_HAVE_SYSUN_H
#define LIBAKRYPT_HAVE_SYSSELECT_H
#define LIBAKRYPT_HAVE_ERRNO_H
#define LIBAKRYPT_HAVE_TERMIOS_H
#define LIBAKRYPT_HAVE_DIRENT_H
#define LIBAKRYPT_HAVE_FNMATCH_H
#define LIBAKRYPT_HAVE_STDALIGN_H
#define LIBAKRYPT_HAVE_STDARG_H
/* #undef LIBAKRYPT_HAVE_WINDOWS_H */
#define LIBAKRYPT_HAVE_LOCALE_H
#define LIBAKRYPT_HAVE_SIGNAL_H
#define LIBAKRYPT_HAVE_GETOPT_H
/* #undef LIBAKRYPT_HAVE_LIBINTL_H */

/* ----------------------------------------------------------------------------------------------- */
#ifdef LIBAKRYPT_HAVE_SYSTYPES_H
 #include <sys/types.h>
#else
 #error Library cannot be compiled without sys/types.h header 
#endif
#ifdef LIBAKRYPT_HAVE_STDIO_H
 #include <stdio.h>
#endif

/* ----------------------------------------------------------------------------------------------- */
#ifdef LIBAKRYPT_HAVE_ENDIAN_H
 #include <endian.h>
 #include <byteswap.h>
 #if __BYTE_ORDER == __LITTLE_ENDIAN
   #define LIBAKRYPT_LITTLE_ENDIAN   (1234)
 #else
   #define LIBAKRYPT_BIG_ENDIAN      (4321)
 #endif
#else
 #ifdef LIBAKRYPT_HAVE_SYSENDIAN_H
   #include <sys/endian.h>
   #if _BYTE_ORDER == _LITTLE_ENDIAN
     #define LIBAKRYPT_LITTLE_ENDIAN  (1234)
   #else
     #define LIBAKRYPT_BIG_ENDIAN     (4321)
   #endif
 #else
  #define LIBAKRYPT_LITTLE_ENDIAN     (1234)
 #endif
#endif

/* ----------------------------------------------------------------------------------------------- */
#ifndef __VERSION__
 #define __VERSION__ LIBAKRYPT_COMPILER_VERSION
#endif

/* ----------------------------------------------------------------------------------------------- */
#ifdef LIBAKRYPT_HAVE_WINDOWS_H
 #include <io.h>
 #include <conio.h>
 #include <process.h>
 #define LIBAKRYPT_LITTLE_ENDIAN      (1234)
#endif

/* ----------------------------------------------------------------------------------------------- */
#ifdef _MSC_VER
 #pragma warning (disable : 4996)
#endif

/* ----------------------------------------------------------------------------------------------- */
#ifdef _MSC_VER
 typedef __int32 ak_int32;
 typedef unsigned __int32 ak_uint32;
 typedef __int64 ak_int64;
 typedef unsigned __int64 ak_uint64;
 typedef __int64 ssize_t;
#endif
#ifdef __MINGW32__
 typedef __int32 ak_int32;
 typedef unsigned __int32 ak_uint32;
 typedef __int64 ak_int64;
 typedef unsigned __int64 ak_uint64;
#endif
#ifdef MSYS
 typedef int32_t ak_int32;
 typedef u_int32_t ak_uint32;
 typedef int64_t ak_int64;
 typedef u_int64_t ak_uint64;
 int snprintf(char *str, size_t size, const char *format, ... );
#endif
#if defined(__unix__) || defined(__APPLE__)
 typedef signed int ak_int32;
 typedef unsigned int ak_uint32;
 typedef signed long long int ak_int64;
 typedef unsigned long long int ak_uint64;
#endif

/* ----------------------------------------------------------------------------------------------- */
 typedef signed char ak_int8;
 typedef unsigned char ak_uint8;
 typedef ak_uint8 ak_byte;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Объединение для обработки 128-ми битных значений. */
 typedef union {
    ak_uint8 b[16];
    ak_uint32 w[4];
    ak_uint64 q[2];
 } ak_uint128;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Определение булева типа, принимающего значения либо истина, либо ложь. */
 typedef enum {
  /*! \brief Ложь */
   ak_false,
  /*! \brief Истина */
   ak_true
} bool_t;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Указатель на произвольный объект библиотеки. */
 typedef void *ak_pointer;
/*! \brief Указатель на произвольный объект библиотеки. */
 typedef const void *ak_const_pointer;
/*! \brief Дескриптор произвольного объекта библиотеки. */
 typedef ak_int64 ak_handle;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Класс функций без параметра. */
 typedef ak_pointer ( ak_function_void )( void );
/*! \brief Пользовательская функция аудита. */
 typedef int ( ak_function_log )( const char * );
/*! \brief Стандартная для языка С функция выделения памяти. */
 typedef ak_pointer ( ak_function_alloc )( size_t );
/*! \brief Функция, возвращающая код ошибки после инициализации объекта (конструктор). */
 typedef int ( ak_function_create_object ) ( ak_pointer );
/*! \brief Функция, возвращающая код ошибки после разрушения объекта (деструктор). */
 typedef int ( ak_function_destroy_object ) ( ak_pointer );
/*! \brief Функция, возвращающая NULL после освобождения памяти. */
 typedef ak_pointer ( ak_function_free_object )( ak_pointer );
/*! \brief Стандартная для языка С функция освобождения памяти. */
 typedef void ( ak_function_free )( ak_pointer );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Результат, говорящий об отсутствии ошибки. */
 #define ak_error_ok                            (0)
/*! \brief Ошибка выделения оперативной памяти. */
 #define ak_error_out_of_memory                (-1)
/*! \brief Ошибка, возникающая при доступе или передаче в качестве аргумента функции null указателя. */
 #define ak_error_null_pointer                 (-2)
/*! \brief Ошибка, возникащая при передаче аргументов функции или выделении памяти нулевой длины. */
 #define ak_error_zero_length                  (-3)
/*! \brief Ошибка, возникающая при обработке данных ошибочной длины. */
 #define ak_error_wrong_length                 (-4)
/*! \brief Использование неопределенного значения. */
 #define ak_error_undefined_value              (-5)
/*! \brief Использование неопределенного указателя на функцию (вызов null указателя). */
 #define ak_error_undefined_function           (-6)
/*! \brief Ошибка переполнения контролируемой переменной */
 #define ak_error_overflow                     (-7)
/*! \brief Попытка доступа к неопределенной опции библиотеки. */
 #define ak_error_wrong_option                 (-8)
/*! \brief Ошибка доступа за пределы массива. */
 #define ak_error_wrong_index                  (-9)

/*! \brief Ошибка создания файла. */
 #define ak_error_create_file                 (-10)
/*! \brief Ошибка доступа к файлу (устройству). */
 #define ak_error_access_file                 (-11)
/*! \brief Ошибка открытия файла (устройства). */
 #define ak_error_open_file                   (-12)
/*! \brief Ошибка закрытия файла (устройства). */
 #define ak_error_close_file                  (-13)
/*! \brief Ошибка чтения из файла (устройства). */
 #define ak_error_read_data                   (-14)
/*! \brief Ошибка чтения из файла (устройства) из-за превышения времени ожидания. */
 #define ak_error_read_data_timeout           (-15)
/*! \brief Ошибка записи в файл (устройство). */
 #define ak_error_write_data                  (-16)
/*! \brief Ошибка записи в файл - файл существует */
 #define ak_error_file_exists                 (-17)

/*! \brief Ошибка открытия сокета. */
 #define ak_error_open_socket                 (-20) 
/*! \brief Ошибка установления соединения с сокетом. */
 #define ak_error_connect_socket              (-21)
/*! \brief Ошибка закрытия сокета. */
 #define ak_error_close_socket                (-22)
/*! \brief Ошибка связывания сокета. */
 #define ak_error_bind_socket                 (-23)
/*! \brief Ошибка прослушивания сокета. */
 #define ak_error_listen_socket               (-24)
/*! \brief Ошибка создания входящего сокета. */
 #define ak_error_accept_socket               (-25)

/*! \brief Ошибка установки опций сокета */
 #define ak_error_wrong_setsockopt            (-26)
/*! \brief Ошибка получения опций сокета */
 #define ak_error_wrong_getsockopt            (-27)
/*! \brief Ошибка конвертации сетевого адреса в двоичное представление. */
 #define ak_error_wrong_inet_pton             (-28)
/*! \brief Ошибка конвертации двоичного представления адреса в человекочитаемое. */
 #define ak_error_wrong_inet_ntop             (-29)
/*! \brief Ошибка получения информации о присоединенном сокете. */
 #define ak_error_wrong_getpeername           (-30)

/*! \brief Ошибка выбора семейства протоколов. */
 #define ak_error_wrong_protocol_family       (-34)

 /*! \brief Ошибка при сравнении двух массивов данных. */
 #define ak_error_not_equal_data              (-35)
/*! \brief Ошибка выполнения библиотеки на неверной архитектуре. */
 #define ak_error_wrong_endian                (-36)
/*! \brief Ошибка чтения из терминала. */
 #define ak_error_terminal                    (-37)

/*! \brief Неверное значение дескриптора объекта. */
 #define ak_error_wrong_handle                (-40)
/*! \brief Попытка создания и/или использования ранее созданного менеджера контектстов */
 #define ak_error_context_manager_usage       (-41)
/*! \brief Ошибка, возникающая в случае неправильного значения размера структуры хранения контекстов. */
 #define ak_error_context_manager_size        (-42)
/*! \brief Ошибка, возникающая при превышении числа возможных элементов структуры хранения контекстов. */
 #define ak_error_context_manager_max_size    (-43)

/*! \brief Неверный тип криптографического механизма. */
 #define ak_error_oid_engine                  (-50)
/*! \brief Неверный режим использования криптографического механизма. */
 #define ak_error_oid_mode                    (-51)
/*! \brief Ошибочное или не определенное имя криптографического механизма. */
 #define ak_error_oid_name                    (-52)
/*! \brief Ошибочный или неопределенный идентификатор криптографического механизма. */
 #define ak_error_oid_id                      (-53)
/*! \brief Ошибочный индекс идентификатора криптографического механизма. */
 #define ak_error_oid_index                   (-54)
/*! \brief Ошибка с обращением к oid. */
 #define ak_error_wrong_oid                   (-55)

/*! \brief Ошибка, возникающая при использовании ключа, значение которого не определено. */
 #define ak_error_key_value                   (-61)
/*! \brief Ошибка, возникающая при использовании ключа для бесключевых функций. */
 #define ak_error_key_usage                   (-62)
/*! \brief Ошибка, возникающая при неверном заполнении полей структуры bckey. */
 #define ak_error_wrong_block_cipher          (-63)
/*! \brief Ошибка, возникающая при зашифровании/расшифровании данных, длина которых не кратна длине блока. */
 #define ak_error_wrong_block_cipher_length   (-64)
/*! \brief Ошибка, возникающая при неверном значении кода целостности ключа. */
 #define ak_error_wrong_key_icode             (-65)
/*! \brief Ошибка, возникающая при неверном значении длины ключа. */
 #define ak_error_wrong_key_length            (-66)
/*! \brief Ошибка, возникающая при недостаточном ресурсе ключа. */
 #define ak_error_low_key_resource            (-67)
/*! \brief Ошибка, возникающая при использовании синхропосылки (инициализационного вектора) неверной длины. */
 #define ak_error_wrong_iv_length             (-68)
/*! \brief Ошибка, возникающая при неправильном использовании функций зашифрования/расшифрования данных. */
 #define ak_error_wrong_block_cipher_function (-69)

/*! \brief Ошибка, возникающая когда параметры кривой не соответствуют алгоритму, в котором они используются. */
 #define ak_error_curve_not_supported         (-80)
/*! \brief Ошибка, возникающая если точка не принадлежит заданной кривой. */
 #define ak_error_curve_point                 (-81)
/*! \brief Ошибка, возникающая когда порядок точки неверен. */
 #define ak_error_curve_point_order           (-82)
/*! \brief Ошибка, возникающая если дискриминант кривой равен нулю (уравнение не задает кривую). */
 #define ak_error_curve_discriminant          (-83)
/*! \brief Ошибка, возникающая когда неверно определены вспомогательные параметры эллиптической кривой. */
 #define ak_error_curve_order_parameters      (-84)
/*! \brief Ошибка, возникающая когда простой модуль кривой задан неверно. */
 #define ak_error_curve_prime_modulo          (-85)

/*! \brief Использование неверного значения поля, определяющего тип данных */
 #define ak_error_invalid_asn1_tag            (-90)
/*! \brief Использование неверного значения длины данных, размещаемых в узле ASN1 дерева */
 #define ak_error_invalid_asn1_length         (-91)
/*! \brief Использование неверной функции для чтения отрицательных данных, размещаемых в узле ASN1 дерева */
 #define ak_error_invalid_asn1_significance   (-92)
/*! \brief Полученные ASN.1 данные содержат неверный или неожидаемый контент */
 #define ak_error_invalid_asn1_content        (-93)
/*! \brief Полученные ASN.1 данные содержат неверное количество элементов */
 #define ak_error_invalid_asn1_count          (-94)
/*! \brief Ошибка, возникающая при кодировании ASN1 структуры (перевод в DER-кодировку). */
 #define ak_error_wrong_asn1_encode           (-95)
/*! \brief Ошибка, возникающая при декодировании ASN1 структуры (перевод из DER-кодировки в ASN1 структуру). */
 #define ak_error_wrong_asn1_decode           (-96)

/*! \brief Ошибка использования неправильного (неожидаемого) значения. */
 #define ak_error_invalid_value               (-99)
/*! \brief Ошибка сохранения/чтения ключа с неподдерживаемым типом криптографического преобразования. */
 #define ak_error_key_engine                 (-100)
/*! \brief Ошибка сохранения/чтения ключа в неподдерживаемом формате хранения. */
 #define ak_error_key_format                 (-101)
/*! \brief Ошибка поиска ключа с заданным номером. */
 #define ak_error_key_search                 (-102)

/* ----------------------------------------------------------------------------------------------- */
 #define ak_null_string                  ("(null)")

/*! \brief Минимальный уровень аудита */
 #define ak_log_none                            (0)
/*! \brief Стандартный уровень аудита */
 #define ak_log_standard                        (1)
/*! \brief Максимальный уровень аудита */
 #define ak_log_maximum                         (2)

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Тип криптографического механизма. */
 typedef enum {
   /*! \brief идентификатор */
     identifier,
   /*! \brief симметричный шифр (блочный алгоритм)  */
     block_cipher,
   /*! \brief симметричный шифр (поточный алгоритм)  */
     stream_cipher,
   /*! \brief схема гибридного шифрования */
     hybrid_cipher,
   /*! \brief функция хеширования */
     hash_function,
   /*! \brief семейство ключевых функций хеширования HMAC */
     hmac_function,
   /*! \brief семейство функций выработки имитовставки согласно ГОСТ Р 34.13-2015. */
     cmac_function,
   /*! \brief семейство функций выработки имитовставки MGM. */
     mgm_function,
   /*! \brief класс всех ключевых функций хеширования (функций вычисления имитовставки) */
     mac_function,
   /*! \brief функция выработки электронной подписи (секретный ключ электронной подписи) */
     sign_function,
   /*! \brief функция проверки электронной подписи (ключ проверки электронной подписи) */
     verify_function,
   /*! \brief генератор случайных и псевдо-случайных последовательностей */
     random_generator,
   /*! \brief механизм идентификаторов криптографических алгоритмов */
     oid_engine,
   /*! \brief неопределенный механизм, может возвращаться как ошибка */
     undefined_engine
} oid_engines_t;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Режим и параметры использования криптографического механизма. */
 typedef enum {
   /*! \brief собственно криптографический механизм (алгоритм) */
     algorithm,
   /*! \brief данные */
     parameter,
   /*! \brief набор параметров эллиптической кривой в форме Вейерштрасса */
     wcurve_params,
   /*! \brief набор параметров эллиптической кривой в форме Эдвардса */
     ecurve_params,
   /*! \brief набор перестановок */
     kbox_params,
   /*! \brief режим простой замены блочного шифра (ГОСТ Р 34.13-2015, раздел 5.1) */
     ecb,
   /*! \brief режим гаммирования для блочного шифра (ГОСТ Р 34.13-2015, раздел 5.2) */
     counter,
   /*! \brief режим гаммирования для блочного шифра согласно ГОСТ 28147-89 */
     counter_gost,
   /*! \brief режим гаммирования c обратной связью по выходу (ГОСТ Р 34.13-2015, раздел 5.3) */
     ofb,
   /*! \brief режим простой замены с зацеплением (ГОСТ Р 34.13-2015, раздел 5.4) */
     cbc,
   /*! \brief режим гаммирования c обратной связью по шифртексту (ГОСТ Р 34.13-2015, раздел 5.5) */
     cfb,
   /*! \brief режим шифрования XTS для блочного шифра */
     xts,
   /*! \brief шифрование с аутентификацией сообщений */
     xtsmac,
   /*! \brief режим гаммирования поточного шифра (сложение по модулю 2) */
     xcrypt,
   /*! \brief гаммирование по модулю \f$ 2^8 \f$ поточного шифра */
     a8,
   /*! \brief описатель для типов данных, помещаемых в asn1 дерево */
     descriptor,
   /*! \brief неопределенный режим, может возвращаться как ошибка */
     undefined_mode
} oid_modes_t;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Описание криптографического механизма. */
 typedef struct oid_info {
  /*! \brief Тип криптографического механизма. */
   oid_engines_t engine;
  /*! \brief Режим применения криптографического механизма. */
   oid_modes_t mode;
  /*! \brief Идентификатор криптографического механизма. */
   const char *id;
  /*! \brief Перечень доступных имен криптографического механизма. */
   const char **names;
} *ak_oid_info;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Формат хранения asn1 дерева в файле */
 typedef enum {
  /*! \brief хранение asn1 дерева в виде der-последовательности. */
   asn1_der_format,
  /*! \brief хранение asn1 дерева в виде der-последовательнсти, закодированной в base64. */
   asn1_pem_format
} export_format_t;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Тип контента, помещаемого в контейнер. */
 typedef enum {
  /*! \brief Не заданный или не определенный контент. */
   undefined_content,
  /*! \brief Секретный ключ симметричного криптографического алгоритма. */
   symmetric_key_content,
  /*! \brief Секретный ключ асимметричного криптографического алгоритма. */
   secret_key_content,
  /*! \brief Открытый ключ асимметричного криптографического алгоритма. */
   public_key_content,
  /*! \brief Запрос на получение открытого ключа асимметричного криптографического алгоритма. */
   public_key_request_content,
  /*! \brief Зашифрованные, не ключевые данные. */
   encrypted_content,
  /*! \brief Незашифрованные, не ключевые данные. */
   plain_content
} crypto_content_t;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция возвращает константный указатель NULL-строку с текущей версией библиотеки. */
 dll_export const char *ak_libakrypt_version( void );
/*! \brief Функция инициализации и тестирования криптографических механизмов библиотеки. */
 dll_export int ak_libakrypt_create( ak_function_log * );
/*! \brief Функция остановки поддержки криптографических механизмов. */
 dll_export int ak_libakrypt_destroy( void );
/*! \brief Запуск динамического тестирования криптографических механизмов. */
 dll_export bool_t ak_libakrypt_dynamic_control_test( void );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция возвращает уровень аудита библиотеки. */
 dll_export int ak_log_get_level( void );
/*! \brief Функция устанавливает уровень аудита библиотеки. */
 dll_export  int ak_log_set_level( int );
/*! \brief Прямой вывод сообщения аудита. */
 dll_export int ak_log_set_message( const char * );
/*! \brief Явное задание функции аудита. */
 dll_export int ak_log_set_function( ak_function_log * );
#ifdef LIBAKRYPT_HAVE_SYSLOG_H
 /*! \brief Функция вывода сообщения об ошибке с помощью демона операционной системы. */
 int ak_function_log_syslog( const char * );
#endif
/*! \brief Функция вывода сообщения об ошибке в стандартный канал вывода ошибок. */
 dll_export int ak_function_log_stderr( const char * );
/*! \brief Вывод сообщений о возникшей в процессе выполнения ошибке. */
 dll_export int ak_error_message( const int, const char *, const char * );
/*! \brief Вывод сообщений о возникшей в процессе выполнения ошибке. */
 dll_export int ak_error_message_fmt( const int , const char *, const char *, ... );
/*! \brief Функция устанавливает значение переменной, хранящей ошибку выполнения программы. */
 dll_export int ak_error_set_value( const int );
/*! \brief Функция возвращает код последней ошибки выполнения программы. */
 dll_export int ak_error_get_value( void );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция возвращает общее количества опций библиотеки. */
 dll_export size_t ak_libakrypt_options_count( void );
/*! \brief Получение имени опции по ее номеру. */
 dll_export char *ak_libakrypt_get_option_name( const size_t index );
/*! \brief Получение значения опции по ее номеру. */
 dll_export ak_int64 ak_libakrypt_get_option_value( const size_t index );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция устанавливает/снимает режим совместимости с форматами данных,
    поддерживаемыми gostengine из библиотеки openssl. */
 dll_export int ak_libakrypt_set_openssl_compability( bool_t );
/*! \brief Функция устанавливает/снимает использование цветового выделения при выводе
    сообщений библиотеки в консоль. */
 dll_export int ak_libakrypt_set_color_output( bool_t );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Получение человекочитаемого имени для заданного типа криптографического механизма. */
 dll_export const char *ak_libakrypt_get_engine_name( const oid_engines_t );
/*! \brief Получение человекочитаемого имени режима или параметров криптографического механизма. */
 dll_export const char *ak_libakrypt_get_mode_name( const oid_modes_t );
/*! \brief Получение информации о криптографическом механизме с заданным именем или идентификатором. */
 dll_export int ak_libakrypt_get_oid( const char * , ak_oid_info );
/*! \brief Получение информации о криптографическом механизме с заданным индексом. */
 dll_export int ak_libakrypt_get_oid_by_index( const size_t , ak_oid_info );
/*! \brief Получение общего количества определенных OID библиотеки. */
 dll_export size_t ak_libakrypt_oids_count( void );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Создание строки символов, содержащей человекочитаемое шестнадцатеричное значение
   заданной области памяти. */
 dll_export const char *ak_ptr_to_hexstr( ak_const_pointer , const size_t , const bool_t );
/*! \brief Создание строки символов, содержащей человекочитаемое шестнадцатеричное значение
   заданной области памяти. */
 dll_export char *ak_ptr_to_hexstr_alloc( ak_const_pointer , const size_t , const bool_t );
/*! \brief Конвертация строки шестнадцатеричных символов в массив данных. */
 dll_export int ak_hexstr_to_ptr( const char *, ak_pointer , const size_t , const bool_t );
/*! \brief Функция высчитывает максимальную длину в байтах последовательности шестнадцатеричных символов. */
 dll_export ssize_t ak_hexstr_size( const char * );
/*! \brief Сравнение двух областей памяти. */
 dll_export bool_t ak_ptr_is_equal( ak_const_pointer, ak_const_pointer , const size_t );
/*! \brief Вычисление 4-х байтной контрольной суммы Флетчера. */
 dll_export int ak_ptr_fletcher32( ak_const_pointer , const size_t , ak_uint32 * );
/*! \brief Вычисление 4-х байтной контрольной суммы Флетчера. */
 dll_export int ak_ptr_fletcher32_xor( ak_const_pointer , const size_t , ak_uint32 * );
/*! \brief Функция чтения заданного файла в буффер. */
 dll_export ak_uint8 *ak_ptr_load_from_file( ak_pointer , size_t *, const char * );
/*! \brief Функция чтения данных в кодировке base64 из файла в буффер. */
 dll_export ak_uint8 *ak_ptr_load_from_base64_file( ak_pointer , size_t *, const char * );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Тип функции, предназначенной для считывания пароля.  */
 typedef int ( ak_function_password_read ) ( char *, const size_t );
/*! \brief Функция устанавливает обработчик - функцию чтения пользовательского пароля. */
 dll_export int ak_libakrypt_set_password_read_function( ak_function_password_read * );
/*! \brief Чтение строки из консоли. */
 dll_export int ak_string_read( const char * , char * , size_t * );
/*! \brief Чтение пароля из консоли. */
 dll_export int ak_password_read( char * , const size_t );

/* ----------------------------------------------------------------------------------------------- */
#ifdef LIBAKRYPT_HAVE_STDIO_H
/*! \brief Печать парметров эллиптической кривой с заданым именем или идентификатором */
 dll_export int ak_libakrypt_print_curve( FILE * , const char * );
/*! \brief Декодирование asn1 дерева, содержащегося в файле и вывод информации в файловый дескриптор */
 dll_export int ak_libakrypt_print_asn1( FILE * , const char * );
#endif
/*! \brief Конвертирование asn1 дерева из der формата в pem и обратно. */
 dll_export int ak_libakrypt_convert_asn1( const char * , const char * ,
                                                              export_format_t , crypto_content_t );
/*! \brief Разбиение asn1 дерева на поддеревья первого уровня. */
 dll_export int ak_libakrypt_split_asn1( const char * , export_format_t , crypto_content_t );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Бит `digitalSignature` расширения `keyUsage`. */
 #define bit_digitalSignature   (256)
/*! \brief Бит `contentCommitment` расширения `keyUsage`. */
 #define bit_contentCommitment  (128)
/*! \brief Бит `keyEncipherment` расширения `keyUsage`. */
 #define bit_keyEncipherment     (64)
/*! \brief Бит `dataEncipherment` расширения `keyUsage`. */
 #define bit_dataEncipherment    (32)
/*! \brief Бит `keyAgreement` расширения `keyUsage`. */
 #define bit_keyAgreement        (16)
/*! \brief Бит `keyCertSign` расширения `keyUsage`. */
 #define bit_keyCertSign          (8)
/*! \brief Бит `cRLSign` расширения `keyUsage`. */
 #define bit_cRLSign              (4)
/*! \brief Бит `encipherOnly` расширения `keyUsage`. */
 #define bit_encipherOnly         (2)
/*! \brief Бит `decipherOnly` расширения `keyUsage`. */
 #define bit_decipherOnly         (1)

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Структура, в которой хранятся параметры создаваемого сертификата открытого ключа. */
  typedef struct certificate_opts
{
 /*! \brief флаг того, что самоподписанный сертификат может порождать цепочки сертификации. */
  bool_t ca;
 /*! \brief количество промежуточных сертификатов в цепочке сертификации. */
  ak_uint32 pathlenConstraint;
 /*! \brief набор бит, описывающих область примеения открытого ключа (расширение `keyUsage`). */
  ak_uint32 keyUsageBits;
} *ak_certificate_opts;

 extern struct certificate_opts certificate_default_options;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Создание дескриптора криптографического преобразования. */
 dll_export ak_handle ak_handle_new( const char *, char * );
/*! \brief Создание дескриптора открытого ключа по заданному секретному ключу. */
 dll_export ak_handle ak_handle_new_from_signkey( ak_handle , char * );
/*! \brief Создание дескриптора ключа из заданного файла (ключевого контейнера) */
 dll_export ak_handle ak_handle_new_from_file( const char * );

/*! \brief Проверка, обладает ли криптографическое преобразование выходным блоком.  */
 dll_export bool_t ak_handle_check_tag( ak_handle );
/*! \brief Проверка, может ли криптографическое преобразование вычислять контрольные суммы.  */
 dll_export bool_t ak_handle_check_icode( ak_handle );
/*! \brief Проверка, допускает ли алгоритм использование секретного ключа. */
 dll_export bool_t ak_handle_check_secret_key( ak_handle );
/*! \brief Проверка, допускает ли алгоритм использование открытого ключа. */
 dll_export bool_t ak_handle_check_public_key( ak_handle );
/*! \brief Проверка, допускает ли алгоритм использование эллиптических кривых. */
 dll_export bool_t ak_handle_check_curve( ak_handle );
/*! \brief Проверка, обладает ли алгоритм расширенным именем согласно x509v3 */
 dll_export bool_t ak_handle_check_name( ak_handle );
/*! \brief Проверка, обладает ли алгоритм временным интервалом действия согласно x509v3 */
 dll_export bool_t ak_handle_check_validity( ak_handle );

/*! \brief Функция добавляет в расширенное имя новую строку. */
 dll_export int ak_handle_add_name_string( ak_handle , const char * , const char * );
/*! \brief Получение информации об параметрах алгоритма по его дескриптору. */
 dll_export int ak_handle_get_oid( ak_handle , ak_oid_info );
/*! \brief Функция возвращает длину выходного блока криптографического преобразования. */
 dll_export size_t ak_handle_get_tag_size( ak_handle );
/*! \brief Функция присваивает дескриптору алгоритма новые параметры эллиптической кривой. */
 dll_export int ak_handle_set_curve( ak_handle , const char * );
/*! \brief Присвоение случайного ключевого значения значения. */
 dll_export int ak_handle_set_key_random( ak_handle );
/*! \brief Присвоение константного ключевого значения. */
 dll_export int ak_handle_set_key_from_hexstr( ak_handle , const char * , const bool_t reverse );
/*! \brief Присвоение ключевого значения, выработанного из пароля. */
 dll_export int ak_handle_set_key_from_password( ak_handle, const ak_pointer , const size_t ,
                                                                 const ak_pointer , const size_t );
/*! \brief Присвоение временного интервала действия ключа. */
 dll_export int ak_handle_set_validity( ak_handle , time_t , time_t );
/*! \brief Удаление дескриптора криптографического преобразования. */
 dll_export int ak_handle_delete( ak_handle );
/*! \brief Экспорт секретного ключа в файл. */
 dll_export int ak_handle_export_to_file_with_password( ak_handle,
                           const char * , const size_t , char * , const size_t , export_format_t );
/*! \brief Экспорт открытого ключа в запрос на сертификат */
 dll_export int ak_handle_export_to_request( ak_handle , ak_handle ,
                                                         char * , const size_t , export_format_t );
/*! \brief Экспорт открытого ключа в сертификат */
 dll_export int ak_handle_export_to_certificate( ak_handle , ak_handle ,
                                   ak_certificate_opts , char * , const size_t , export_format_t );
/*! \brief Вычисление результата работы алгоритма итерационного сжатия для заданной области памяти. */
 dll_export int ak_handle_mac_ptr( ak_handle , ak_pointer , const size_t ,
                                                                       ak_pointer , const size_t );
/*! \brief Вычисление результата работы алгоритма итерационного сжатия для заданного файла. */
 dll_export int ak_handle_mac_file( ak_handle , const char *, ak_pointer , const size_t );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Обобщенная реализация функции snprintf для различных компиляторов. */
 dll_export int ak_snprintf( char *str, size_t size, const char *format, ... );

/* ----------------------------------------------------------------------------------------------- */
/*#ifndef __STDC_VERSION__
  #define inline
  int snprintf(char *str, size_t size, const char *format, ... );
#endif*/
#ifdef _MSC_VER
 #define __func__  __FUNCTION__
 #define strtoll _strtoi64
#endif

#ifndef _WIN32
 #ifndef O_BINARY
   #define O_BINARY  ( 0x0 )
 #endif 
#else
 #include <stdlib.h>
 #ifndef _MSC_VER
   unsigned __int64 __cdecl _byteswap_uint64(unsigned __int64 _Int64);

   #define _byteswap_ulong( x )  ((((x)&0xFF)<<24) \
                                 |(((x)>>24)&0xFF) \
                                 |(((x)&0x0000FF00)<<8)    \
                                 |(((x)&0x00FF0000)>>8)    )
 #endif
 #define bswap_32 _byteswap_ulong
 #define bswap_64 _byteswap_uint64
#endif
#ifdef LIBAKRYPT_HAVE_SYSENDIAN_H
 #define bswap_64 bswap64
 #define bswap_32 bswap32
#endif

/* ----------------------------------------------------------------------------------------------- */
#define ak_max(x,y) ((x) > (y) ? (x) : (y))
#define ak_min(x,y) ((x) < (y) ? (x) : (y))

/* ----------------------------------------------------------------------------------------------- */
#ifndef LIBAKRYPT_CONST_CRYPTO_PARAMS
/*! \brief Функция устанавливает домашний каталог пользователя. */
 dll_export int ak_libakrypt_get_home_path( char *, const size_t );
/*! \brief Функция создает полное имя файла в служебном каталоге библиотеки. */
 dll_export int ak_libakrypt_create_filename( char * , const size_t , char * , const int );
#endif

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Прототип функции-обработчика. */
 typedef int (*ini_handler)( void *user , const char *section ,
                                                            const char *name , const char *value );
/*! \brief Прототип функции чтения строк (fgets-style). */
 typedef char* (*ini_reader)( char * , int , void * );
/*! \brief Функция разбора ini-файла с заданным именем */
 dll_export int ak_libakrypt_ini_parse( const char* , ini_handler , void * );
/*! \brief Функция разбора ранее открытого ini-файла */
 dll_export int ak_libakrypt_ini_parse_file( FILE* , ini_handler , void * );
/*! \brief Функция разбора строки, содержащей корректные данные в формате ini-файла. */
 dll_export int ak_libakrypt_ini_parse_string( const char * , ini_handler , void* );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция возвращает строку, начинающую цветовое выделение. */
 dll_export const char *ak_libakrypt_get_start_error_string( void );
/*! \brief Функция возвращает строку, завершающую цветовое выделение. */
 dll_export const char *ak_libakrypt_get_end_error_string( void );

#ifdef __cplusplus
} /* конец extern "C" */
#endif
#endif

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                     libakrypt.h */
/* ----------------------------------------------------------------------------------------------- */
