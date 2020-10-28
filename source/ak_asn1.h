/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2019 by Anton Sakharov                                                           */
/*  Copyright (c) 2020 by Axel Kenzo, axelkenzo@mail.ru                                            */
/*                                                                                                 */
/*  Файл ak_asn1.h                                                                                 */
/*  - содержит определения функций,                                                                */
/*    используемых для базового кодирования/декодированя ASN.1 структур                            */
/* ----------------------------------------------------------------------------------------------- */
#ifndef __AK_ASN1_H__
#define __AK_ASN1_H__

#ifdef __cplusplus
extern "C" {
#endif

/* ----------------------------------------------------------------------------------------------- */
 #include <ak_bckey.h>

/* ----------------------------------------------------------------------------------------------- */
#ifdef LIBAKRYPT_HAVE_STDIO_H
 #include <stdio.h>
#else
 #error Library cannot be compiled without string.h header
#endif

/* ----------------------------------------------------------------------------------------------- */
/* Флаги, определяющие класс данных ASN.1. */
 #define UNIVERSAL           0x00u
 #define APPLICATION         0x40u
 #define CONTEXT_SPECIFIC    0x80u
 #define PRIVATE             0xC0u

/* ----------------------------------------------------------------------------------------------- */
/* Флаг, определяющий структуру блока данных ASN.1. */
 #define PRIMITIVE           0x00u
 #define CONSTRUCTED         0x20u

/* ----------------------------------------------------------------------------------------------- */
/* Номера стандартных тегов ASN.1. */
 #define TEOC                0x00u
 #define TBOOLEAN            0x01u
 #define TINTEGER            0x02u
 #define TBIT_STRING         0x03u
 #define TOCTET_STRING       0x04u
 #define TNULL               0x05u
 #define TOBJECT_IDENTIFIER  0x06u
 #define TOBJECT_DESCRIPTOR  0x07u
 #define TEXTERNAL           0x08u
 #define TREAL               0x09u
 #define TENUMERATED         0x0Au
 #define TUTF8_STRING        0x0Cu
 #define TSEQUENCE           0x10u
 #define TSET                0x11u
 #define TNUMERIC_STRING     0x12u
 #define TPRINTABLE_STRING   0x13u
 #define TT61_STRING         0x14u
 #define TVIDEOTEX_STRING    0x15u
 #define TIA5_STRING         0x16u
 #define TUTCTIME            0x17u
 #define TGENERALIZED_TIME   0x18u
 #define TGRAPHIC_STRING     0x19u
 #define TVISIBLE_STRING     0x1Au
 #define TGENERAL_STRING     0x1Bu
 #define TUNIVERSAL_STRING   0x1Cu
 #define TCHARACTER_STRING   0x1Du
 #define TBMP_STRING         0x1Eu

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Биты, определяющие класс данных */
 #define DATA_CLASS(x)     ((x) & 0xC0)
/*! \brief Бит, определяющий структуру данных */
 #define DATA_STRUCTURE(x) ((x) & 0x20)
/*! \brief Биты, определяющие номер тега */
 #define TAG_NUMBER(x)     ((x) & 0x1F)

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Длина тега (текущая реализация поддерживает кодирование
 *         и декодирование тегов, представленных одним байтом) */
 #define TAG_LEN 1

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Максимальный размер закодированного ASN.1 дерева в виде der-последовательности */
 #define ak_libakrypt_encoded_asn1_der_sequence (4096)

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Указатель на примитивный элемент дерева ASN1 нотации */
 typedef struct tlv *ak_tlv;
/*! \brief Указатель на один уровень дерева ASN1 нотации */
 typedef struct asn1 *ak_asn1;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Класс, реализующий один уровень дерева ASN1 нотации.
    \details Фактически, класс asn1 является двусвязным списком узлов, расположенных на одном
    уровне ASN1 дерева. Каждый узел, реализуемый при помощи структуры \ref tlv,
    представляет собой примитивный элемент, либо низлежащий уровень -- двусвязный список,
    также реализуемый при помощи класса asn1.                                                      */
/* ----------------------------------------------------------------------------------------------- */
 typedef struct asn1 {
   /*! \brief указатель на текущий узел списка */
    ak_tlv current;
   /*! \brief количество содержащихся узлов в списке (одного уровня) */
    size_t count;
 } *ak_asn1;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Структура, определяющая элемент дерева ASN1 нотации
    \details ASN1 дерево представляется в памяти двусвязным списком узлов (tlv структур), образующих
    один уровень. При этом, каждый узел может быть:
     - примитивным, содержащим данные, для которых определены стандартные процедуры кодирования и
       декодирования,
     - составным, представляющим собой двусвязный список узлов следующего уровня;
       составные узлы позволяют образовывать произвольные типы данных, отличные от примитивных;
       процедуры кодирования/декодирования составных узлов сводятся к последовательному применению
       процедур для примитивных типов.                                                             */
/* ----------------------------------------------------------------------------------------------- */
 struct tlv
{
 /*! \brief объединение, определяющее способ представления данных (примитивный или составной элемент),
     а также сами данные. */
  union {
   /*! \brief указатель на примитивные, закодированые по правилам ASN.1 данные */
    ak_uint8* primitive;
   /*! \brief указатель на составные данные, представляющие собой двусвязный список следующего уровня */
    ak_asn1 constructed;
  } data;
 /*! \brief тег, идентифицирующий данные. */
  ak_uint8 tag;
 /*! \brief длинна данных. */
  ak_uint32 len;
 /*! \brief флаг, определяющий, должен ли объект освобождать память из под данных, которыми управляет */
  bool_t free;

 /*! \brief указатель на предыдущий элемент списка. */
  ak_tlv prev;
 /*! \brief указатель на следующий элемент списка. */
  ak_tlv next;
};

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Структура, используемая для передачи информации о битовых строках. */
 typedef struct bit_string {
  /*! \brief массив, содержащий данные (в шестнадцатеричном виде) */
   ak_uint8 *value;
  /*! \brief размер массива с данными (в октетах) */
   ak_uint32 len;
  /*! \brief кол-во неиспользуемых битов в последнем байте
     (допустимые значения: от 0 до 7 включительно). */
   ak_uint8 unused;
 } *ak_bit_string;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Определение количества байт, необходимых для кодирования длины элемента ASN1 дерева. */
 size_t ak_asn1_get_length_size( const size_t );
/*! \brief Определение количества байт, необходимых для кодирования идентификатора объекта. */
 size_t ak_asn1_get_length_oid( const char * );
/*! \brief Получение символьного (человекочитаемого) описания типа примитивного элемента ASN1 дерева. */
 const char* ak_asn1_get_tag_description( ak_uint8 );
/*! \brief Получение из DER-последовательности тега для текущего узла ASN1 дерева. */
 int ak_asn1_get_tag_from_der( ak_uint8** , ak_uint8 * );
/*! \brief Получение из DER-последовательности длины текущего узла ASN1 дерева. */
 int ak_asn1_get_length_from_der( ak_uint8** , size_t * );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Создание примитивного узла ASN1 дерева. */
 int ak_tlv_context_create_primitive( ak_tlv , ak_uint8 , size_t , ak_pointer , bool_t );
/*! \brief Создание примитивного узла ASN1 дерева. */
 ak_tlv ak_tlv_context_new_primitive( ak_uint8 , size_t , ak_pointer , bool_t );
/*! \brief Создание составного узла ASN1 дерева. */
 int ak_tlv_context_create_constructed( ak_tlv , ak_uint8 , ak_asn1 ); 
/*! \brief Создание составного узла ASN1 дерева. */
 ak_tlv ak_tlv_context_new_constructed( ak_uint8 , ak_asn1 );
/*! \brief Создание составного узла ASN1 дерева, содержащего пустую последовательность */
 ak_tlv ak_tlv_context_new_sequence( void );
/*! \brief Уничтожение примитивного узла ASN1 дерева. */
 int ak_tlv_context_destroy( ak_tlv );
/*! \brief Уничтожение примитивного узла ASN1 дерева и освобождение памяти. */
 ak_pointer ak_tlv_context_delete( ak_pointer );
/*! \brief Вывод информации о заданном узле ASN1 дерева. */
 int ak_tlv_context_print( ak_tlv , FILE * );
/*! \brief Вывод информации о примитивном узле ASN1 дерева. */
 int ak_tlv_context_print_primitive( ak_tlv, FILE * );
/*! \brief Функция вычисляет размер, занимаемый данным уровнем ASN.1 дерева */
 int ak_tlv_context_evaluate_length( ak_tlv , size_t * );
/*! \brief Кодирование одного узла ASN1 дерева в DER-последовательность октетов. */
 int ak_tlv_context_encode( ak_tlv , ak_pointer , size_t * );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Получение булевого значения, хранящегося в заданном узле ASN1 дерева. */
 int ak_tlv_context_get_bool( ak_tlv , bool_t * );
/*! \brief Получение беззнакового, 32-х битного значения, хранящегося в заданном узле ASN1 дерева. */
 int ak_tlv_context_get_uint32( ak_tlv , ak_uint32 * );
/*! \brief Получение указателя на последовательность октетов, хранящуюся в заданном узле ASN1 дерева. */
 int ak_tlv_context_get_octet_string( ak_tlv , ak_pointer *, size_t * );
/*! \brief Получение указателя на utf8 последовательность символов, хранящуюся в заданном узле ASN1 дерева. */
 int ak_tlv_context_get_utf8_string( ak_tlv , ak_pointer * );
/*! \brief Получение указателя на ia5 строку, хранящуюся в заданном узле ASN1 дерева. */
 int ak_tlv_context_get_ia5_string( ak_tlv , ak_pointer * );
/*! \brief Получение указателя на строку, содержащую только символы английского алфавита (см. стандарт ITU-T X.690 ). */
 int ak_tlv_context_get_printable_string( ak_tlv , ak_pointer * );
/*! \brief Получение указателя на строку, содержащую только арабские цифры и пробел. */
 int ak_tlv_context_get_numeric_string( ak_tlv , ak_pointer * );
/*! \brief Получение указателя на битовую строку. */
 int ak_tlv_context_get_bit_string( ak_tlv , ak_bit_string );
/*! \brief Получение указателя на символьную запись идентификатора объекта (OID),
    хранящуюся в заданном узле ASN1 дерева. */
 int ak_tlv_context_get_oid( ak_tlv , ak_pointer * );
/*! \brief Получение универсального времни, хранящегося в заданном узле ASN1 дерева. */
 int ak_tlv_context_get_utc_time( ak_tlv , time_t * );
/*! \brief Получение указателя на строку, содержащую значение локального времени (UTC),
    хранящегося в заданном узле ASN1 дерева. */
 int ak_tlv_context_get_utc_time_string( ak_tlv , ak_pointer * );
/*! \brief Получение времни, хранящегося в заданном узле ASN1 дерева. */
 int ak_tlv_context_get_generalized_time( ak_tlv , time_t * );
/*! \brief Получение указателя на строку, содержащую значение локального времени (GeneralizedTime),
    хранящегося в заданном узле ASN1 дерева. */
 int ak_tlv_context_get_generalized_time_string( ak_tlv , ak_pointer * );
/*! \brief Получение временного интервала в структуру данных TimeValidity, хранящуюся в
   заданном узле ASN1 дерева. */
 int ak_tlv_context_get_validity( ak_tlv , time_t * , time_t * );
/*! \brief Получение структуры, содержащей ресурс (структуру struct resource). */
 int ak_tlv_context_get_resource( ak_tlv , ak_resource );

/*! \brief Добавление типизированной строки в последовательность обобщенных имен,
    которой владеет текущий узел. */
 int ak_tlv_context_add_string_to_global_name( ak_tlv , const char * , const char * );
/*! \brief Функция создает новую последовательность обобщенных имен и копирует в нее типизированные
    строки из заданной последовательности. */
 ak_tlv ak_tlv_context_duplicate_global_name( ak_tlv );

/*! \brief Создание расширения, содержащего идентификатор открытого ключа (x509v3: SubjectKeyIdentifier ) */
 ak_tlv ak_tlv_context_new_subject_key_identifier( ak_pointer, const size_t );
/*! \brief Создание расширения, содержащего основные ограничения (x509v3: BasicConstraints ) */
 ak_tlv ak_tlv_context_new_basic_constraints( bool_t , const ak_uint32 );
/*! \brief Создание расширения, содержащего область применения сертификата (x509v3: keyUsage ) */
 ak_tlv ak_tlv_context_new_key_usage( const ak_uint32 );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Выделение памяти и создание одного уровня ASN1 дерева. */
 ak_asn1 ak_asn1_context_new( void );
/*! \brief Создание одного уровня ASN1 дерева. */
 int ak_asn1_context_create( ak_asn1 );
/*! \brief Перемещение к следующему узлу текущего уровня ASN1 дерева. */
 bool_t ak_asn1_context_next( ak_asn1 );
/*! \brief Перемещение к предыдущему узлу текущего уровня ASN1 дерева. */
 bool_t ak_asn1_context_prev( ak_asn1 );
/*! \brief Перемещение к последнему узлу текущего уровня ASN1 дерева. */
 bool_t ak_asn1_context_last( ak_asn1 );
/*! \brief Перемещение к первому узлу текущего уровня ASN1 дерева. */
 bool_t ak_asn1_context_first( ak_asn1 );
/*! \brief Изъятие текущего узла из ASN1 дерева. */
 ak_tlv ak_asn1_context_exclude( ak_asn1 asn1 );
/*! \brief Уничтожение текущего узла с текущего уровня ASN1 дерева. */
 bool_t ak_asn1_context_remove( ak_asn1 );
/*! \brief Уничтожение текущего уровня ASN1 дерева. */
 int ak_asn1_context_destroy( ak_asn1 );
/*! \brief Уничтожение текущего уровня ASN1 дерева и освобождение памяти. */
 ak_pointer ak_asn1_context_delete( ak_pointer );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Добавление нового узла к текущему уровню ASN1 дерева. */
 int ak_asn1_context_add_tlv( ak_asn1 , ak_tlv );
/*! \brief Добавление к текущему уровню ASN1 дерева булева значения. */
 int ak_asn1_context_add_bool( ak_asn1 , const bool_t );
/*! \brief Добавление к текущему уровню ASN1 дерева целого числа, представимого в виде
    беззнакового 32-х битного значения. */
 int ak_asn1_context_add_uint32( ak_asn1 , const ak_uint32 );
/*! \brief Добавление к текущему уровню ASN1 дерева большого целого числа, представимого
    в виде объекта класса \ref ak_mpzn */
 int ak_asn1_context_add_mpzn( ak_asn1 , ak_uint64 * , const size_t );
/*! \brief Добавление к текущему уровню ASN1 дерева узла, содержащего произвольную
    последовательность октетов */
 int ak_asn1_context_add_octet_string( ak_asn1 , const ak_pointer , const size_t );
/*! \brief Добавление к текущему уровню ASN1 дерева узла, содержащего произвольную строку
    в кодировке utf-8. */
 int ak_asn1_context_add_utf8_string( ak_asn1 , const char * );
/*! \brief Добавление к текущему уровню ASN1 дерева узла, содержащего произвольную ia5-строку. */
 int ak_asn1_context_add_ia5_string( ak_asn1 , const char * );
/*! \brief Добавление к текущему уровню ASN1 дерева узла, содержащего произвольную
    printable-строку. */
 int ak_asn1_context_add_printable_string( ak_asn1 , const char * );
/*! \brief Добавление к текущему уровню ASN1 дерева узла, содержащего произвольную
    последовательность арабских цифр. */
 int ak_asn1_context_add_numeric_string( ak_asn1 , const char * ); 
/*! \brief Добавление к текущему уровню ASN1 дерева узла, содержащего двоичную строку. */
 int ak_asn1_context_add_bit_string( ak_asn1 , ak_bit_string );
/*! \brief Добавление к текущему уровню ASN1 дерева узла, содержащего идентификатор объекта */
 int ak_asn1_context_add_oid( ak_asn1 , const char * );
/*!  \brief Добавление универсального времени к текущему уровню ASN1 дерева узла*/
 int ak_asn1_context_add_utc_time( ak_asn1 , time_t );
/*! \brief Добавление к текущему уровню ASN1 дерева низлежащего уровня */
 int ak_asn1_context_add_asn1( ak_asn1 , ak_uint8 , ak_asn1 );
/*! \brief Добавление к текущему уровню ASN1 дерева низлежащего уровня,
    представленного в виде der-последовательности октетов */
 int ak_asn1_context_add_asn1_as_octet_string( ak_asn1 , ak_asn1 );
/*! \brief Добавление к текущему уровню ASN1 дерева низлежащего уровня, содержащего временной интервал */
 int ak_asn1_context_add_validity( ak_asn1 , time_t , time_t );
/*! \brief Функция добавляет в ASN.1 структуру, содержащую ресурс (структуру struct resource). */
 int ak_asn1_context_add_resource( ak_asn1 root, ak_resource );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Вывод информации о текущем уровне ASN1 дерева. */
 int ak_asn1_context_print( ak_asn1 , FILE * );
/*! \brief Функция вычисляет размер, занимаемый данным уровнем ASN.1 дерева */
 int ak_asn1_context_evaluate_length( ak_asn1 , size_t * );
/*! \brief Кодирование ASN1 дерева в DER-последовательность октетов. */
 int ak_asn1_context_encode( ak_asn1 , ak_pointer , size_t * );
/*! \brief Декодирование ASN1 дерева из заданной DER-последовательности октетов. */
 int ak_asn1_context_decode( ak_asn1 , const ak_pointer , const size_t , bool_t );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Экспорт ASN.1 дерева в файл в виде der-последовательности. */
 int ak_asn1_context_export_to_derfile( ak_asn1 , const char * );
/*! \brief Экспорт ASN.1 дерева в файл в виде der-последовательности, закодированной в base64. */
 int ak_asn1_context_export_to_pemfile( ak_asn1 , const char * , crypto_content_t );
/*! \brief Импорт ASN.1 дерева из файла, содержащего der-последовательность. */
 int ak_asn1_context_import_from_file( ak_asn1 , const char * );

#ifdef __cplusplus
} /* конец extern "C" */
#endif
#endif
/* ----------------------------------------------------------------------------------------------- */
/*                                                                                      ak_asn1.h  */
/* ----------------------------------------------------------------------------------------------- */
