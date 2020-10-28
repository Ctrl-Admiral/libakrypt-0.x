/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2020 by Axel Kenzo, axelkenzo@mail.ru                                            */
/*                                                                                                 */
/*  Файл ak_asn1_keys.h                                                                            */
/*  - содержит описания функций, предназначенных для экспорта/импорта ключевой информации          */
/* ----------------------------------------------------------------------------------------------- */
#ifndef __AK_ASN1_KEYS_H__
#define __AK_ASN1_KEYS_H__

#ifdef __cplusplus
extern "C" {
#endif

/* ----------------------------------------------------------------------------------------------- */
 #include <ak_sign.h>

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция вырабатывает производные ключи шифрования и имитозащиты контента из пароля и
    экспортирует в ASN.1 дерево параметры ключа, необходимые для восстановления. */
 int ak_asn1_context_add_derived_keys_from_password( ak_asn1 , ak_oid , ak_bckey ,
                                                          ak_bckey , const char * , const size_t );
/*! \brief Функция восстанавливает производные ключи шифрования и имитозащиты на основе информации,
   хранящейся в ASN.1 дереве. */
 int ak_asn1_context_get_derived_keys( ak_asn1 , ak_bckey , ak_bckey );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Структура для получения информации о содержимом ключевого контейнера. */
 typedef struct container_info {
  /*! \brief Идентификатор криптографического алгоритма. */
   ak_oid oid;
  /*! \brief Номер ключа. */
   ak_pointer number;
  /*! \brief Длина ключа (в октетах). */
   size_t numlen;
  /*! \brief Ресурс ключа. */
   struct resource resource;
  /*! \brief Имя ключа. */
   char *alias;
  /*! \brief Идентификатор параметров эллиптической кривой, на которой
     реализуется асимметричный алгоритм */
   ak_oid ec_oid;
  /*! \brief Идентификатор открытого ключа владельца */
   ak_pointer subjectKeyIdentifier;
  /*! \brief Длина идентификатора открытого ключа владельца */
   size_t subjectKeyLength;
  /*! \brief Обощенное имя владельца. */
   ak_tlv subjectName;

} *ak_container_info;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция проверяет, что данный узел ASN.1 дерева является контейнером. */
 bool_t ak_tlv_context_check_libakrypt_container( ak_tlv tlv, ak_asn1 * , ak_asn1 * );
/*! \brief Функция возвращает тип контента, помещенного в ASN.1 контейнер. */
 crypto_content_t ak_asn1_context_get_content_type( ak_asn1 );
/*! \brief Функция получает служебную информацию о ключе, расположенном в ASN.1 контейнере. */
 int ak_asn1_context_get_symmetric_key_info( ak_asn1 , ak_container_info );
/*! \brief Функция получает служебную информацию об асимметричном ключе,
   расположенном в ASN.1 контейнере. */
 int ak_asn1_context_get_secret_key_info( ak_asn1 , ak_container_info );
/*! \brief Функция инициализирует секретный ключ значениями, расположенными в ASN.1 контейнере. */
 int ak_asn1_context_get_skey( ak_asn1 , ak_skey , ak_bckey , ak_bckey );

/* ----------------------------------------------------------------------------------------------- */
/** \addtogroup backend_keys Функции внутреннего интерфейса. Управление ключами.
 * @{*/
/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция экспортирует секретный ключ в заданный файл. */
 int ak_key_context_export_to_file_with_password( ak_pointer , oid_engines_t ,
             const char *, const size_t , const char * , char * , const size_t , export_format_t );
/*! \brief Функция экспортирует открытый ключ асиметричного криптографического алгоритма
    в запрос на получение сертификата окрытого ключа. */
 int ak_verifykey_context_export_to_request( ak_verifykey , ak_signkey ,
                                                         char * , const size_t , export_format_t );
/*! \brief Функция экспортирует открытый ключ асиметричного криптографического алгоритма
    в сертификат открытого ключа. */
 int ak_verifykey_context_export_to_certificate( ak_verifykey , ak_signkey ,
                                   ak_certificate_opts , char * , const size_t , export_format_t );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция импортирует секретный ключ криптографического преобразования из
   der-последовательности, хранящейся в заданном файле. */
 int ak_key_context_import_from_file( ak_pointer , oid_engines_t , const char * , char ** );
/*! \brief Функция импортирует секретный ключ криптографического преобразования из
   der-последовательности, хранящейся в заданном файле. */
 ak_pointer ak_key_context_new_from_file( const char *, oid_engines_t * , char ** );
/*! \brief Функция импортирует ключ алгоритма блочного шифрования из заданного файла. */
 int ak_bckey_context_import_from_file( ak_bckey , const char * , char ** );
/*! \brief Функция импортирует ключ алгоритма блочного шифрования из заданного файла. */
 int ak_hmac_context_import_from_file( ak_hmac , const char * , char ** );
/*! \brief Функция импортирует ключ асимметричного криптографического алгоритма. */
 int ak_signkey_context_import_from_file( ak_signkey , const char * , char ** );
/*! \brief Функция импортирует открытый ключ асимметричного преобразования из запроса
   на сертификат открытого ключа (тип CertificationRequest) */
 int ak_verifykey_context_import_from_request( ak_verifykey , const char * );
/** @}*/

#ifdef __cplusplus
} /* конец extern "C" */
#endif
#endif
/* ----------------------------------------------------------------------------------------------- */
/*                                                                                 ak_asn1_keys.h  */
/* ----------------------------------------------------------------------------------------------- */
