/* 
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

#ifndef _GL19_MGR_KEY_H
#define _GL19_MGR_KEY_H

#include <stdint.h>
#include "types.h"
#include "sysenv.h"
#include "gl19.h"
#include "include/mgr_key.h"
#include "shim/pbc_ext.h"

/**
 * @def GL19_MGR_KEY_BEGIN_MSG
 * @brief Begin string to prepend to headers of files containing GL19 group keys
 */
#define GL19_MGR_KEY_BEGIN_MSG "BEGIN GL19 MANAGERKEY"

/**
 * @def GL19_MGR_KEY_END_MSG
 * @brief End string to prepend to headers of files containing GL19 group keys
 */
#define GL19_MGR_KEY_END_MSG "END GL19 MANAGERKEY"

/**
 * @struct gl19_mgr_key_t
 * @brief GL19 Manager key.
 * 
 * In the CL19 paper, there are two authorities: the Issuer and the Converter.
 * The Issuer can add new members to the group. The Converter can link signatures
 * generated by group members. These should be different parties. But For simplicity,
 * we bundle them together for now.
 */
typedef struct {
  pbcext_element_Fr_t *isk; /**< Issuer secret key. */
  pbcext_element_Fr_t *csk; /**< Converter secret key. */
  pbcext_element_Fr_t *esk; /**< Extractor secret key. */
} gl19_mgr_key_t;

/** 
 * @fn groupsig_key_t* gl19_mgr_key_init()
 * @brief Creates a new GL19 manager key
 *
 * @return The created manager key or NULL if error.
 */
groupsig_key_t* gl19_mgr_key_init();

/** 
 * @fn int gl19_mgr_key_free(groupsig_key_t *key)
 * @brief Frees the variables of the given manager key.
 *
 * @param[in,out] key The manager key to initialize.
 * 
 * @return IOK or IERROR
 */
int gl19_mgr_key_free(groupsig_key_t *key);

/** 
 * @fn int gl19_mgr_key_copy(groupsig_key_t *dst, groupsig_key_t *src)
 * @brief Copies the source key into the destination key (which must be initialized by 
 * the caller).
 *
 * @param[in,out] dst The destination key.
 * @param[in] src The source key.
 * 
 * @return IOK or IERROR.
 */
int gl19_mgr_key_copy(groupsig_key_t *dst, groupsig_key_t *src);

/**
 * @fn int gl19_mgr_key_get_size(groupsig_key_t *key)
 * @brief Returns the number of bytes required to export the key.
 *
 * @param[in] key The key.
 *
 * @return The required number of bytes, or -1 if error.
 */
int gl19_mgr_key_get_size(groupsig_key_t *key);

/** 
 * @fn int gl19_mgr_key_export(byte_t **bytes, uint32_t *size, groupsig_key_t *key)
 * @brief Writes a bytearray representation of the given manager key to an array
 *  with format:
 *
 *  | GL19_CODE | KEYTYPE | size_isk | isk | size_cpk | cpk | size_esk | esk |
 *
 * @param[in,out] bytes A pointer to the array that will contain the exported
 *  manager key. If <i>*bytes</i> is NULL, memory will be internally allocated.
 * @param[in,out] size Will be set to the number of bytes written in <i>*bytes</i>.
 * @param[in] key The manager key to export.
 * 
 * @return IOK or IERROR.
 */
int gl19_mgr_key_export(byte_t **bytes, uint32_t *size, groupsig_key_t *key);

/** 
 * @fn groupsig_key_t* gl19_mgr_key_import(byte_t *source, uint32_t size)
 * @brief Imports a manager key.
 *
 * Imports a GL19 manager key from the specified source, of the specified format.
 * 
 * @param[in] source The array of bytes containing the key to import.
 * @param[in] source The number of bytes in the passed array.
 * 
 * @return A pointer to the imported key, or NULL if error.
 */
groupsig_key_t* gl19_mgr_key_import(byte_t *source, uint32_t size);

/** 
 * @fn char* gl19_mgr_key_to_string(mgr_key_t *key)
 * @brief Creates a printable string of the given manager key.
 *
 * @param[in] key The manager key.
 * 
 * @return The created string or NULL if error.
 */
char* gl19_mgr_key_to_string(groupsig_key_t *key);

/**
 * @var gl19_mgr_key_handle
 * @brief Set of functions for GL19 manager keys management.
 */
static const mgr_key_handle_t gl19_mgr_key_handle = {
 .code = GROUPSIG_GL19_CODE, /**< The scheme code. */
 .init = &gl19_mgr_key_init, /**< Initializes manager keys. */
 .free = &gl19_mgr_key_free, /**< Frees manager keys. */
 .copy = &gl19_mgr_key_copy, /**< Copies manager keys. */
 .gexport = &gl19_mgr_key_export, /**< Exports manager keys. */
 .gimport = &gl19_mgr_key_import, /**< Imports manager keys. */
 .to_string = &gl19_mgr_key_to_string, /**< Converts manager keys to printable strings. */
 .get_size = &gl19_mgr_key_get_size /**< Gets the size of the key in the specified format. */
};

#endif

/* mgr_key.h ends here */
