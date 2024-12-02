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

#ifndef _ksap23_MGR_KEY_H
#define _ksap23_MGR_KEY_H

#include <stdint.h>
#include "types.h"
#include "sysenv.h"
#include "ksap23.h"
#include "include/mgr_key.h"
#include "shim/pbc_ext.h"

/**
 * @def ksap23_MGR_KEY_BEGIN_MSG
 * @brief Begin string to prepend to headers of files containing ksap23 group keys
 */
#define ksap23_MGR_KEY_BEGIN_MSG "BEGIN ksap23 MANAGERKEY"

/**
 * @def ksap23_MGR_KEY_END_MSG
 * @brief End string to prepend to headers of files containing ksap23 group keys
 */
#define ksap23_MGR_KEY_END_MSG "END ksap23 MANAGERKEY"

/**
 * @struct ksap23_mgr_key_t
 * @brief ksap23 manager key. 
 */
typedef struct {
  pbcext_element_Fr_t *x; /**< Issuer component x. */
  pbcext_element_Fr_t *y; /**< Issuer component x. */
  pbcext_element_Fr_t *z0; /**< Opener component z_0. */
  pbcext_element_Fr_t *z1; /**< Opener component z_1. */  
} ksap23_mgr_key_t;

/** 
 * @fn groupsig_key_t* ksap23_mgr_key_init()
 * @brief Creates a new ksap23 manager key
 *
 * @return The created manager key or NULL if error.
 */
groupsig_key_t* ksap23_mgr_key_init();

/** 
 * @fn int ksap23_mgr_key_free(groupsig_key_t *key)
 * @brief Frees the variables of the given manager key.
 *
 * @param[in,out] key The manager key to initialize.
 * 
 * @return IOK or IERROR
 */
int ksap23_mgr_key_free(groupsig_key_t *key);

/** 
 * @fn int ksap23_mgr_key_copy(groupsig_key_t *dst, groupsig_key_t *src)
 * @brief Copies the source key into the destination key (which must be initialized by 
 * the caller).
 *
 * @param[in,out] dst The destination key.
 * @param[in] src The source key.
 * 
 * @return IOK or IERROR.
 */
int ksap23_mgr_key_copy(groupsig_key_t *dst, groupsig_key_t *src);

/** 
 * @fn int ksap23_mgr_key_get_size(groupsig_key_t *key)
 * @brief Returns the size that the given key would require in order to be
 *  stored in an array of bytes.
 *
 * @param[in] key The key.
 *
 * @return The required number of bytes, or -1 if error.
 */
int ksap23_mgr_key_get_size(groupsig_key_t *key);

/**
 * @fn int ksap23_mgr_key_export(byte_t **bytes, uint32_t *size, groupsig_key_t *key)
 * @brief Writes a bytearray representation of the given key, with format:
 *
 *  | ksap23_CODE | KEYTYPE | size_x | x | size_y | y | size_z0 | z0 | size_z1 | z1 |
 *
 * Note that the issuer and opener keys (both manager keys) are likely to be
 * exported separately. In that case, the corresponding size_* field will be set
 * to 0, and the associated data field will be skipped (i.e., the next field, if
 * any, will again be a size_* field).
 *
 * @param[in,out] bytes A pointer to the array that will contain the exported
 *  manager key. If <i>*bytes</i> is NULL, memory will be internally allocated.
 * @param[in,out] size Will be set to the number of bytes written in <i>*bytes</i>.
 * @param[in] key The manager key to export.
 *
 * @return IOK or IERROR
 */
int ksap23_mgr_key_export(byte_t **bytes, uint32_t *size, groupsig_key_t *key);

/** 
 * @fn groupsig_key_t* ksap23_mgr_key_import(byte_t *source, uint32_t size)
 * @brief Imports a manager key.
 *
 * Imports a ksap23 manager key from the specified array of bytes.
 * 
 * @param[in] source The array of bytes containing the key to import.
 * @param[in] source The number of bytes in the passed array.
 * 
 * @return A pointer to the imported key, or NULL if error.
 */
groupsig_key_t* ksap23_mgr_key_import(byte_t *source, uint32_t size);

/** 
 * @fn char* ksap23_mgr_key_to_string(mgr_key_t *key)
 * @brief Creates a printable string of the given manager key.
 *
 * @param[in] key The manager key.
 * 
 * @return The created string or NULL if error.
 */
char* ksap23_mgr_key_to_string(groupsig_key_t *key);

/**
 * @var ksap23_mgr_key_handle
 * @brief Set of functions for ksap23 manager keys management.
 */
static const mgr_key_handle_t ksap23_mgr_key_handle = {
  .code = GROUPSIG_ksap23_CODE, /**< The scheme code. */
  .init = &ksap23_mgr_key_init, /**< Initializes manager keys. */
  .free = &ksap23_mgr_key_free, /**< Frees manager keys. */
  .copy = &ksap23_mgr_key_copy, /**< Copies manager keys. */
  .gexport = &ksap23_mgr_key_export, /**< Exports manager keys. */
  .gimport = &ksap23_mgr_key_import, /**< Imports manager keys. */
  .to_string = &ksap23_mgr_key_to_string, /**< Converts manager keys to printable strings. */
  .get_size = &ksap23_mgr_key_get_size,
};

#endif

/* mgr_key.h ends here */
