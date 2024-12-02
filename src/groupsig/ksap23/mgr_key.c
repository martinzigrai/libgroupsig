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

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#include "ksap23.h"
#include "groupsig/ksap23/mgr_key.h"
#include "misc/misc.h"
#include "shim/base64.h"
#include "shim/pbc_ext.h"
#include "sys/mem.h"

groupsig_key_t* ksap23_mgr_key_init() {

  groupsig_key_t *key;
  ksap23_mgr_key_t *ksap23_key;
  
  if(!(key = (groupsig_key_t *) mem_malloc(sizeof(groupsig_key_t)))) {
    return NULL;
  }

  if(!(key->key = (ksap23_mgr_key_t *) mem_malloc(sizeof(ksap23_mgr_key_t)))) {
    mem_free(key); key = NULL;
    return NULL;
  }

  key->scheme = GROUPSIG_ksap23_CODE;
  ksap23_key = key->key;
  ksap23_key->x = NULL;
  ksap23_key->y = NULL;
  ksap23_key->z0 = NULL;
  ksap23_key->z1 = NULL;

  return key;

}

int ksap23_mgr_key_free(groupsig_key_t *key) {

  ksap23_mgr_key_t *ksap23_key;

  if(!key) {
    LOG_EINVAL_MSG(&logger, __FILE__, "ksap23_mgr_key_free", __LINE__, 
		   "Nothing to free.", LOGWARN);
    return IOK;  
  }

  if(key->scheme != GROUPSIG_ksap23_CODE) {
    LOG_EINVAL(&logger, __FILE__, "ksap23_mgr_key_free", __LINE__, LOGERROR);
    return IERROR;	       
  }

  if(key->key) {
    ksap23_key = key->key;
    if(ksap23_key->x) { pbcext_element_Fr_free(ksap23_key->x); ksap23_key->x = NULL; }
    if(ksap23_key->y) { pbcext_element_Fr_free(ksap23_key->y); ksap23_key->y = NULL; }
    if(ksap23_key->z0) { pbcext_element_Fr_free(ksap23_key->z0); ksap23_key->z0 = NULL; }
    if(ksap23_key->z1) { pbcext_element_Fr_free(ksap23_key->z1); ksap23_key->z1 = NULL; }
    mem_free(key->key); key->key = NULL;
  }
  
  mem_free(key); key = NULL;

  return IOK;

}

int ksap23_mgr_key_copy(groupsig_key_t *dst, groupsig_key_t *src) {

  ksap23_mgr_key_t *ksap23_dst, *ksap23_src;
  int rc;
  
  if(!dst || dst->scheme != GROUPSIG_ksap23_CODE ||
     !src || src->scheme != GROUPSIG_ksap23_CODE) {
    LOG_EINVAL(&logger, __FILE__, "ksap23_mgr_key_copy", __LINE__, LOGERROR);
    return IERROR;
  }

  ksap23_dst = dst->key;
  ksap23_src = src->key;
  rc = IOK;
  
  /* Copy the elements */
  if(ksap23_src->x) {
    if(!(ksap23_dst->x = pbcext_element_Fr_init()))
      GOTOENDRC(IERROR, ksap23_mgr_key_copy);
    if(pbcext_element_Fr_set(ksap23_dst->x, ksap23_src->x) == IERROR)
      GOTOENDRC(IERROR, ksap23_mgr_key_copy);
  }

  if(ksap23_src->y) {  
    if(!(ksap23_dst->y = pbcext_element_Fr_init()))
      GOTOENDRC(IERROR, ksap23_mgr_key_copy);
    if(pbcext_element_Fr_set(ksap23_dst->y, ksap23_src->y) == IERROR)
      GOTOENDRC(IERROR, ksap23_mgr_key_copy);
  }

  if(ksap23_src->z0) {  
    if(!(ksap23_dst->z0 = pbcext_element_Fr_init()))
      GOTOENDRC(IERROR, ksap23_mgr_key_copy);
    if(pbcext_element_Fr_set(ksap23_dst->z0, ksap23_src->z0) == IERROR)
      GOTOENDRC(IERROR, ksap23_mgr_key_copy);
  }

  if(ksap23_src->z1) {  
    if(!(ksap23_dst->z1 = pbcext_element_Fr_init()))
      GOTOENDRC(IERROR, ksap23_mgr_key_copy);
    if(pbcext_element_Fr_set(ksap23_dst->z1, ksap23_src->z1) == IERROR)
      GOTOENDRC(IERROR, ksap23_mgr_key_copy);  
  }
    
 ksap23_mgr_key_copy_end:

  if(rc == IERROR) {
    if (ksap23_dst->x) { pbcext_element_Fr_free(ksap23_dst->x); ksap23_dst->x = NULL; }
    if (ksap23_dst->y) { pbcext_element_Fr_free(ksap23_dst->y); ksap23_dst->y = NULL; }
    if (ksap23_dst->z0) { pbcext_element_Fr_free(ksap23_dst->z0); ksap23_dst->z0 = NULL; }
    if (ksap23_dst->z1) { pbcext_element_Fr_free(ksap23_dst->z1); ksap23_dst->z1 = NULL; }
  }

  return rc;

}

int ksap23_mgr_key_get_size(groupsig_key_t *key) {

  ksap23_mgr_key_t *ksap23_key;
  uint64_t size64, sx, sy, sz0, sz1;
  
  if(!key || key->scheme != GROUPSIG_ksap23_CODE) {
    LOG_EINVAL(&logger, __FILE__, "ksap23_mgr_key_get_size", __LINE__, LOGERROR);
    return -1;
  }

  ksap23_key = key->key;

  sx = sy = sz0 = sz1 = 0;

  if (ksap23_key->x) { if(pbcext_element_Fr_byte_size(&sx) == IERROR) return -1; }
  if (ksap23_key->y) { if(pbcext_element_Fr_byte_size(&sy) == IERROR) return -1; }
  if (ksap23_key->z0) { if(pbcext_element_Fr_byte_size(&sz0) == IERROR) return -1; }
  if (ksap23_key->z1) { if(pbcext_element_Fr_byte_size(&sz1) == IERROR) return -1; }

  size64 = sizeof(uint8_t)*2 + sizeof(int)*4 + sx + sy + sz0 + sz1;

  if(size64 > INT_MAX) return -1;
  return (int) size64;

}

int ksap23_mgr_key_export(byte_t **bytes,
			 uint32_t *size,
			 groupsig_key_t *key) {

  ksap23_mgr_key_t *ksap23_key;
  byte_t *_bytes, *__bytes;
  uint64_t len;
  int _size, ctr, rc;
  uint8_t code, type;  

  if (!bytes ||
      !size ||
      !key || key->scheme != GROUPSIG_ksap23_CODE) {
    LOG_EINVAL(&logger, __FILE__, "ksap23_mgr_key_export", __LINE__, LOGERROR);
    return IERROR;
  }
  
  rc = IOK;
  ctr = 0;
  ksap23_key = key->key;
  
  /* Get the number of bytes to represent the key */
  if ((_size = ksap23_mgr_key_get_size(key)) == -1) {
    return IERROR;
  }

  if (!(_bytes = mem_malloc(sizeof(byte_t)*_size))) {
    return IERROR;
  }
  
  /* Dump GROUPSIG_ksap23_CODE */
  code = GROUPSIG_ksap23_CODE;
  _bytes[ctr++] = code;

  /* Dump key type */
  type = GROUPSIG_KEY_MGRKEY;
  _bytes[ctr++] = GROUPSIG_KEY_MGRKEY;

  /* Dump x */
  __bytes = &_bytes[ctr];
  if (ksap23_key->x) {
    if (pbcext_dump_element_Fr_bytes(&__bytes, &len, ksap23_key->x) == IERROR) 
      GOTOENDRC(IERROR, ksap23_mgr_key_export);
    ctr += len;
  } else {
    ctr += sizeof(int);    
  }

  /* Dump y */
  __bytes = &_bytes[ctr];
  if (ksap23_key->y) {
    if (pbcext_dump_element_Fr_bytes(&__bytes, &len, ksap23_key->y) == IERROR) 
      GOTOENDRC(IERROR, ksap23_mgr_key_export);
    ctr += len;
  } else {
    ctr += sizeof(int);    
  }

  /* Dump z0 */
  if (ksap23_key->z0) {  
    __bytes = &_bytes[ctr];
    if (pbcext_dump_element_Fr_bytes(&__bytes, &len, ksap23_key->z0) == IERROR) 
      GOTOENDRC(IERROR, ksap23_mgr_key_export);
    ctr += len;
  } else {
    ctr += sizeof(int);    
  }
  
  /* Dump z1 */
  if (ksap23_key->z1) {
    __bytes = &_bytes[ctr];
    if (pbcext_dump_element_Fr_bytes(&__bytes, &len, ksap23_key->z1) == IERROR) 
      GOTOENDRC(IERROR, ksap23_mgr_key_export);
    ctr += len;
  } else {
    ctr += sizeof(int);    
  }

  /* Prepare the return */
  if(!*bytes) {
    *bytes = _bytes;
  } else {
    memcpy(*bytes, _bytes, ctr);
    mem_free(_bytes); _bytes = NULL;
  }

  /* Sanity check */
  if (ctr != _size) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "ksap23_mgr_key_export", __LINE__, 
		      EDQUOT, "Unexpected size.", LOGERROR);
    GOTOENDRC(IERROR, ksap23_mgr_key_export);
  }

  *size = ctr;  

 ksap23_mgr_key_export_end:
  
  if (rc == IERROR) {
    if(_bytes) { mem_free(_bytes); _bytes = NULL; }
  }  

  return rc;
  
}

groupsig_key_t* ksap23_mgr_key_import(byte_t *source, uint32_t size) {

  groupsig_key_t *key;
  ksap23_mgr_key_t *ksap23_key;
  uint64_t len;
  byte_t scheme, type;
  int rc, ctr;
  
  if(!source || !size) {
    LOG_EINVAL(&logger, __FILE__, "ksap23_mgr_key_import", __LINE__, LOGERROR);
    return NULL;
  }

  rc = IOK;
  ctr = 0;
  
  if(!(key = ksap23_mgr_key_init())) {
    return NULL;
  }

  ksap23_key = key->key;

  /* First byte: scheme */
  scheme = source[ctr++];
  if(scheme != key->scheme) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "ksap23_mgr_key_import", __LINE__, 
		      EDQUOT, "Unexpected key scheme.", LOGERROR);
    GOTOENDRC(IERROR, ksap23_mgr_key_import);
  }

  /* Next  byte: key type */
  type = source[ctr++];
  if(type != GROUPSIG_KEY_MGRKEY) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "ksap23_mgr_key_import", __LINE__,
		      EDQUOT, "Unexpected key scheme.", LOGERROR);
    GOTOENDRC(IERROR, ksap23_mgr_key_import);
  }

  /* Get x */
  if(!(ksap23_key->x = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, ksap23_mgr_key_import);
  if(pbcext_get_element_Fr_bytes(ksap23_key->x, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, ksap23_mgr_key_import);

  if(!len) {
    ctr += sizeof(int); // @TODO: this is an artifact of pbcext_get_element_XX_bytes
    pbcext_element_Fr_free(ksap23_key->x); ksap23_key->x = NULL;
  } else {
    ctr += len;
  }

  /* Get y */
  if(!(ksap23_key->y = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, ksap23_mgr_key_import);
  if(pbcext_get_element_Fr_bytes(ksap23_key->y, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, ksap23_mgr_key_import);

  if(!len) {
    ctr += sizeof(int); // @TODO: this is an artifact of pbcext_get_element_XX_bytes
    pbcext_element_Fr_free(ksap23_key->y); ksap23_key->y = NULL;
  } else {
    ctr += len;
  }

  /* Get z0 */
  if(!(ksap23_key->z0 = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, ksap23_mgr_key_import);
  if(pbcext_get_element_Fr_bytes(ksap23_key->z0, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, ksap23_mgr_key_import);

  if(!len) {
    ctr += sizeof(int); // @TODO: this is an artifact of pbcext_get_element_XX_bytes
    pbcext_element_Fr_free(ksap23_key->z0); ksap23_key->z0 = NULL;
  } else {
    ctr += len;
  }

  /* Get z1 */
  if(!(ksap23_key->z1 = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, ksap23_mgr_key_import);
  if(pbcext_get_element_Fr_bytes(ksap23_key->z1, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, ksap23_mgr_key_import);

  if(!len) {
    ctr += sizeof(int); // @TODO: this is an artifact of pbcext_get_element_XX_bytes
    pbcext_element_Fr_free(ksap23_key->z1); ksap23_key->z1 = NULL;
  } else {
    ctr += len;
  }  

 ksap23_mgr_key_import_end:
  
  if(rc == IERROR && key) { ksap23_mgr_key_free(key); key = NULL; }
  if(rc == IOK) return key;
  
  return NULL; 
  
}

char* ksap23_mgr_key_to_string(groupsig_key_t *key) {

  if(!key || key->scheme != GROUPSIG_ksap23_CODE) {
    LOG_EINVAL(&logger, __FILE__, "ksap23_mgr_key_to_string", __LINE__, LOGERROR);
    return NULL;
  }

  return NULL;

}

/* mgr_key.c ends here */
