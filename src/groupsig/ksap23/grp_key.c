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
#include <math.h>

#include "sysenv.h"
#include "sys/mem.h"
#include "misc/misc.h"
#include "shim/base64.h"
#include "shim/pbc_ext.h"

#include "ksap23.h" //TODO: ksap23.h v include + premenovat vsetko na ksap23
#include "groupsig/ksap23/grp_key.h"

groupsig_key_t* ksap23_grp_key_init() {

  groupsig_key_t *key;
  ksap23_grp_key_t *ksap23_key;

  if(!(key = (groupsig_key_t *) mem_malloc(sizeof(groupsig_key_t)))) {
    return NULL;
  }

  if(!(key->key = (ksap23_grp_key_t *) mem_malloc(sizeof(ksap23_grp_key_t)))) {
    mem_free(key); key = NULL;
    return NULL;
  }

  key->scheme = GROUPSIG_ksap23_CODE;
  ksap23_key = key->key;
  ksap23_key->g = NULL;
  ksap23_key->gg = NULL;
  ksap23_key->XX = NULL;
  ksap23_key->YY = NULL;
  ksap23_key->ZZ0 = NULL;
  ksap23_key->ZZ1 = NULL;
  ksap23_key->h = NULL;
  return key;
  
}

int ksap23_grp_key_free(groupsig_key_t *key) {

  ksap23_grp_key_t *ksap23_key;

  if(!key) {
    LOG_EINVAL_MSG(&logger, __FILE__, "ksap23_grp_key_free", __LINE__, 
		   "Nothing to free.", LOGWARN);
    return IOK;  
  }

  if(key->scheme != GROUPSIG_ksap23_CODE) {
    LOG_EINVAL(&logger, __FILE__, "ksap23_grp_key_free", __LINE__, LOGERROR);
    return IERROR;	       
  }

  if(key->key) {
    ksap23_key = key->key;
    if(ksap23_key->g) { pbcext_element_G1_free(ksap23_key->g); ksap23_key->g = NULL; }
    if(ksap23_key->gg) { pbcext_element_G2_free(ksap23_key->gg); ksap23_key->gg = NULL; }
    if(ksap23_key->XX) { pbcext_element_G2_free(ksap23_key->XX); ksap23_key->XX = NULL; }
    if(ksap23_key->YY) { pbcext_element_G2_free(ksap23_key->YY); ksap23_key->YY = NULL; }
    if(ksap23_key->ZZ0) { pbcext_element_G1_free(ksap23_key->ZZ0); ksap23_key->ZZ0 = NULL; }
    if(ksap23_key->ZZ1) { pbcext_element_G1_free(ksap23_key->ZZ1); ksap23_key->ZZ1 = NULL; }
    if(ksap23_key->h) { pbcext_element_G1_free(ksap23_key->h); ksap23_key->h = NULL; }    
    mem_free(key->key); key->key = NULL;
  }

  mem_free(key); key = NULL;

  return IOK;

}

int ksap23_grp_key_copy(groupsig_key_t *dst, groupsig_key_t *src) {

  ksap23_grp_key_t *ksap23_dst, *ksap23_src;
  int rc;
  
  if(!dst || dst->scheme != GROUPSIG_ksap23_CODE ||
     !src || src->scheme != GROUPSIG_ksap23_CODE) {
    LOG_EINVAL(&logger, __FILE__, "ksap23_grp_key_copy", __LINE__, LOGERROR);
    return IERROR;
  }

  ksap23_dst = dst->key;
  ksap23_src = src->key;
  rc = IOK;

  /* Copy the elements */
  if(!(ksap23_dst->g = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, ksap23_grp_key_copy);
  if(pbcext_element_G1_set(ksap23_dst->g, ksap23_src->g) == IERROR)
    GOTOENDRC(IERROR, ksap23_grp_key_copy);
  if(!(ksap23_dst->gg = pbcext_element_G2_init()))
    GOTOENDRC(IERROR, ksap23_grp_key_copy);  
  if(pbcext_element_G2_set(ksap23_dst->gg, ksap23_src->gg) == IERROR)
    GOTOENDRC(IERROR, ksap23_grp_key_copy);
  if(!(ksap23_dst->XX = pbcext_element_G2_init()))
    GOTOENDRC(IERROR, ksap23_grp_key_copy);  
  if(pbcext_element_G2_set(ksap23_dst->XX, ksap23_src->XX) == IERROR)
    GOTOENDRC(IERROR, ksap23_grp_key_copy);
  if(!(ksap23_dst->YY = pbcext_element_G2_init()))
    GOTOENDRC(IERROR, ksap23_grp_key_copy);  
  if(pbcext_element_G2_set(ksap23_dst->YY, ksap23_src->YY) == IERROR)
    GOTOENDRC(IERROR, ksap23_grp_key_copy);
  if(!(ksap23_dst->ZZ0 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, ksap23_grp_key_copy);  
  if(pbcext_element_G1_set(ksap23_dst->ZZ0, ksap23_src->ZZ0) == IERROR)
    GOTOENDRC(IERROR, ksap23_grp_key_copy);
  if(!(ksap23_dst->ZZ1 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, ksap23_grp_key_copy);  
  if(pbcext_element_G1_set(ksap23_dst->ZZ1, ksap23_src->ZZ1) == IERROR)
    GOTOENDRC(IERROR, ksap23_grp_key_copy);
  if(!(ksap23_dst->h = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, ksap23_grp_key_copy);
  if(pbcext_element_G1_set(ksap23_dst->h, ksap23_src->h) == IERROR)
    GOTOENDRC(IERROR, ksap23_grp_key_copy);

  /*if(hash_update(ksap23_dst->h, ksap23_src->h,ksap23_src->h->length) == IERROR)
    GOTOENDRC(IERROR, ksap23_grp_key_copy);  */

 ksap23_grp_key_copy_end:

  if(rc == IERROR) {
    if (ksap23_dst->g) { pbcext_element_G1_free(ksap23_dst->g); ksap23_dst->g = NULL; }
    if (ksap23_dst->gg) { pbcext_element_G2_free(ksap23_dst->gg); ksap23_dst->gg = NULL; }
    if (ksap23_dst->XX) { pbcext_element_G2_free(ksap23_dst->XX); ksap23_dst->XX = NULL; }
    if (ksap23_dst->YY) { pbcext_element_G2_free(ksap23_dst->YY); ksap23_dst->YY = NULL; }
    if (ksap23_dst->ZZ0) { pbcext_element_G1_free(ksap23_dst->ZZ0); ksap23_dst->ZZ0 = NULL; }
    if (ksap23_dst->ZZ1) { pbcext_element_G1_free(ksap23_dst->ZZ1); ksap23_dst->ZZ1 = NULL; }
    if (ksap23_dst->h) { pbcext_element_G1_free(ksap23_dst->h); ksap23_dst->h = NULL; }

  }
  
  return rc;

}

int ksap23_grp_key_get_size(groupsig_key_t *key) {

  ksap23_grp_key_t *ksap23_key;
  uint64_t size64, sg, sgg, sXX, sYY, sZZ0, sZZ1, sh;
  
  if(!key || key->scheme != GROUPSIG_ksap23_CODE) {
    LOG_EINVAL(&logger, __FILE__, "ksap23_grp_key_get_size", __LINE__, LOGERROR);
    return -1;
  }

  sg = sgg = sXX = sYY = sZZ0 = sZZ1 = sh = 0;

  ksap23_key = key->key;

  if(pbcext_element_G1_byte_size(&sg) == IERROR) return -1;
  if(pbcext_element_G2_byte_size(&sgg) == IERROR) return -1;
  if(pbcext_element_G2_byte_size(&sXX) == IERROR) return -1;
  if(pbcext_element_G2_byte_size(&sYY) == IERROR) return -1;
  if(pbcext_element_G1_byte_size(&sZZ0) == IERROR) return -1;
  if(pbcext_element_G1_byte_size(&sZZ1) == IERROR) return -1;
  if(pbcext_element_G1_byte_size(&sh) == IERROR) return -1;  

  size64 = sizeof(uint8_t)*2 + sizeof(int)*6 + sg + sgg + sXX + sYY + sZZ0 + sZZ1 + sh;
  if (size64 > INT_MAX) return -1;
  
  return (int) size64;  

}

int ksap23_grp_key_export(byte_t **bytes,
			 uint32_t *size,
			 groupsig_key_t *key) {

  ksap23_grp_key_t *ksap23_key;
  byte_t *_bytes, *__bytes;
  uint64_t len;
  int _size, ctr, rc;
  uint8_t code, type;  

  if(!bytes ||
     !size ||
     !key || key->scheme != GROUPSIG_ksap23_CODE) {
    LOG_EINVAL(&logger, __FILE__, "ksap23_grp_key_export", __LINE__, LOGERROR);
    return IERROR;
  }

  rc = IOK;
  ctr = 0;
  ksap23_key = key->key;
  
  /* Get the number of bytes to represent the key */
  if ((_size = ksap23_grp_key_get_size(key)) == -1) {
    return IERROR;
  }

  if(!(_bytes = mem_malloc(sizeof(byte_t)*_size))) {
    return IERROR;
  }
  
  /* Dump GROUPSIG_ksap23_CODE */
  code = GROUPSIG_ksap23_CODE;
  _bytes[ctr++] = code;

  /* Dump key type */
  type = GROUPSIG_KEY_GRPKEY;
  _bytes[ctr++] = GROUPSIG_KEY_GRPKEY;

  /* Dump g */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_G1_bytes(&__bytes, &len, ksap23_key->g) == IERROR) 
    GOTOENDRC(IERROR, ksap23_grp_key_export);
  ctr += len;
  
  /* Dump gg */
  __bytes = &_bytes[ctr];  
  if(pbcext_dump_element_G2_bytes(&__bytes, &len, ksap23_key->gg) == IERROR)
    GOTOENDRC(IERROR, ksap23_grp_key_export);
  ctr += len;
  
  /* Dump XX */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_G2_bytes(&__bytes, &len, ksap23_key->XX) == IERROR)
    GOTOENDRC(IERROR, ksap23_grp_key_export);
  ctr += len;

  /* Dump YY */
  __bytes = &_bytes[ctr];  
  if(pbcext_dump_element_G2_bytes(&__bytes, &len, ksap23_key->YY) == IERROR)    
    GOTOENDRC(IERROR, ksap23_grp_key_export);
  ctr += len;

  /* Dump XX */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_G1_bytes(&__bytes, &len, ksap23_key->ZZ0) == IERROR)
    GOTOENDRC(IERROR, ksap23_grp_key_export);
  ctr += len;

  /* Dump YY */
  __bytes = &_bytes[ctr];  
  if(pbcext_dump_element_G1_bytes(&__bytes, &len, ksap23_key->ZZ1) == IERROR)
    GOTOENDRC(IERROR, ksap23_grp_key_export);
  ctr += len;

  /* Dump h */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_G1_bytes(&__bytes, &len, ksap23_key->h) == IERROR) 
    GOTOENDRC(IERROR, ksap23_grp_key_export);
  ctr += len;  

  /* Prepare the return */
  if(!*bytes) {
    *bytes = _bytes;
  } else {
    memcpy(*bytes, _bytes, ctr);
    mem_free(_bytes); _bytes = NULL;
  }

  /* Sanity check */
  if (ctr != _size) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "ksap23_grp_key_export", __LINE__, 
		      EDQUOT, "Unexpected size.", LOGERROR);
    GOTOENDRC(IERROR, ksap23_grp_key_export);
  }

  *size = ctr;  
  
 ksap23_grp_key_export_end:

  if (rc == IERROR) {
    if(_bytes) { mem_free(_bytes); _bytes = NULL; }
  }
  
  return rc;
  
}

groupsig_key_t* ksap23_grp_key_import(byte_t *source, uint32_t size) {

  groupsig_key_t *key;
  ksap23_grp_key_t *ksap23_key;
  uint64_t len;
  byte_t scheme, type;
  int rc, ctr;
  
  if(!source || !size) {
    LOG_EINVAL(&logger, __FILE__, "ksap23_grp_key_import", __LINE__, LOGERROR);
    return NULL;
  }

  rc = IOK;
  ctr = 0;
  
  if(!(key = ksap23_grp_key_init())) {
    return NULL;
  }

  ksap23_key = key->key;

  /* First byte: scheme */
  scheme = source[ctr++];
  if(scheme != key->scheme) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "ksap23_grp_key_import", __LINE__, 
		      EDQUOT, "Unexpected key scheme.", LOGERROR);
    GOTOENDRC(IERROR, ksap23_grp_key_import);
  }

  /* Next  byte: key type */
  type = source[ctr++];
  if(type != GROUPSIG_KEY_GRPKEY) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "ksap23_grp_key_import", __LINE__,
		      EDQUOT, "Unexpected key scheme.", LOGERROR);
    GOTOENDRC(IERROR, ksap23_grp_key_import);
  }

  /* Get g */
  if(!(ksap23_key->g = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, ksap23_grp_key_import);
  if(pbcext_get_element_G1_bytes(ksap23_key->g, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, ksap23_grp_key_import);
  ctr += len;  

  /* Get gg */
  if(!(ksap23_key->gg = pbcext_element_G2_init()))
    GOTOENDRC(IERROR, ksap23_grp_key_import);
  if(pbcext_get_element_G2_bytes(ksap23_key->gg, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, ksap23_grp_key_import);
  ctr += len;  

  /* Get XX */
  if(!(ksap23_key->XX = pbcext_element_G2_init()))
    GOTOENDRC(IERROR, ksap23_grp_key_import);
  if(pbcext_get_element_G2_bytes(ksap23_key->XX, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, ksap23_grp_key_import);
  ctr += len;  

  /* Get YY */
  if(!(ksap23_key->YY = pbcext_element_G2_init()))
    GOTOENDRC(IERROR, ksap23_grp_key_import);
  if(pbcext_get_element_G2_bytes(ksap23_key->YY, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, ksap23_grp_key_import);
  ctr += len;

  /* Get ZZ0 */
  if(!(ksap23_key->ZZ0 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, ksap23_grp_key_import);
  if(pbcext_get_element_G1_bytes(ksap23_key->ZZ0, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, ksap23_grp_key_import);
  ctr += len;  

  /* Get ZZ1 */
  if(!(ksap23_key->ZZ1 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, ksap23_grp_key_import);
  if(pbcext_get_element_G1_bytes(ksap23_key->ZZ1, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, ksap23_grp_key_import);
  ctr += len;  

  /* Get h */
  if(!(ksap23_key->h = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, ksap23_grp_key_import);
  if(pbcext_get_element_G1_bytes(ksap23_key->h, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, ksap23_grp_key_import);
  ctr += len;
  
 ksap23_grp_key_import_end:
  
  if(rc == IERROR && key) { ksap23_grp_key_free(key); key = NULL; }
  if(rc == IOK) return key;
  
  return NULL; 
  
}

char* ksap23_grp_key_to_string(groupsig_key_t *key) { 
  return NULL;
}

/* grp_key.c ends here */
