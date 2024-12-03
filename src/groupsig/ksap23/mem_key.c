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

#include "ksap23.h"
#include "groupsig/ksap23/mem_key.h"
#include "shim/base64.h"
#include "shim/pbc_ext.h"
#include "misc/misc.h"
#include "sys/mem.h"

groupsig_key_t* ksap23_mem_key_init() {
  
  groupsig_key_t *key;
  ksap23_mem_key_t *ksap23_key;

  if(!(key = (groupsig_key_t *) mem_malloc(sizeof(groupsig_key_t)))) {
    return NULL;
  }

  if(!(key->key = (ksap23_mem_key_t *) mem_malloc(sizeof(ksap23_mem_key_t)))) {
    mem_free(key); key = NULL;
    return NULL;
  }

  key->scheme = GROUPSIG_ksap23_CODE;
  ksap23_key = key->key;
  
  ksap23_key->alpha = NULL;
  ksap23_key->f1 = NULL;
  ksap23_key->f2 = NULL;
  ksap23_key->u = NULL;
  ksap23_key->v = NULL;
  ksap23_key->w = NULL;
  
  return key;

}

int ksap23_mem_key_free(groupsig_key_t *key) {

  ksap23_mem_key_t *ksap23_key;

  if(!key) {
    LOG_EINVAL_MSG(&logger, __FILE__, "ksap23_mem_key_free", __LINE__, 
		   "Nothing to free.", LOGWARN);
    return IOK;  
  }

  if(key->scheme != GROUPSIG_ksap23_CODE) {
    LOG_EINVAL(&logger, __FILE__, "ksap23_mem_key_free", __LINE__, LOGERROR);
    return IERROR;	       
  }

  if(key->key) {
    ksap23_key = key->key;
    if(ksap23_key->alpha) {
      pbcext_element_Fr_free(ksap23_key->alpha);
      ksap23_key->alpha = NULL;
    }
    if(ksap23_key->f1) {
      pbcext_element_G1_free(ksap23_key->f1);
      ksap23_key->f1 = NULL;
    }
    if(ksap23_key->f2) {
      pbcext_element_G1_free(ksap23_key->f2);
      ksap23_key->f2 = NULL;
    }
    if(ksap23_key->u) {
      pbcext_element_G1_free(ksap23_key->u);
      ksap23_key->u = NULL;
    }
    if(ksap23_key->v) {
      pbcext_element_G1_free(ksap23_key->v);
      ksap23_key->v = NULL;
    }
    if(ksap23_key->w) {
      pbcext_element_G1_free(ksap23_key->w);
      ksap23_key->w = NULL;
    }
    mem_free(key->key); key->key = NULL;
    key->key = NULL;
  }
  
  mem_free(key); key = NULL;

  return IOK;

}

int ksap23_mem_key_copy(groupsig_key_t *dst, groupsig_key_t *src) {

  ksap23_mem_key_t *ksap23_dst, *ksap23_src;
  int rc;
  
  if(!dst || dst->scheme != GROUPSIG_ksap23_CODE ||
     !src || src->scheme != GROUPSIG_ksap23_CODE) {
    LOG_EINVAL(&logger, __FILE__, "ksap23_mem_key_copy", __LINE__, LOGERROR);
    return IERROR;
  }

  ksap23_dst = dst->key;
  ksap23_src = src->key;
  rc = IOK;

  /* Copy the elements */
  if(ksap23_src->alpha) {
    if(!(ksap23_dst->alpha = pbcext_element_Fr_init()))
      GOTOENDRC(IERROR, ksap23_mem_key_copy);
    if(pbcext_element_Fr_set(ksap23_dst->alpha, ksap23_src->alpha) == IERROR)
      GOTOENDRC(IERROR, ksap23_mem_key_copy);
  }

  if(ksap23_src->u) {
    if(!(ksap23_dst->f1 = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, ksap23_mem_key_copy); 
    if(pbcext_element_G1_set(ksap23_dst->f1, ksap23_src->f1) == IERROR)
      GOTOENDRC(IERROR, ksap23_mem_key_copy);
  }

  if(ksap23_src->f2) {
    if(!(ksap23_dst->f2 = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, ksap23_mem_key_copy);
    if(pbcext_element_G1_set(ksap23_dst->f2, ksap23_src->f2) == IERROR)
      GOTOENDRC(IERROR, ksap23_mem_key_copy);
  }

  if(ksap23_src->u) {
    if(!(ksap23_dst->u = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, ksap23_mem_key_copy);
    if(pbcext_element_G1_set(ksap23_dst->u, ksap23_src->u) == IERROR)
      GOTOENDRC(IERROR, ksap23_mem_key_copy);    
  }

  if(ksap23_src->v) {
    if(!(ksap23_dst->v = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, ksap23_mem_key_copy);
    if(pbcext_element_G1_set(ksap23_dst->v, ksap23_src->v) == IERROR)
      GOTOENDRC(IERROR, ksap23_mem_key_copy);    
  }

  if(ksap23_src->w) {
    if(!(ksap23_dst->w = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, ksap23_mem_key_copy);
    if(pbcext_element_G1_set(ksap23_dst->w, ksap23_src->w) == IERROR)
      GOTOENDRC(IERROR, ksap23_mem_key_copy);    
  }
  
 ksap23_mem_key_copy_end:

  if(rc == IERROR) {
    if(ksap23_dst->alpha) {
      pbcext_element_Fr_free(ksap23_dst->alpha);
      ksap23_dst->alpha = NULL;
    }
    if(ksap23_dst->f1) {
      pbcext_element_G1_free(ksap23_dst->f1);
      ksap23_dst->f1 = NULL;
    }
    if(ksap23_dst->f2) {
      pbcext_element_G1_free(ksap23_dst->f2);
      ksap23_dst->f2 = NULL;
    }
    if(ksap23_dst->u) {
      pbcext_element_G1_free(ksap23_dst->u);
      ksap23_dst->u = NULL;
    }
    if(ksap23_dst->v) {
      pbcext_element_G1_free(ksap23_dst->v);
      ksap23_dst->v = NULL;
    }
    if(ksap23_dst->w) {
      pbcext_element_G1_free(ksap23_dst->w);
      ksap23_dst->w = NULL;
    }
  }

  return rc;

}

int ksap23_mem_key_get_size(groupsig_key_t *key) {

  ksap23_mem_key_t *ksap23_key;
  uint64_t size64, salpha, sf1, sf2 ,su, sv, sw;
  
  if(!key || key->scheme != GROUPSIG_ksap23_CODE) {
    LOG_EINVAL(&logger, __FILE__, "ksap23_mem_key_get_size", __LINE__, LOGERROR);
    return -1;
  }

  salpha = sf1 = sf2 = su = sv = sw = 0;
  ksap23_key = key->key;
  
  if(ksap23_key->alpha) { if(pbcext_element_Fr_byte_size(&salpha) == IERROR) return -1; }
  if(ksap23_key->f1) { if(pbcext_element_G1_byte_size(&sf1) == IERROR) return -1; }
  if(ksap23_key->f2) { if(pbcext_element_G1_byte_size(&sf2) == IERROR) return -1; }
  if(ksap23_key->u) { if(pbcext_element_G1_byte_size(&su) == IERROR) return -1; }
  if(ksap23_key->v) { if(pbcext_element_G1_byte_size(&sv) == IERROR) return -1; }
  if(ksap23_key->w) { if(pbcext_element_G1_byte_size(&sw) == IERROR) return -1; }

  size64 = sizeof(uint8_t)*2 + sizeof(int)*4+ salpha + sf1 + sf2 + su + sv + sw;

  if(size64 > INT_MAX) return -1;
  return (int) size64;

}

int ksap23_mem_key_export(byte_t **bytes,
			uint32_t *size,
			groupsig_key_t *key) {

  ksap23_mem_key_t *ksap23_key;
  byte_t *_bytes, *__bytes;
  uint64_t len;
  int _size, ctr, rc;
  uint8_t code, type;  
  
  if(!bytes ||
     !size ||
     !key || key->scheme != GROUPSIG_ksap23_CODE) {
    LOG_EINVAL(&logger, __FILE__, "ksap23_mem_key_export", __LINE__, LOGERROR);
    return IERROR;
  }

  rc = IOK;
  ctr = 0;
  ksap23_key = key->key;
  
  /* Get the number of bytes to represent the key */
  if ((_size = ksap23_mem_key_get_size(key)) == -1) {
    return IERROR;
  }

  if(!(_bytes = mem_malloc(sizeof(byte_t)*_size))) {
    return IERROR;
  }
  
  /* Dump GROUPSIG_ksap23_CODE */
  code = GROUPSIG_ksap23_CODE;
  _bytes[ctr++] = code;

  /* Dump key type */
  type = GROUPSIG_KEY_MEMKEY;
  _bytes[ctr++] = GROUPSIG_KEY_MEMKEY;
  
  /* Dump alpha */
  if (ksap23_key->alpha) {
    __bytes = &_bytes[ctr];
    if(pbcext_dump_element_Fr_bytes(&__bytes, &len, ksap23_key->alpha) == IERROR) 
      GOTOENDRC(IERROR, ksap23_mem_key_export);
    ctr += len;
  } else { ctr += sizeof(int); }

  /* Dump f1 */
  if (ksap23_key->f1) {
    __bytes = &_bytes[ctr];
    if(pbcext_dump_element_G1_bytes(&__bytes, &len, ksap23_key->f1) == IERROR)
      GOTOENDRC(IERROR, ksap23_mem_key_export);
    ctr += len;
  } else { ctr += sizeof(int); }

  /* Dump f2 */
  if (ksap23_key->f2) {
    __bytes = &_bytes[ctr];
    if(pbcext_dump_element_G1_bytes(&__bytes, &len, ksap23_key->f2) == IERROR)
      GOTOENDRC(IERROR, ksap23_mem_key_export);
    ctr += len;
  } else { ctr += sizeof(int); }

  /* Dump u */
  if (ksap23_key->u) {
    __bytes = &_bytes[ctr];
    if(pbcext_dump_element_G1_bytes(&__bytes, &len, ksap23_key->u) == IERROR)
      GOTOENDRC(IERROR, ksap23_mem_key_export);
    ctr += len;
  } else { ctr += sizeof(int); }

  /* Dump v */
  if (ksap23_key->v) {
    __bytes = &_bytes[ctr];
    if(pbcext_dump_element_G1_bytes(&__bytes, &len, ksap23_key->v) == IERROR)
      GOTOENDRC(IERROR, ksap23_mem_key_export);
    ctr += len;
  } else { ctr += sizeof(int); }
  
  /* Dump w */
  if (ksap23_key->w) {
    __bytes = &_bytes[ctr];
    if(pbcext_dump_element_G1_bytes(&__bytes, &len, ksap23_key->w) == IERROR) 
      GOTOENDRC(IERROR, ksap23_mem_key_export);
    ctr += len;
  } else { ctr += sizeof(int); }

  /* Sanity check */
  if (ctr != _size) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "ksap23_mem_key_export", __LINE__, 
		      EDQUOT, "Unexpected size.", LOGERROR);
    GOTOENDRC(IERROR, ksap23_mem_key_export);
  }  

  /* Prepare the return */
  if(!*bytes) {
    *bytes = _bytes;
  } else {
    memcpy(*bytes, _bytes, ctr);
    mem_free(_bytes); _bytes = NULL;
  }
  
  *size = ctr;  
  
 ksap23_mem_key_export_end:
  
  if (rc == IERROR) {
    if(_bytes) { mem_free(_bytes); _bytes = NULL; }
  }  

  return rc;
  
}

groupsig_key_t* ksap23_mem_key_import(byte_t *source, uint32_t size) {

  groupsig_key_t *key;
  ksap23_mem_key_t *ksap23_key;
  uint64_t len;
  byte_t scheme, type;
  int rc, ctr;
  
  if(!source || !size) {
    LOG_EINVAL(&logger, __FILE__, "ksap23_mem_key_import", __LINE__, LOGERROR);
    return NULL;
  }

  rc = IOK;
  ctr = 0;
  
  if(!(key = ksap23_mem_key_init())) {
    return NULL;
  }

  ksap23_key = key->key;

  /* First byte: scheme */
  scheme = source[ctr++];
  if(scheme != key->scheme) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "ksap23_mem_key_import", __LINE__, 
		      EDQUOT, "Unexpected key scheme.", LOGERROR);
    GOTOENDRC(IERROR, ksap23_mem_key_import);
  }

  /* Next  byte: key type */
  type = source[ctr++];
  if(type != GROUPSIG_KEY_MEMKEY) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "ksap23_mem_key_import", __LINE__,
		      EDQUOT, "Unexpected key scheme.", LOGERROR);
    GOTOENDRC(IERROR, ksap23_mem_key_import);
  }

  /* Get alpha */
  if(!(ksap23_key->alpha = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, ksap23_mem_key_import);
  if(pbcext_get_element_Fr_bytes(ksap23_key->alpha, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, ksap23_mem_key_import);
  if(!len) {
    ctr += sizeof(int); // @TODO: this is an artifact of pbcext_get_element_XX_bytes
    pbcext_element_Fr_free(ksap23_key->alpha); ksap23_key->alpha = NULL;
  } else {
    ctr += len;
  }

  /* Get f1 */
  if(!(ksap23_key->f1 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, ksap23_mem_key_import);
  if(pbcext_get_element_G1_bytes(ksap23_key->f1, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, ksap23_mem_key_import);
  if(!len) {
    ctr += sizeof(int); // @TODO: this is an artifact of pbcext_get_element_XX_bytes
    pbcext_element_G1_free(ksap23_key->f1); ksap23_key->f1 = NULL;
  } else {
    ctr += len;
  }

  /* Get f2 */  
  if(!(ksap23_key->f2 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, ksap23_mem_key_import);
  if(pbcext_get_element_G1_bytes(ksap23_key->f2, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, ksap23_mem_key_import);
  if(!len) {
    ctr += sizeof(int); // @TODO: this is an artifact of pbcext_get_element_XX_bytes
    pbcext_element_G1_free(ksap23_key->f2); ksap23_key->f2 = NULL;
  } else {
    ctr += len;
  }  

  /* Get u */
  if(!(ksap23_key->u = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, ksap23_mem_key_import);
  if(pbcext_get_element_G1_bytes(ksap23_key->u, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, ksap23_mem_key_import);
  if(!len) {
    ctr += sizeof(int); // @TODO: this is an artifact of pbcext_get_element_XX_bytes
    pbcext_element_G1_free(ksap23_key->u); ksap23_key->u = NULL;
  } else {
    ctr += len;
  }

  /* Get v */  
  if(!(ksap23_key->v = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, ksap23_mem_key_import);
  if(pbcext_get_element_G1_bytes(ksap23_key->v, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, ksap23_mem_key_import);
  if(!len) {
    ctr += sizeof(int); // @TODO: this is an artifact of pbcext_get_element_XX_bytes
    pbcext_element_G1_free(ksap23_key->v); ksap23_key->v = NULL;
  } else {
    ctr += len;
  }  

  /* Get w */
  if(!(ksap23_key->w = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, ksap23_mem_key_import);
  if(pbcext_get_element_G1_bytes(ksap23_key->w, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, ksap23_mem_key_import);
  if(!len) {
    ctr += sizeof(int); // @TODO: this is an artifact of pbcext_get_element_XX_bytes
    pbcext_element_G1_free(ksap23_key->w); ksap23_key->w = NULL;
  } else {
    ctr += len;
  }  
 

 ksap23_mem_key_import_end:
  
  if(rc == IERROR && key) { ksap23_mem_key_free(key); key = NULL; }
  if(rc == IOK) return key;
  
  return NULL; 
}

char* ksap23_mem_key_to_string(groupsig_key_t *key) {

  if(!key || key->scheme != GROUPSIG_ksap23_CODE) {
    LOG_EINVAL(&logger, __FILE__, "ksap23_mem_key_to_string", __LINE__, LOGERROR);
    return NULL;
  }

  return NULL;

}

/* mem_key.c ends here */
