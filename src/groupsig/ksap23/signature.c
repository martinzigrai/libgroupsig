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
#include <math.h>

#include "types.h"
#include "sysenv.h"
#include "sys/mem.h"
#include "shim/base64.h"
#include "shim/pbc_ext.h"
#include "misc/misc.h"
#include "ksap23.h"
#include "groupsig/ksap23/signature.h"

groupsig_signature_t* ksap23_signature_init() {

  groupsig_signature_t *sig;
  ksap23_signature_t *ksap23_sig;

  ksap23_sig = NULL;

  /* Initialize the signature contents */
  if(!(sig = (groupsig_signature_t *) mem_malloc(sizeof(groupsig_signature_t)))) {
    LOG_ERRORCODE(&logger, __FILE__, "ksap23_signature_init", __LINE__, errno, 
		  LOGERROR);
  }

  if(!(ksap23_sig = (ksap23_signature_t *) mem_malloc(sizeof(ksap23_signature_t)))) {
    LOG_ERRORCODE(&logger, __FILE__, "ksap23_signature_init", __LINE__, errno, 
		  LOGERROR);
    return NULL;
  }

  sig->scheme = GROUPSIG_ksap23_CODE;
  sig->sig = ksap23_sig;

  return sig;

}

int ksap23_signature_free(groupsig_signature_t *sig) {

  ksap23_signature_t *ksap23_sig;

  if(!sig || sig->scheme != GROUPSIG_ksap23_CODE) {
    LOG_EINVAL_MSG(&logger, __FILE__, "ksap23_signature_free", __LINE__,
		   "Nothing to free.", LOGWARN);    
    return IOK;
  }

  if(sig->sig) {
    ksap23_sig = sig->sig;
    if(ksap23_sig->uu) {
      pbcext_element_G1_free(ksap23_sig->uu);
      ksap23_sig->uu = NULL;
    }
    if(ksap23_sig->vv) {
      pbcext_element_G1_free(ksap23_sig->vv);
      ksap23_sig->vv = NULL;
    }
    if(ksap23_sig->ww) {
      pbcext_element_G1_free(ksap23_sig->ww);
      ksap23_sig->ww = NULL;
    }
    if(ksap23_sig->c0) {
      pbcext_element_G1_free(ksap23_sig->c0);
      ksap23_sig->c0 = NULL;
    }
    if(ksap23_sig->c1) {
      pbcext_element_G1_free(ksap23_sig->c1);
      ksap23_sig->c1 = NULL;
    }
    if(ksap23_sig->c2) {
      pbcext_element_G1_free(ksap23_sig->c2);
      ksap23_sig->c2 = NULL;
    }
    /*if(ksap23_sig->pi) {
      spk_dlog_free(ksap23_sig->pi);
      ksap23_sig->pi = NULL;
    }*/
    mem_free(ksap23_sig); ksap23_sig = NULL;
  }
  
  mem_free(sig); sig = NULL;

  return IOK;

}

int ksap23_signature_copy(groupsig_signature_t *dst, groupsig_signature_t *src) {

  ksap23_signature_t *ksap23_dst, *ksap23_src;
  int rc;

  if(!dst || dst->scheme != GROUPSIG_ksap23_CODE ||
     !src || src->scheme != GROUPSIG_ksap23_CODE) {
    LOG_EINVAL(&logger, __FILE__, "ksap23_signature_copy", __LINE__, LOGERROR);
    return IERROR;
  }

  ksap23_dst = dst->sig;
  ksap23_src = src->sig;
  rc = IOK;

  /* Copy the elements */
  if(!(ksap23_dst->uu = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, ksap23_signature_copy);
  if(pbcext_element_G1_set(ksap23_dst->uu, ksap23_src->uu) == IERROR)
    GOTOENDRC(IERROR, ksap23_signature_copy);
  if(!(ksap23_dst->vv = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, ksap23_signature_copy);    
  if(pbcext_element_G1_set(ksap23_dst->vv, ksap23_src->vv) == IERROR)
    GOTOENDRC(IERROR, ksap23_signature_copy);
  if(!(ksap23_dst->ww = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, ksap23_signature_copy);    
  if(pbcext_element_G1_set(ksap23_dst->ww, ksap23_src->ww) == IERROR)
    GOTOENDRC(IERROR, ksap23_signature_copy);
  if(!(ksap23_dst->c0 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, ksap23_signature_copy);    
  if(pbcext_element_G1_set(ksap23_dst->c0, ksap23_src->c0) == IERROR)
    GOTOENDRC(IERROR, ksap23_signature_copy);
  if(!(ksap23_dst->c1 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, ksap23_signature_copy);    
  if(pbcext_element_G1_set(ksap23_dst->c1, ksap23_src->c1) == IERROR)
    GOTOENDRC(IERROR, ksap23_signature_copy);
  if(!(ksap23_dst->c2 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, ksap23_signature_copy);    
  if(pbcext_element_G1_set(ksap23_dst->c2, ksap23_src->c2) == IERROR)
    GOTOENDRC(IERROR, ksap23_signature_copy);            
  /*if(!(ksap23_dst->pi = spk_dlog_init()))
    GOTOENDRC(IERROR, ksap23_signature_copy);
  if(spk_dlog_copy(ksap23_dst->pi, ksap23_src->pi) == IERROR)
    GOTOENDRC(IERROR, ksap23_signature_copy);*/
  
 ksap23_signature_copy_end:

  if(rc == IERROR) {
    if(ksap23_dst->uu) {
      pbcext_element_G1_free(ksap23_dst->uu);
      ksap23_dst->uu = NULL;
    }
    if(ksap23_dst->vv) {
      pbcext_element_G1_free(ksap23_dst->vv);
      ksap23_dst->vv = NULL;
    }
    if(ksap23_dst->ww) {
      pbcext_element_G1_free(ksap23_dst->ww);
      ksap23_dst->ww = NULL;
    }
    if(ksap23_dst->c0) {
      pbcext_element_G1_free(ksap23_dst->c0);
      ksap23_dst->c0 = NULL;
    }
    if(ksap23_dst->c1) {
      pbcext_element_G1_free(ksap23_dst->c1);
      ksap23_dst->c1 = NULL;
    }
    if(ksap23_dst->c2) {
      pbcext_element_G1_free(ksap23_dst->c2);
      ksap23_dst->c2 = NULL;
    }
    /*if(ksap23_dst->pi) {
      spk_dlog_free(ksap23_dst->pi);
      ksap23_dst->pi = NULL;
    }*/

  }
  
  return rc;

}

int ksap23_signature_get_size(groupsig_signature_t *sig) {

  ksap23_signature_t *ksap23_sig;
  uint64_t size64, suu, svv, sww, sc0, sc1, sc2, ss, sc;  
  
  if(!sig || sig->scheme != GROUPSIG_ksap23_CODE) {
    LOG_EINVAL(&logger, __FILE__, "ksap23_signature_get_size",
	       __LINE__, LOGERROR);
    return -1;
  }

  suu = svv = sww = sc0 = sc1 = sc2 = ss = sc = 0;

  ksap23_sig = sig->sig;

  if(pbcext_element_G1_byte_size(&suu) == IERROR) return -1;
  if(pbcext_element_G1_byte_size(&svv) == IERROR) return -1;
  if(pbcext_element_G1_byte_size(&sww) == IERROR) return -1;
  if(pbcext_element_G1_byte_size(&sc0) == IERROR) return -1;
  if(pbcext_element_G1_byte_size(&sc1) == IERROR) return -1;
  if(pbcext_element_G1_byte_size(&sc2) == IERROR) return -1;
  if(pbcext_element_Fr_byte_size(&sc) == IERROR) return -1;
  if(pbcext_element_Fr_byte_size(&ss) == IERROR) return -1;  
      
  size64 = sizeof(uint8_t) + sizeof(int)*5 + suu + svv + sww + sc0 + sc1 + sc2 + sc + ss;

  if(size64 > INT_MAX) return -1;
  return (int) size64;

}

int ksap23_signature_export(byte_t **bytes,
			  uint32_t *size,
			  groupsig_signature_t *sig) {

  ksap23_signature_t *ksap23_sig;
  byte_t *_bytes, *__bytes;
  uint64_t len;
  int rc, ctr, _size;
  uint8_t code;
  
  if(!sig || sig->scheme != GROUPSIG_ksap23_CODE) {
    LOG_EINVAL(&logger, __FILE__, "ksap23_signature_export", __LINE__, LOGERROR);
    return IERROR;
  }

  rc = IOK;
  ctr = 0;
  ksap23_sig = sig->sig;

  if ((_size = ksap23_signature_get_size(sig)) == -1) {
    return IERROR;
  }

  if (!(_bytes = mem_malloc(sizeof(byte_t)*_size))) {
    return IERROR;
  }  
  
  /* Dump GROUPSIG_ksap23_CODE */
  code = GROUPSIG_ksap23_CODE;
  _bytes[ctr++] = code;

  /* Dump uu */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_G1_bytes(&__bytes, &len, ksap23_sig->uu) == IERROR) 
    GOTOENDRC(IERROR, ksap23_signature_export);
  ctr += len;  

  /* Dump vv */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_G1_bytes(&__bytes, &len, ksap23_sig->vv) == IERROR) 
    GOTOENDRC(IERROR, ksap23_signature_export);
  ctr += len;

  /* Dump ww */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_G1_bytes(&__bytes, &len, ksap23_sig->ww) == IERROR) 
    GOTOENDRC(IERROR, ksap23_signature_export);
  ctr += len;

  /* Dump c0 */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_G1_bytes(&__bytes, &len, ksap23_sig->c0) == IERROR) 
    GOTOENDRC(IERROR, ksap23_signature_export);
  ctr += len;

  /* Dump c1 */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_G1_bytes(&__bytes, &len, ksap23_sig->c1) == IERROR) 
    GOTOENDRC(IERROR, ksap23_signature_export);
  ctr += len;

  /* Dump c2 */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_G1_bytes(&__bytes, &len, ksap23_sig->c2) == IERROR) 
    GOTOENDRC(IERROR, ksap23_signature_export);
  ctr += len;    

  /* Dump pi->c */
  /*__bytes = &_bytes[ctr];
  if(pbcext_dump_element_Fr_bytes(&__bytes, &len, ksap23_sig->pi->c) == IERROR) //tu to treba upravit na potreby ksap23
    GOTOENDRC(IERROR, ksap23_signature_export);
  ctr += len;*/

  /* Dump pi->s */
  /*__bytes = &_bytes[ctr];
  if(pbcext_dump_element_Fr_bytes(&__bytes, &len, ksap23_sig->pi->s) == IERROR)  //same ako komentar predtym
    GOTOENDRC(IERROR, ksap23_signature_export);
  ctr += len;*/  

  /* Sanity check */
  if (ctr != _size) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "ksap23_signature_export", __LINE__, 
		      EDQUOT, "Unexpected size.", LOGERROR);
    GOTOENDRC(IERROR, ksap23_signature_export);
  }
  
  /* Prepare the return */
  if(!*bytes) {
    *bytes = _bytes;
  } else {
    memcpy(*bytes, _bytes, ctr);
    mem_free(_bytes); _bytes = NULL;
  }

  *size = ctr;  

 ksap23_signature_export_end:
  
  if (rc == IERROR && _bytes) { mem_free(_bytes); _bytes = NULL; }
  return rc;  

}

groupsig_signature_t* ksap23_signature_import(byte_t *source, uint32_t size) {

  groupsig_signature_t *sig;
  ksap23_signature_t *ksap23_sig;
  uint64_t len;
  int rc, ctr;
  uint8_t scheme;
  
  if(!source || !size) {
    LOG_EINVAL(&logger, __FILE__, "ksap23_signature_import", __LINE__, LOGERROR);
    return NULL;
  }

  rc = IOK;
  ctr = 0;

  if(!(sig = ksap23_signature_init())) {
    return NULL;
  }
  
  ksap23_sig = sig->sig;

  /* First byte: scheme */
  scheme = source[ctr++];
  if(scheme != sig->scheme) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "ksap23_signature_import", __LINE__, 
		      EDQUOT, "Unexpected signature scheme.", LOGERROR);
    GOTOENDRC(IERROR, ksap23_signature_import);
  }

  /* Get uu */
  if(!(ksap23_sig->uu = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, ksap23_signature_import);
  if(pbcext_get_element_G1_bytes(ksap23_sig->uu, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, ksap23_signature_import);
  ctr += len;

  /* Get vv */
  if(!(ksap23_sig->vv = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, ksap23_signature_import);
  if(pbcext_get_element_G1_bytes(ksap23_sig->vv, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, ksap23_signature_import);
  ctr += len;

  /* Get ww */
  if(!(ksap23_sig->ww = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, ksap23_signature_import);
  if(pbcext_get_element_G1_bytes(ksap23_sig->ww, &len, &source[ctr]) == IERROR) 
    GOTOENDRC(IERROR, ksap23_signature_import);
  ctr += len;  

  /* Get c0 */
  if(!(ksap23_sig->c0 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, ksap23_signature_import);
  if(pbcext_get_element_G1_bytes(ksap23_sig->c0, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, ksap23_signature_import);
  ctr += len;

  /* Get c1 */
  if(!(ksap23_sig->c1 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, ksap23_signature_import);
  if(pbcext_get_element_G1_bytes(ksap23_sig->c1, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, ksap23_signature_import);
  ctr += len;

  /* Get c2 */
  if(!(ksap23_sig->c2 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, ksap23_signature_import);
  if(pbcext_get_element_G1_bytes(ksap23_sig->c2, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, ksap23_signature_import);
  ctr += len;

  /* Get c */
  /*if (!(ksap23_sig->pi = spk_dlog_init()))
    GOTOENDRC(IERROR, ksap23_signature_import);
  
  if(!(ksap23_sig->pi->c = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, ksap23_signature_import);
  if(pbcext_get_element_Fr_bytes(ksap23_sig->pi->c, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, ksap23_signature_import);
  ctr += len;*/

  /* Get s */
  /*if(!(ksap23_sig->pi->s = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, ksap23_signature_import);
  if(pbcext_get_element_Fr_bytes(ksap23_sig->pi->s, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, ksap23_signature_import);
  ctr += len;*/

 ksap23_signature_import_end:

  if(rc == IERROR && sig) { ksap23_signature_free(sig); sig = NULL; }
  if(rc == IOK) return sig;
  return NULL;  

}

// @TODO this is not what I'd like from a to_string function.
// this should return a human readable string with the contents
// of the signature.
char* ksap23_signature_to_string(groupsig_signature_t *sig) {

  uint32_t size;
  byte_t *bytes;
  char *str;
  
  if(!sig || sig->scheme != GROUPSIG_ksap23_CODE) {
    LOG_EINVAL(&logger, __FILE__, "signature_to_string", __LINE__, LOGERROR);
    return NULL;
  }

  bytes = NULL;
  if(ksap23_signature_export(&bytes, &size, sig) == IERROR) return NULL;
  str = base64_encode(bytes, size, 1);
  mem_free(bytes); bytes = NULL;

  return str;
}

/* signature.c ends here */
