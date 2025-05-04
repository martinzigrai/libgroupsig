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
 #include <unistd.h>
 
 #include "types.h"
 #include "sysenv.h"
 #include "sys/mem.h"
 #include "shim/pbc_ext.h"
 #include "ksap23.h"
 //#include "groupsig/ksap23/spk.h"
 #include "groupsig/ksap23/nizk.h"
 #include "groupsig/ksap23/proof.h"

 
groupsig_proof_t* ksap23_proof_init() {

    groupsig_proof_t *proof;
    ksap23_proof_t *ksap23_proof;
    

    ksap23_proof = NULL;

     /* Initialize the signature contents */
    if(!(proof = (groupsig_proof_t *) mem_malloc(sizeof(groupsig_proof_t)))) {
      LOG_ERRORCODE(&logger, __FILE__, "ksap23_proof_init", __LINE__, errno, 
        LOGERROR);
    }

    if(!(ksap23_proof = (ksap23_proof_t *) mem_malloc(sizeof(ksap23_proof_t)))) {
      LOG_ERRORCODE(&logger, __FILE__, "ksap23_proof_init", __LINE__, errno, 
        LOGERROR);
      return NULL;
    }

    proof->scheme = GROUPSIG_ksap23_CODE;
    proof->proof = ksap23_proof;

    return proof;
    
    //int rc = IOK;
    
    /*if(!(proof = mem_malloc(sizeof(groupsig_proof_t)))) {
        //printf("Proof je prvy NULL");
        return NULL;
        //GOTOENDRC(IERROR, ksap23_proof_init);
    }

    if(!(ksap23_proof = mem_malloc(sizeof(ksap23_proof_t)))) {
      //printf("Proof je prvy NULL");
        mem_free(proof); proof = NULL;
        return NULL;
        //GOTOENDRC(IERROR, ksap23_proof_init);
    }


    ksap23_proof->pi = NULL;
    ksap23_proof->f1 = NULL;
    ksap23_proof->f2 = NULL;

    if (!(ksap23_proof->pi = spk_rep_init(2)) ||
        !(ksap23_proof->f1 = pbcext_element_G1_init()) ||
        !(ksap23_proof->f2 = pbcext_element_G1_init())) {
        
        if (ksap23_proof->pi) spk_rep_free(ksap23_proof->pi);
        if (ksap23_proof->f1) pbcext_element_G1_free(ksap23_proof->f1);
        if (ksap23_proof->f2) pbcext_element_G1_free(ksap23_proof->f2);
        mem_free(ksap23_proof);
        mem_free(proof);
        return NULL;
    }

    /*if (!ksap23_proof->pi || !ksap23_proof->f1 || !ksap23_proof->f2) {
        ksap23_proof_free(proof); // Uvoľnenie čiastočne alokovanej pamäte
        return NULL;
    }

    if(proof == NULL){
      printf("Proof je NULL");
    } else {
      printf("proof nie je null");
    }

    proof->scheme = GROUPSIG_ksap23_CODE;
    proof->proof = ksap23_proof;

    return proof;*/

}

int ksap23_proof_free(groupsig_proof_t *proof) {
    //if (!proof) return IOK;
    ksap23_proof_t *ksap23_proof;

    if(!proof || proof->scheme != GROUPSIG_ksap23_CODE) {
      LOG_EINVAL_MSG(&logger, __FILE__, "ksap23_proof_free", __LINE__,
         "Nothing to free.", LOGWARN);    
      return IOK;
    }

    if(proof->proof) {
      ksap23_proof = proof->proof;
      if(ksap23_proof->f1) {
        pbcext_element_G1_free(ksap23_proof->f1);
        ksap23_proof->f1 = NULL;
      }
      if(ksap23_proof->f2) {
        pbcext_element_G1_free(ksap23_proof->f2);
        ksap23_proof->f2 = NULL;
      }
      if(ksap23_proof->pi) {
        spk_rep_free(ksap23_proof->pi);
        ksap23_proof->pi = NULL;
      }
      mem_free(ksap23_proof); ksap23_proof = NULL;
    }
    
    mem_free(proof); proof = NULL;
  
    return IOK;

    /*if (!proof) {
      LOG_EINVAL_MSG(&logger, __FILE__, "ksap23_proof_free", __LINE__,
         "Nothing to free.", LOGWARN);
      return IERROR;
    }

    if(proof->scheme != GROUPSIG_ksap23_CODE) {
      LOG_EINVAL(&logger, __FILE__, "ksap23_proof_free", __LINE__, LOGERROR);
      return IERROR;	       
    }*/
    
    /*if (proof->proof) {
        //ksap23_proof_internal_free((ksap23_proof_t*)proof->proof);
        ksap23_proof = proof->proof;
        if(ksap23_proof->pi){
          spk_rep_free(ksap23_proof->pi);
          ksap23_proof->pi = NULL;
        }
        if(ksap23_proof->f1){
          pbcext_element_G1_free(ksap23_proof->f1);
          ksap23_proof->f1 = NULL;
        }
        if(ksap23_proof->f2){
          pbcext_element_G1_free(ksap23_proof->f2);
          ksap23_proof->f2 = NULL;
        }
        mem_free(ksap23_proof);
    }
    mem_free(proof); proof = NULL;

    return IOK;*/
}

int ksap23_proof_export(byte_t **bytes,
      uint32_t *size,
      groupsig_proof_t *proof) {

    ksap23_proof_t *ksap23_proof;
    byte_t *_bytes, *__bytes;
    uint64_t len;
    int _size, ctr, rc;
    uint8_t code;

    if(!bytes ||
     !size ||
     !proof || proof->scheme != GROUPSIG_ksap23_CODE) {
    LOG_EINVAL(&logger, __FILE__, "ksap23_proof_export", __LINE__, LOGERROR);
    return IERROR;
  }

  rc = IOK;
  ctr = 0;
  ksap23_proof = proof->proof;

  if((_size = ksap23_proof_get_size(proof)) == -1){
    return IERROR;
  }

  if(!(_bytes = mem_malloc(sizeof(byte_t)*_size))) {
    return IERROR;
  }

  code = GROUPSIG_ksap23_CODE;
  _bytes[ctr++] = code;

  /* Dump pi->c */
  if(ksap23_proof->pi->c){
    __bytes = &_bytes[ctr];
    if(pbcext_dump_element_Fr_bytes(&__bytes, &len, ksap23_proof->pi->c) == IERROR) 
      GOTOENDRC(IERROR, ksap23_proof_export);
    ctr += len;

  } else {ctr += sizeof(int); }

  /* Dump pi->s1 */
  if(ksap23_proof->pi->s[0]){
    __bytes = &_bytes[ctr];
    if(pbcext_dump_element_Fr_bytes(&__bytes, &len, ksap23_proof->pi->s[0]) == IERROR) 
      GOTOENDRC(IERROR, ksap23_proof_export);
    ctr += len;

  } else {ctr += sizeof(int); }

  /* Dump pi->s2 */
  if(ksap23_proof->pi->s[1]){
    __bytes = &_bytes[ctr];
    if(pbcext_dump_element_Fr_bytes(&__bytes, &len, ksap23_proof->pi->s[1]) == IERROR) 
      GOTOENDRC(IERROR, ksap23_proof_export);
    ctr += len;

  } else {ctr += sizeof(int); }

  /* Dump f1 */
  if(ksap23_proof->f1){
    __bytes = &_bytes[ctr];
    if(pbcext_dump_element_G1_bytes(&__bytes, &len, ksap23_proof->f1) == IERROR) 
      GOTOENDRC(IERROR, ksap23_proof_export);
    ctr += len;
    
  } else {ctr += sizeof(int); }

  /* Dump f2 */
  if(ksap23_proof->f2){
    __bytes = &_bytes[ctr];
    if(pbcext_dump_element_G1_bytes(&__bytes, &len, ksap23_proof->f2) == IERROR) 
      GOTOENDRC(IERROR, ksap23_proof_export);
    ctr += len;
    
  } else {ctr += sizeof(int); }

  if (ctr != _size) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "ksap23_proof_export", __LINE__, 
		      EDQUOT, "Unexpected size.", LOGERROR);
    GOTOENDRC(IERROR, ksap23_proof_export);
  }  

  if(!*bytes){
    *bytes = _bytes;
  } else {
    memcpy(*bytes, _bytes, ctr);
    mem_free(_bytes); _bytes = NULL;
  }

  *size = ctr;

  ksap23_proof_export_end:

  if(rc == IERROR){
    if(_bytes) {mem_free(_bytes); _bytes = NULL; }
  }

  return rc;
}

groupsig_proof_t* ksap23_proof_import(byte_t *source, uint32_t size) {

    groupsig_proof_t *proof;
    ksap23_proof_t *ksap23_proof;
    uint64_t len;
    byte_t scheme; //mozno treba type taktiez aj do export ale myslim ze netreba
    int rc, ctr;

    if(!source || !size) {
      LOG_EINVAL(&logger, __FILE__, "ksap23_proof_import", __LINE__, LOGERROR);
      return NULL;
    }
  
    rc = IOK;
    ctr = 0;

    if(!(proof = ksap23_proof_init())) {
      return NULL;
    }

    ksap23_proof = proof->proof;

    scheme = source[ctr++];
    if(scheme != proof->scheme) {
       LOG_ERRORCODE_MSG(&logger, __FILE__, "ksap23_proof_import", __LINE__, 
		      EDQUOT, "Unexpected proof scheme.", LOGERROR);
       GOTOENDRC(IERROR, ksap23_proof_import);
    }

    /* Get c */
    if(!(ksap23_proof->pi = spk_rep_init(2)))
      GOTOENDRC(IERROR, ksap23_proof_import);

    if(!(ksap23_proof->pi->c = pbcext_element_Fr_init()))
      GOTOENDRC(IERROR, ksap23_proof_import);  
    if(pbcext_get_element_Fr_bytes(ksap23_proof->pi->c, &len, &source[ctr]) == IERROR)
      GOTOENDRC(IERROR, ksap23_proof_import);
    ctr += len;  
    if(!len) {
      ctr += sizeof(int); // @TODO: this is an artifact of pbcext_get_element_XX_bytes
      spk_rep_free(ksap23_proof->pi); ksap23_proof->pi = NULL;
    } else {
      ctr += len;
    }

    /* Get s1 */
    if(!(ksap23_proof->pi->s[0] = pbcext_element_Fr_init()))
      GOTOENDRC(IERROR, ksap23_proof_import);  
    if(pbcext_get_element_Fr_bytes(ksap23_proof->pi->s[0], &len, &source[ctr]) == IERROR)
      GOTOENDRC(IERROR, ksap23_proof_import);
    ctr += len;  
    if(!len) {
      ctr += sizeof(int); // @TODO: this is an artifact of pbcext_get_element_XX_bytes
      spk_rep_free(ksap23_proof->pi); ksap23_proof->pi = NULL;
    } else {
      ctr += len;
    }


    /* Get s2 */
    if(!(ksap23_proof->pi->s[1] = pbcext_element_Fr_init()))
      GOTOENDRC(IERROR, ksap23_proof_import);  
    if(pbcext_get_element_Fr_bytes(ksap23_proof->pi->s[1], &len, &source[ctr]) == IERROR)
      GOTOENDRC(IERROR, ksap23_proof_import);
    ctr += len;  
    if(!len) {
      ctr += sizeof(int); // @TODO: this is an artifact of pbcext_get_element_XX_bytes
      spk_rep_free(ksap23_proof->pi); ksap23_proof->pi = NULL;
    } else {
      ctr += len;
    }

    if(!(ksap23_proof->f1 = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, ksap23_proof_import);
    if(pbcext_get_element_G1_bytes(ksap23_proof->f1, &len, &source[ctr]) == IERROR)
      GOTOENDRC(IERROR, ksap23_proof_import);
    if(!len) {
      ctr += sizeof(int); // @TODO: this is an artifact of pbcext_get_element_XX_bytes
      pbcext_element_G1_free(ksap23_proof->f1); ksap23_proof->f1 = NULL;
    } else {
      ctr += len;
   }

   if(!(ksap23_proof->f2 = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, ksap23_proof_import);
   if(pbcext_get_element_G1_bytes(ksap23_proof->f2, &len, &source[ctr]) == IERROR)
      GOTOENDRC(IERROR, ksap23_proof_import);
   if(!len) {
      ctr += sizeof(int); // @TODO: this is an artifact of pbcext_get_element_XX_bytes
      pbcext_element_G1_free(ksap23_proof->f2); ksap23_proof->f2 = NULL;
   } else {
      ctr += len;
   }

  ksap23_proof_import_end:

   if(rc == IERROR && proof) { ksap23_proof_free(proof); proof = NULL; }
   if(rc == IOK) return proof;
  
   return NULL; 
   
}

int ksap23_proof_get_size(groupsig_proof_t *proof) {
    
  ksap23_proof_t *ksap23_proof;
  uint64_t f1_len, f2_len, pi_len, total_size;

    /*if (!proof || !proof->proof) {
        return -1;
    }*/

  if(!proof || !proof->proof || proof->scheme != GROUPSIG_ksap23_CODE) {
      LOG_EINVAL(&logger, __FILE__, "ksap23_proof_get_size", __LINE__, LOGERROR);
      return -1;
  }
  
  //ksap23_proof = proof->proof;
    

  /*if(!proof || proof->scheme != GROUPSIG_ksap23_CODE) {
    LOG_EINVAL(&logger, __FILE__, "ksap23_proof_get_size", __LINE__, LOGERROR);
    return -1;
  }*/

  f1_len = f2_len = pi_len = 0;
  ksap23_proof = proof->proof;

  if(ksap23_proof->pi) {
     /*if(spk_rep_get_size(&pi_len) == IERROR) return -1;
     }*/
    int size = spk_rep_get_size(ksap23_proof->pi);
    if(size == IERROR) return -1;

    pi_len = size;
    printf("%" PRIu64 "\n", pi_len);
  }
  if(ksap23_proof->f1) { if(pbcext_element_G1_byte_size(&f1_len) == IERROR) return -1; }
  if(ksap23_proof->f2) { if(pbcext_element_G1_byte_size(&f2_len) == IERROR) return -1; }

  total_size = sizeof(uint8_t) + sizeof(int)*3 + f1_len + f2_len + pi_len;

  if(total_size > INT_MAX) return -1;
  return (int)total_size;
}

char* ksap23_proof_to_string(groupsig_proof_t *proof) {
 
  if(!proof || proof->scheme != GROUPSIG_ksap23_CODE) {
    LOG_EINVAL(&logger, __FILE__, "ksap23_proof_to_string", __LINE__, LOGERROR);
    return NULL;
  }
  
  return NULL;

}
 
 /* proof.c ends here */
 