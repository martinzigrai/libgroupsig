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

#include <stdlib.h>
#include <limits.h>

#include "ksap23.h"
#include "groupsig/ksap23/grp_key.h"
#include "groupsig/ksap23/mem_key.h"
#include "groupsig/ksap23/signature.h"
#include "groupsig/ksap23/nizk.h"
#include "crypto/spk.h"
#include "shim/pbc_ext.h"
#include "sys/mem.h"

int ksap23_sign(groupsig_signature_t *sig,
		message_t *msg,
		groupsig_key_t *memkey,
		groupsig_key_t *grpkey,
		unsigned int seed) {

  pbcext_element_Fr_t *r;  //random element r
  pbcext_element_Fr_t *s;  //random element s
  pbcext_element_G1_t *D1s, *D2s; //D1^s
  ksap23_signature_t *ksap23_sig;
  ksap23_grp_key_t *ksap23_grpkey;
  ksap23_mem_key_t *ksap23_memkey;
  int rc;
  
  if(!sig || !msg || 
     !memkey || memkey->scheme != GROUPSIG_ksap23_CODE ||
     !grpkey || grpkey->scheme != GROUPSIG_ksap23_CODE) {
    LOG_EINVAL(&logger, __FILE__, "ksap23_sign", __LINE__, LOGERROR);
    return IERROR;
  }

  ksap23_sig = sig->sig;
  ksap23_grpkey = grpkey->key;
  ksap23_memkey = memkey->key;
  r = s = NULL;
  D1s = D2s = NULL;
  rc = IOK;

  /* Randomize u, v and w */
  if (!(r = pbcext_element_Fr_init())) GOTOENDRC(IERROR, ksap23_sign);
  if (pbcext_element_Fr_random(r) == IERROR) GOTOENDRC(IERROR, ksap23_sign);

  if (!(ksap23_sig->uu = pbcext_element_G1_init())) GOTOENDRC(IERROR, ksap23_sign);
  if (pbcext_element_G1_mul(ksap23_sig->uu, ksap23_memkey->u, r) == IERROR)
    GOTOENDRC(IERROR, ksap23_sign);
  if (!(ksap23_sig->vv = pbcext_element_G1_init())) GOTOENDRC(IERROR, ksap23_sign);
  if (pbcext_element_G1_mul(ksap23_sig->vv, ksap23_memkey->v, r) == IERROR)
    GOTOENDRC(IERROR, ksap23_sign);
  if (!(ksap23_sig->ww = pbcext_element_G1_init())) GOTOENDRC(IERROR, ksap23_sign);
  if (pbcext_element_G1_mul(ksap23_sig->ww, ksap23_memkey->w, r) == IERROR)
    GOTOENDRC(IERROR, ksap23_sign);

  /*Compute c0, c1 and c2*/
  if (!(s = pbcext_element_Fr_init())) GOTOENDRC(IERROR, ksap23_sign);
  if (pbcext_element_Fr_random(s) == IERROR) GOTOENDRC(IERROR, ksap23_sign);

  if (!(ksap23_sig->c0 = pbcext_element_G1_init())) GOTOENDRC(IERROR, ksap23_sign);
  if (pbcext_element_G1_mul(ksap23_sig->c0, ksap23_grpkey->g, s) == IERROR)
    GOTOENDRC(IERROR, ksap23_sign);
  
  /*c1 = f1*D1^s */
  if(!(D1s = pbcext_element_G1_init())) GOTOENDRC(IERROR, ksap23_sign);
  if(pbcext_element_G1_mul(D1s,
	     ksap23_grpkey->ZZ0,
	     s) == IERROR)
      GOTOENDRC(IERROR, ksap23_sign);
  if(!(ksap23_sig->c1 = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, ksap23_sign);
    if(pbcext_element_G1_add(ksap23_sig->c1, ksap23_memkey->f1, D1s) == IERROR)
      GOTOENDRC(IERROR, ksap23_sign);

  /*c2 = f2*D2^s */ 
  if(!(D2s = pbcext_element_G1_init())) GOTOENDRC(IERROR, ksap23_sign);
  if(pbcext_element_G1_mul(D2s,
	     ksap23_grpkey->ZZ1,
	     s) == IERROR)
      GOTOENDRC(IERROR, ksap23_sign);
  if(!(ksap23_sig->c2 = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, ksap23_sign);
    if(pbcext_element_G1_add(ksap23_sig->c2, ksap23_memkey->f2, D2s) == IERROR)
      GOTOENDRC(IERROR, ksap23_sign);


  /* Compute signature of knowledge of alpha */ //toto prerobit na ksap NIZK
  /*if (!(ksap23_sig->pi = spk_dlog_init()))
    GOTOENDRC(IERROR, ksap23_sign);
  if (spk_dlog_G1_sign(ksap23_sig->pi,
		       ksap23_sig->ww,
		       ksap23_sig->uu,
		       ksap23_memkey->alpha,
		       msg->bytes,
		       msg->length) == IERROR)
    GOTOENDRC(IERROR, ksap23_sign);*/

    if(!(ksap23_sig->pi = spk_rep_init(2))) GOTOENDRC(IERROR, ksap23_sign);
    if (ksap23_snizk2_sign(ksap23_sig->pi,
          ksap23_sig->uu,
          ksap23_grpkey->g,  // g
          ksap23_grpkey->h,
          ksap23_grpkey->ZZ0,
          ksap23_grpkey->ZZ1,
          ksap23_sig->ww,
          ksap23_sig->c0,
          ksap23_sig->c1,
          ksap23_sig->c2,
          ksap23_memkey->alpha,
          s,
          msg->bytes,
		      msg->length) == IERROR)
      GOTOENDRC(IERROR, ksap23_sign);
  

 ksap23_sign_end:

  if (r) { pbcext_element_Fr_free(r); r = NULL; }

  if (rc == IERROR) {
    
    if (ksap23_sig->uu) {
      pbcext_element_G1_free(ksap23_sig->uu);
      ksap23_sig->uu = NULL;
    }
    if (ksap23_sig->vv) {
      pbcext_element_G1_free(ksap23_sig->vv);
      ksap23_sig->vv = NULL;
    }
    if (ksap23_sig->ww) {
      pbcext_element_G1_free(ksap23_sig->ww);
      ksap23_sig->ww = NULL;
    }
    if (ksap23_sig->c0) {
      pbcext_element_G1_free(ksap23_sig->c0);
      ksap23_sig->c0 = NULL;
    }
    if (ksap23_sig->c1) {
      pbcext_element_G1_free(ksap23_sig->c1);
      ksap23_sig->c1 = NULL;
    }
    if (ksap23_sig->c2) {
      pbcext_element_G1_free(ksap23_sig->c2);
      ksap23_sig->c2 = NULL;
    }
    if (ksap23_sig->pi) {
      spk_rep_free(ksap23_sig->pi);
      ksap23_sig->pi = NULL;
    }    
    
  }
  
  return rc;
  
}

/* sign.c ends here */
