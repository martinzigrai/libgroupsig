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
#include <math.h>

#include "ksap23.h" 
#include "logger.h"
#include "groupsig/ksap23/grp_key.h"
#include "groupsig/ksap23/mgr_key.h"
#include "groupsig/ksap23/gml.h"
#include "sys/mem.h"
#include "shim/pbc_ext.h"

int ksap23_init() {

  if(pbcext_init(BLS12_381) == IERROR) {
    return IERROR;
  }  

  return IOK;

}

int ksap23_clear() {  
  return IOK;
}

int ksap23_setup(groupsig_key_t *grpkey,
		 groupsig_key_t *mgrkey,
		 gml_t *gml) {

  ksap23_grp_key_t *gkey; 
  ksap23_mgr_key_t *mkey;
  //pbcext_element_Fr_t *inv = NULL;
  int rc;
  uint8_t call;

  if(!grpkey || grpkey->scheme != GROUPSIG_ksap23_CODE ||
     !mgrkey || mgrkey->scheme != GROUPSIG_ksap23_CODE ||
     !gml) {
    LOG_EINVAL(&logger, __FILE__, "ksap23_setup", __LINE__, LOGERROR);
    return IERROR;
  }

  gkey = grpkey->key;
  mkey = mgrkey->key;
  
  rc = IOK;
  call = 0;

  byte_t *bf = NULL;
  uint64_t len;
  hash_t *h = NULL;

  /* 
   * If the group key is "empty" (we check gkey->g for this), we interpret this
   * as the first call. In this case, we generate the Issuer's keypair, and all 
   * the group public key except for the Opener's public key.
   */
  if (!gkey->g) {

    call = 1;

    /* Initialize the Issuer's key */
    if(!(mkey->x = pbcext_element_Fr_init())) GOTOENDRC(IERROR, ksap23_setup);
    if(pbcext_element_Fr_random(mkey->x) == IERROR)
      GOTOENDRC(IERROR, ksap23_setup);

    if(!(mkey->y = pbcext_element_Fr_init())) GOTOENDRC(IERROR, ksap23_setup);
    if(pbcext_element_Fr_random(mkey->y) == IERROR)
      GOTOENDRC(IERROR, ksap23_setup);    

    /* Initialize the group key */

    /* Compute random generators g and gg. Since G1 and G2 are cyclic
       groups of prime order, just pick random elements.  */
    if(!(gkey->g = pbcext_element_G1_init())) GOTOENDRC(IERROR, ksap23_setup);
    if(pbcext_element_G1_random(gkey->g) == IERROR)
      GOTOENDRC(IERROR, ksap23_setup);
    
    if(!(gkey->gg = pbcext_element_G2_init())) GOTOENDRC(IERROR, ksap23_setup);
    if(pbcext_element_G2_random(gkey->gg) == IERROR)
      GOTOENDRC(IERROR, ksap23_setup);
    
    /* Partially fill the group key with the Issuer's public key */
    if(!(gkey->XX = pbcext_element_G2_init())) GOTOENDRC(IERROR, ksap23_setup);
    if(pbcext_element_G2_mul(gkey->XX, gkey->gg, mkey->x) == IERROR)
      GOTOENDRC(IERROR, ksap23_setup);

    if(!(gkey->YY = pbcext_element_G2_init())) GOTOENDRC(IERROR, ksap23_setup);
    if(pbcext_element_G2_mul(gkey->YY, gkey->gg, mkey->y) == IERROR)
      GOTOENDRC(IERROR, ksap23_setup);

    /* h = Hash(g) */
    if(!(gkey->h = pbcext_element_G1_init())) GOTOENDRC(IERROR, ksap23_setup);
    if(pbcext_dump_element_G1_bytes(&bf, &len, gkey->g) == IERROR) 
      GOTOENDRC(IERROR, ksap23_setup);    
    if(!(h = hash_init(HASH_BLAKE2)))
      GOTOENDRC(IERROR, ksap23_setup);
    if(hash_update(h, bf, len) == IERROR)
      GOTOENDRC(IERROR, ksap23_setup);
    if(hash_finalize(h) == IERROR)
      GOTOENDRC(IERROR, ksap23_setup);
    /*if(!(gkey->h = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, ksap23_setup);*/
    if(pbcext_element_G1_from_hash(gkey->h,
				   h->hash,
				   h->length) == IERROR)
      GOTOENDRC(IERROR, ksap23_setup);      
    
  }

  /*
   * If the group key is not "empty" (gkey->g != null), we interpret this as 
   * the second call. In this case, we set the manager's key to an initialized
   * Opener key (using the value of g computed in the first call), and fill
   * the received public key with the public part of the Opener's keypair.
   */
  else {

    call = 2;

    /* Initialize the Opener's key */
    if(!(mkey->z0 = pbcext_element_Fr_init())) GOTOENDRC(IERROR, ksap23_setup);
    if(pbcext_element_Fr_random(mkey->z0) == IERROR)
      GOTOENDRC(IERROR, ksap23_setup);

    if(!(mkey->z1 = pbcext_element_Fr_init())) GOTOENDRC(IERROR, ksap23_setup);
    if(pbcext_element_Fr_random(mkey->z1) == IERROR)
      GOTOENDRC(IERROR, ksap23_setup);       

    /* Finalize the group key with the Opener's public key */
    if(!(gkey->ZZ0 = pbcext_element_G1_init())) GOTOENDRC(IERROR, ksap23_setup);
    if(pbcext_element_G1_mul(gkey->ZZ0, gkey->g, mkey->z0) == IERROR)
      GOTOENDRC(IERROR, ksap23_setup);

    if(!(gkey->ZZ1 = pbcext_element_G1_init())) GOTOENDRC(IERROR, ksap23_setup);
    if(pbcext_element_G1_mul(gkey->ZZ1, gkey->g, mkey->z1) == IERROR)
      GOTOENDRC(IERROR, ksap23_setup);      

  }
  
 ksap23_setup_end:

  if (bf) { mem_free(bf); bf = NULL; }
  if (h) { hash_free(h); h = NULL; }

  if (rc == IERROR) {

    /* These are only allocated in "1" calls -- don't clean them upon 
       error otherwise. */
    if (call == 1) {
      if (mkey->x) { pbcext_element_Fr_free(mkey->x); mkey->x = NULL; }
      if (mkey->y) { pbcext_element_Fr_free(mkey->y); mkey->y = NULL; }
      if (gkey->g) { pbcext_element_G1_free(gkey->g); gkey->g = NULL; }
      if (gkey->gg) { pbcext_element_G2_free(gkey->gg); gkey->gg = NULL; }
      if (gkey->XX) { pbcext_element_G2_free(gkey->XX); gkey->XX = NULL; }
      if (gkey->YY) { pbcext_element_G2_free(gkey->YY); gkey->YY = NULL; }
      if (gkey->h) { pbcext_element_G1_free(gkey->h); gkey->h = NULL; }

    }
    
    if (mkey->z0) { pbcext_element_Fr_free(mkey->z0); mkey->z0 = NULL; }
    if (mkey->z1) { pbcext_element_Fr_free(mkey->z1); mkey->z1 = NULL; }    
    if (gkey->ZZ0) { pbcext_element_G1_free(gkey->ZZ0); gkey->ZZ0 = NULL; }
    if (gkey->ZZ1) { pbcext_element_G1_free(gkey->ZZ1); gkey->ZZ1 = NULL; }
    
  }

  return rc;

}

/* setup.c ends here */
