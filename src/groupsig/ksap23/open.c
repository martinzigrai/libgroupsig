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
 
 #include "types.h"
 #include "sysenv.h"
 #include "ksap23.h"
 #include "sys/mem.h"
 #include "crypto/spk.h"
 #include "math/rnd.h"
 #include "groupsig/ksap23/proof.h"
 #include "groupsig/ksap23/grp_key.h"
 #include "groupsig/ksap23/mgr_key.h"
 #include "groupsig/ksap23/signature.h"
 #include "groupsig/ksap23/gml.h"
 
 int ksap23_open(uint64_t *index,
           groupsig_proof_t *proof, 
           crl_t *crl,
           groupsig_signature_t *sig, 
           groupsig_key_t *grpkey,
           groupsig_key_t *mgrkey,
           gml_t *gml) {
 
   pbcext_element_G1_t *ff1, *ff2; //toto je f s tou strieskou, treba f1 a f2
   //pbcext_element_GT_t *e1, *e2, *e3; //toto mi ksap23 netreba
   ksap23_signature_t *ksap23_sig;
   ksap23_grp_key_t *ksap23_grpkey;
   ksap23_mgr_key_t *ksap23_mgrkey;
   gml_entry_t *ksap23_entry;
   ksap23_gml_entry_data_t *ksap23_data;
   byte_t *bsig;
   uint64_t i, b;
   uint32_t slen;
   uint8_t match;
   int rc;
 
   if (!index || !sig || sig->scheme != GROUPSIG_ksap23_CODE ||
       !grpkey || grpkey->scheme != GROUPSIG_ksap23_CODE ||
       !mgrkey || mgrkey->scheme != GROUPSIG_ksap23_CODE ||
       !gml) {
     LOG_EINVAL(&logger, __FILE__, "ksap23_open", __LINE__, LOGERROR);
     return IERROR;
   }
 
   ksap23_sig = sig->sig;
   ksap23_grpkey = grpkey->key;
   ksap23_mgrkey = mgrkey->key;
   rc = IOK;
  
    //initialization of ff1 and ff2
   if (!(ff1 = pbcext_element_G1_init()))
     GOTOENDRC(IERROR, ksap23_open);
   if (!(ff2 = pbcext_element_G1_init()))
     GOTOENDRC(IERROR, ksap23_open);
     
   match = 0;
   
   if (pbcext_element_G1_mul(ff1, ksap23_sig->c0, ksap23_grpkey->ZZ0) == IERROR)
     GOTOENDRC(IERROR, ksap23_open);
   if (pbcext_element_G1_neg(ff1, ff1) == IERROR) 
     GOTOENDRC(IERROR, ksap23_open); 
   if (pbcext_element_G1_add(ff1, ksap23_sig->c1, ff1) == IERROR)
     GOTOENDRC(IERROR, ksap23_open);

   if (pbcext_element_G1_mul(ff2, ksap23_sig->c0, ksap23_grpkey->ZZ1) == IERROR)
     GOTOENDRC(IERROR, ksap23_open);
   if (pbcext_element_G1_neg(ff2, ff2) == IERROR) 
     GOTOENDRC(IERROR, ksap23_open); 
   if (pbcext_element_G1_add(ff2, ksap23_sig->c2, ff2) == IERROR)
     GOTOENDRC(IERROR, ksap23_open);

   for (i=0; i<gml->n; i++) {

      if (!(ksap23_entry = gml_get(gml, i))) GOTOENDRC(IERROR, ksap23_open);
      ksap23_data = ksap23_entry->data;
      if (!ksap23_data) GOTOENDRC(IERROR, ksap23_open);

      if (!pbcext_element_G1_cmp(ksap23_data->f1, ff1) &&
      !pbcext_element_G1_cmp(ksap23_data->f2, ff2)) { //tu doplnit dokaz
 
       /* Get the identity from the matched entry. */
       *index = ksap23_entry->id;
       match++; //prechadza sa cely zoznam, co moze trvat dlhsie

       if(match > 1) GOTOENDRC(IFAIL, ksap23_open);
 
     }

   }

   if(!match) GOTOENDRC(IFAIL, ksap23_open);

 
   /* Export the signature as an array of bytes */
   bsig = NULL;
   if (ksap23_signature_export(&bsig, &slen, sig) == IERROR)
     GOTOENDRC(IERROR, ksap23_open);
 
   /*if (!(proof->proof = ksap23_spk1_init()))
     GOTOENDRC(IERROR, ksap23_open);
 
   if (!(((ksap23_spk1_t *) proof->proof)->tau = pbcext_element_GT_init()))
     GOTOENDRC(IERROR, ksap23_open);
   if (pbcext_element_GT_set(((ksap23_spk1_t *) proof->proof)->tau, e3) == IERROR)
     GOTOENDRC(IERROR, ksap23_open);*/
   
   /*if (ksap23_spk1_sign(proof->proof,
                ff,
                ksap23_sig->uu,
                ksap23_grpkey->g,
                e2,
                e3,
                bsig,
                slen) == IERROR) 
     GOTOENDRC(IERROR, ksap23_open);*/
 
  ksap23_open_end:
 
   if (ff1) { pbcext_element_G1_free(ff1); ff1 = NULL; }
   if (ff2) { pbcext_element_G1_free(ff2); ff2 = NULL; }
   
   if (bsig) { mem_free(bsig); bsig = NULL; }
   
   if (rc == IERROR) {
     if (proof->proof) {
       ksap23_spk1_free(proof->proof);
       proof->proof = NULL;
     }
   }
   
   return rc;
   
 }
 
 /* open.c ends here */
 