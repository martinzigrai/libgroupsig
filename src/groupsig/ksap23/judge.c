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
 #include "groupsig/ksap23/proof.h" // s tymto preč
 #include "groupsig/ksap23/grp_key.h"
 #include "groupsig/ksap23/signature.h"
 #include "groupsig/ksap23/gml.h"
 #include "groupsig/ksap23/nizk.h"

 
 int ksap23_judge(uint8_t *ok,
              groupsig_proof_t *proof,
              //spk_rep_t *proof,
              groupsig_signature_t *sig,
              //pbcext_element_G1_t *f1,
              //pbcext_element_G1_t *f2, //z proof, f1 a f2 by bolo dobre spravit datovu strukturu
              groupsig_key_t *grpkey) {
 
   //pbcext_element_GT_t *e2;
   ksap23_signature_t *ksap23_sig;
   ksap23_proof_t *ksap23_proof;
   ksap23_grp_key_t *ksap23_grpkey;
   byte_t *bsig;
   int rc;
   uint32_t slen;
   uint8_t _ok;
 
   if (!proof || proof->scheme != GROUPSIG_ksap23_CODE ||
       !sig || sig->scheme != GROUPSIG_ksap23_CODE ||
       !grpkey || grpkey->scheme != GROUPSIG_ksap23_CODE) {
     LOG_EINVAL(&logger, __FILE__, "ksap23_judge", __LINE__, LOGERROR);
     return IERROR;
   }
 
   ksap23_sig = sig->sig;
   ksap23_grpkey = grpkey->key;
   ksap23_proof = proof->proof;
   rc = IOK;
   //e2 = NULL;
 
   /*if (!(e2 = pbcext_element_GT_init())) GOTOENDRC(IERROR, ksap23_judge);
   if (pbcext_pairing(e2, ksap23_sig->ww, ksap23_grpkey->gg) == IERROR)
     GOTOENDRC(IERROR, ksap23_judge);*/
 
   /* Export the signature as an array of bytes */
   bsig = NULL;
   if (ksap23_signature_export(&bsig, &slen, sig) == IERROR)
     GOTOENDRC(IERROR, ksap23_judge);

   /*printf("bsig (sign): ");
   for (int i = 0; i < slen; i++) printf("%02x", bsig[i]);
   printf("\n");  */

     if(ksap23_nizk3_verify(&_ok,
        ksap23_proof->pi,
        ksap23_grpkey->g,
        ksap23_sig->c0,
        ksap23_sig->c1,
        ksap23_sig->c2,
        ksap23_proof->f1,
        ksap23_proof->f2,
        ksap23_grpkey->ZZ0,
        ksap23_grpkey->ZZ1,
        bsig,
        slen) == IERROR)
      GOTOENDRC(IERROR, ksap23_judge);

      //možno niekdey v buducnosti doplnim overenie dig. podpisu
 
   *ok = _ok;
 
  ksap23_judge_end:
 
   if (bsig) { mem_free(bsig); bsig = NULL; }
   
 
   return rc;
   
 }
 
 /* judge.c ends here */
 