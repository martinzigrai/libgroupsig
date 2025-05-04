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
#include <errno.h>
#include <stdlib.h>

#include "ksap23.h"
#include "groupsig/ksap23/grp_key.h"
#include "groupsig/ksap23/mem_key.h" //toto je gski na konci join
#include "sys/mem.h"
#include "groupsig/ksap23/nizk.h" /* To be replaced in issue23. */ //toto je NIZK pre KSAP23
#include "shim/pbc_ext.h"
#include "shim/hash.h"

/** 
 * In the paper, it is the member who begins the protocol and, during join,
 * an interactive ZK protocol is done where the member proves knowledge of
 * her secret exponent. Here, we replace this with having the protocol start
 * by the manager, who sends a fresh random number. Then, the member responds
 * with an SPK over that random number, where she also proves knowledge of
 * her secret exponent. This saves one message. 
 *
 * @TODO: This should not break security, but cross-check!
 *
 * Additionally, the ksap23 scheme requires the member to have a previous
 * keypair+ccertificate from some "traditional" PKI system (e.g., an RSA/ECDSA 
 * certificate). During the join protocol, the member has to send a signature
 * of the value tau (see below, or the paper) under that keypair. IMHO, it makes
 * little sense to code that here, and it would be best to just "require" that
 * some external mechanism using a well tested PKI library is used for that.
 * Instead of signing tau, we can just sign the first message produced by the
 * member (which includes tau). 
 */
int ksap23_join_mem(message_t **mout, groupsig_key_t *memkey,
		    int seq, message_t *min, groupsig_key_t *grpkey) {

  ksap23_mem_key_t *ksap23_memkey;
  ksap23_grp_key_t *ksap23_grpkey;
  spk_rep_t *pi; //toto doriesit NIZK
  hash_t *h;
  //pbcext_element_Fr_t *s0, *s1, *x[3];
  pbcext_element_G1_t *n, *f;
  //pbcext_element_G2_t *SS0, *SS1, *ff0, *ff1, *ggalpha, *ZZ0s0, *ZZ1s1;
  pbcext_element_GT_t *tau, *e1, *e2, *e3;  
  message_t *_mout;
  byte_t *bn, *bw, *bu, *bmsg, *bf1 ,*bf2;
  byte_t *bpi; 
  //void *y[6], *g[5];
  uint64_t len, nlen, f1len, f2len, wlen, ulen, offset;
  uint64_t pilen; //vsetko co suvisi s pi treba potom pridat
  int rc;
  uint16_t i[8][2], prods[6];  
  
  if(!memkey || memkey->scheme != GROUPSIG_ksap23_CODE ||
     !min || (seq != 1 && seq != 3)) {
    LOG_EINVAL(&logger, __FILE__, "ksap23_join_mem", __LINE__, LOGERROR);
    return IERROR;
  }

  ksap23_memkey = memkey->key;
  ksap23_grpkey = grpkey->key;
  _mout = NULL;
  n = f = NULL;
 
  tau = e1 = e2 = e3 = NULL;
  pi = NULL;
  bn = bf1 = bw = bf2 = bu = bmsg = NULL; // bpi
  h = NULL;
  rc = IOK;
  
  if (seq == 1) { /* Second step of the <join,issue> interactive protocol.*/

    /* The manager sends a random element in G1 */
    if(!(n = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, ksap23_join_mem);
    if(pbcext_get_element_G1_bytes(n, &nlen, min->bytes) == IERROR)
      GOTOENDRC(IERROR, ksap23_join_mem);
    if(pbcext_element_G1_to_bytes(&bn, &nlen, n) == IERROR)
      GOTOENDRC(IERROR, ksap23_join_mem);

    /* Compute secret alpha*/
    if(!(ksap23_memkey->alpha = pbcext_element_Fr_init()))
      GOTOENDRC(IERROR, ksap23_join_mem);
    if(pbcext_element_Fr_random(ksap23_memkey->alpha) == IERROR)
      GOTOENDRC(IERROR, ksap23_join_mem);

    /* f1 = g^alpha */
    if(!(ksap23_memkey->f1 = pbcext_element_G1_init())) GOTOENDRC(IERROR, ksap23_join_mem);
    if(pbcext_element_G1_mul(ksap23_memkey->f1,
			     ksap23_grpkey->g,
			     ksap23_memkey->alpha) == IERROR)
      GOTOENDRC(IERROR, ksap23_join_mem);

    /* f2 = h^alpha */
    if(!(ksap23_memkey->f2 = pbcext_element_G1_init())) GOTOENDRC(IERROR, ksap23_join_mem);
    if(pbcext_element_G1_mul(ksap23_memkey->f2,
			     ksap23_grpkey->h,
			     ksap23_memkey->alpha) == IERROR)
      GOTOENDRC(IERROR, ksap23_join_mem);

    /* u = Hash(f1)  */
    if(pbcext_dump_element_G1_bytes(&bf1, &len, ksap23_memkey->f1) == IERROR) 
      GOTOENDRC(IERROR, ksap23_join_mem);    
    if(!(h = hash_init(HASH_BLAKE2)))
      GOTOENDRC(IERROR, ksap23_join_mem);
    if(hash_update(h, bf1, len) == IERROR)
      GOTOENDRC(IERROR, ksap23_join_mem);
    if(hash_finalize(h) == IERROR)
      GOTOENDRC(IERROR, ksap23_join_mem);
    if(!(ksap23_memkey->u = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, ksap23_join_mem);
    if(pbcext_element_G1_from_hash(ksap23_memkey->u,
				   h->hash,
				   h->length) == IERROR)
      GOTOENDRC(IERROR, ksap23_join_mem);

    /* w = u^alpha */
    if(!(ksap23_memkey->w = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, ksap23_join_mem);
    if(pbcext_element_G1_mul(ksap23_memkey->w,
			     ksap23_memkey->u,
			     ksap23_memkey->alpha) == IERROR)
      GOTOENDRC(IERROR, ksap23_join_mem);


    /*TU TREBA NIZK Dôkaz*/
    if(!(pi = spk_rep_init(1))) GOTOENDRC(IERROR, ksap23_join_mem);
    if (ksap23_nizk1_sign(pi, 
                      ksap23_grpkey->g,  // g
                      ksap23_grpkey->h,  // h
                      ksap23_memkey->u,  // u
                      ksap23_memkey->f1, // f1
                      ksap23_memkey->f2, // f2
                      ksap23_memkey->w,  // w
                      ksap23_memkey->alpha) == IERROR)
      GOTOENDRC(IERROR, ksap23_join_mem);


    /* Need to send (n, f1, f2, u, w, pi, sigmads): prepare ad hoc message */
    mem_free(bn); bn = NULL;
    if (pbcext_dump_element_G1_bytes(&bn, &nlen, n) == IERROR) 
      GOTOENDRC(IERROR, ksap23_join_mem);
    len = nlen;
    
    if(pbcext_dump_element_G1_bytes(&bf1,
				    &f1len,
				    ksap23_memkey->f1) == IERROR) 
      GOTOENDRC(IERROR, ksap23_join_mem);
    len += f1len;

    if(pbcext_dump_element_G1_bytes(&bf2,
				    &f2len,
				    ksap23_memkey->f2) == IERROR) 
      GOTOENDRC(IERROR, ksap23_join_mem);
    len += f2len;

    if(pbcext_dump_element_G1_bytes(&bu,
				    &ulen,
				    ksap23_memkey->u) == IERROR) 
      GOTOENDRC(IERROR, ksap23_join_mem);
    len += ulen;

    if(pbcext_dump_element_G1_bytes(&bw,
				    &wlen,
				    ksap23_memkey->w) == IERROR) 
      GOTOENDRC(IERROR, ksap23_join_mem);
    len += wlen;
    
    bpi = NULL;
    if(spk_rep_export(&bpi, &pilen, pi) == IERROR)
      GOTOENDRC(IERROR, ksap23_join_mem);
    len += pilen;


    if(!(bmsg = (byte_t *) mem_malloc(sizeof(byte_t)*len)))
      GOTOENDRC(IERROR, ksap23_join_mem);

    memcpy(bmsg, bn, nlen); offset = nlen;
    memcpy(&bmsg[offset], bf1, f1len); offset += f1len;
    memcpy(&bmsg[offset], bf2, f2len); offset += f2len;
    memcpy(&bmsg[offset], bu, ulen); offset += ulen;
    memcpy(&bmsg[offset], bw, wlen); offset += wlen;
    memcpy(&bmsg[offset], bpi, pilen); offset += pilen; //neviem ci tu nechyba sigma ale asi ok

    mem_free(bn); bn = NULL;
    mem_free(bf1); bf1 = NULL;
    mem_free(bf2); bf2 = NULL;
    mem_free(bu); bu = NULL;
    mem_free(bw); bw = NULL;
    mem_free(bpi); bpi = NULL;

    if(!*mout) {
      if(!(_mout = message_from_bytes(bmsg, len))){
        mem_free(bmsg);
        GOTOENDRC(IERROR, ksap23_join_mem);
      }
	      
      *mout = _mout;
    } else {
      _mout = *mout;
      if(message_set_bytes(*mout, bmsg, len) == IERROR){
        mem_free(bmsg);
        GOTOENDRC(IERROR, ksap23_join_mem);
      }
    }
    mem_free(bmsg);
    bmsg = NULL;

    pi = NULL;

    
  } else { /* Third (last) message of interactive protocol */

    /* Min = v */
    if(!(ksap23_memkey->v = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, ksap23_join_mem);
    if(pbcext_get_element_G1_bytes(ksap23_memkey->v,
				   &len, min->bytes) == IERROR)
      GOTOENDRC(IERROR, ksap23_join_mem);    
    
    /* Check correctness: e(v,gg) = e(u,XX)e(w,YY) */
    if (!(e1 = pbcext_element_GT_init()))
      GOTOENDRC(IERROR, ksap23_join_mem);
    if (pbcext_pairing(e1, ksap23_memkey->v, ksap23_grpkey->gg) == IERROR)
      GOTOENDRC(IERROR, ksap23_join_mem);

    if (!(e2 = pbcext_element_GT_init()))
      GOTOENDRC(IERROR, ksap23_join_mem);
    if (pbcext_pairing(e2, ksap23_memkey->u, ksap23_grpkey->XX) == IERROR)
      GOTOENDRC(IERROR, ksap23_join_mem);

    if (!(e3 = pbcext_element_GT_init()))
      GOTOENDRC(IERROR, ksap23_join_mem);
    if (pbcext_pairing(e3, ksap23_memkey->w, ksap23_grpkey->YY) == IERROR)
      GOTOENDRC(IERROR, ksap23_join_mem);

    if (pbcext_element_GT_mul(e2, e2, e3) == IERROR)
      GOTOENDRC(IERROR, ksap23_join_mem);

    if (pbcext_element_GT_cmp(e1, e2)) rc = IERROR;
    
  }
  
  ksap23_join_mem_end:

  if (rc == IERROR) {
    if (pi) { 
      spk_rep_free(pi); 
      pi = NULL; 
    }

    if (seq == 1) {
      if (ksap23_memkey->alpha) {
        pbcext_element_Fr_free(ksap23_memkey->alpha);
        ksap23_memkey->alpha = NULL;
      }
      if (ksap23_memkey->f1) {
        pbcext_element_G1_free(ksap23_memkey->f1);
        ksap23_memkey->f1 = NULL;
      }
      if (ksap23_memkey->f2) {
        pbcext_element_G1_free(ksap23_memkey->f2);
        ksap23_memkey->f2 = NULL;
      }
      if (ksap23_memkey->u) {
        pbcext_element_G1_free(ksap23_memkey->u);
        ksap23_memkey->u = NULL;
      }
      if (ksap23_memkey->w) {
        pbcext_element_G1_free(ksap23_memkey->w);
        ksap23_memkey->w = NULL;
      }
    }
    if (seq == 3) {
      if (ksap23_memkey->v) {
        pbcext_element_G1_free(ksap23_memkey->v);
        ksap23_memkey->v = NULL;
      }
    }
  }

  // Uvoľnenie zvyšných premenných
  if (pi) { spk_rep_free(pi); pi = NULL; }
  if (bn) { mem_free(bn); bn = NULL; }
  if (bw) { mem_free(bw); bw = NULL; }
  if (bu) { mem_free(bu); bu = NULL; }
  if (bf1) { mem_free(bf1); bf1 = NULL; }
  if (bf2) { mem_free(bf2); bf2 = NULL; }
  if (bmsg) { mem_free(bmsg); bmsg = NULL; }
  if (h) { hash_free(h); h = NULL; }
  if (tau) { pbcext_element_GT_free(tau); tau = NULL; }
  if (e1) { pbcext_element_GT_free(e1); e1 = NULL; }
  if (e2) { pbcext_element_GT_free(e2); e2 = NULL; }
  if (e3) { pbcext_element_GT_free(e3); e3 = NULL; }
  if (n) { pbcext_element_G1_free(n); n = NULL; }
  if (f) { pbcext_element_G1_free(f); f = NULL; }
  if (bpi) { mem_free(bpi); bpi = NULL; }

  return rc;
}
 /*ksap23_join_mem_end:

  if (rc == IERROR) {
    if (seq == 1) {
      if (ksap23_memkey->alpha) {
	pbcext_element_Fr_free(ksap23_memkey->alpha);
	ksap23_memkey->alpha = NULL;
      }
      if (ksap23_memkey->f1) {
	pbcext_element_G1_free(ksap23_memkey->f1);
	ksap23_memkey->f1 = NULL;
      }
      if (ksap23_memkey->f2) {
	pbcext_element_G1_free(ksap23_memkey->f2);
	ksap23_memkey->f2 = NULL;
      }
      if (ksap23_memkey->u) {
	pbcext_element_G1_free(ksap23_memkey->u);
	ksap23_memkey->u = NULL;
      }
      if (ksap23_memkey->w) {
	pbcext_element_G1_free(ksap23_memkey->w);
	ksap23_memkey->w = NULL;
      }
    }
    if (seq == 3) {
      if (ksap23_memkey->v) {
	pbcext_element_G1_free(ksap23_memkey->v);
	ksap23_memkey->v = NULL;
      }
    }
  }

  if (pi) { spk_rep_free(pi); pi = NULL; }
  //if (s0) { pbcext_element_Fr_free(s0); s0 = NULL; }
  //if (s1) { pbcext_element_Fr_free(s1); s1 = NULL; }  
  if (n) { pbcext_element_G1_free(n); n = NULL; }
  if (f) { pbcext_element_G1_free(f); f = NULL; }
  //if (SS0) { pbcext_element_G2_free(SS0); SS0 = NULL; }
  //if (SS1) { pbcext_element_G2_free(SS1); SS1 = NULL; }
  //if (ff0) { pbcext_element_G2_free(ff0); ff0 = NULL; }
  //if (ff1) { pbcext_element_G2_free(ff1); ff1 = NULL; }  
  //if (ggalpha) { pbcext_element_G2_free(ggalpha); ggalpha = NULL; }
  //if (ZZ0s0) { pbcext_element_G2_free(ZZ0s0); ZZ0s0 = NULL; }
  //if (ZZ1s1) { pbcext_element_G2_free(ZZ1s1); ZZ1s1 = NULL; } 
  if (tau) { pbcext_element_GT_free(tau); tau = NULL; }
  if (e1) { pbcext_element_GT_free(e1); e1 = NULL; }
  if (e2) { pbcext_element_GT_free(e2); e2 = NULL; }
  if (e3) { pbcext_element_GT_free(e3); e3 = NULL; } 
  if (bn) { mem_free(bn); bn = NULL; }      
  //if (bf) { mem_free(bf); bf = NULL; }
  if (bw) { mem_free(bw); bw = NULL; }
  if (bu) { mem_free(bu); bu = NULL; }
  //if (bSS1) { mem_free(bSS1); bSS1 = NULL; }  
  if (bf1) { mem_free(bf1); bf1 = NULL; }
  if (bf2) { mem_free(bf2); bf2 = NULL; }   
  if (bpi) { mem_free(bpi); bpi = NULL; }
  if (bmsg) { mem_free(bmsg); bmsg = NULL; }
  if (h) { hash_free(h); h = NULL; }

  return rc;

}*/

/* join_mem.c ends here */
