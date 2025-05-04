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
#include "groupsig/ksap23/mgr_key.h"
#include "groupsig/ksap23/mem_key.h"
#include "groupsig/ksap23/gml.h"
#include "groupsig/ksap23/nizk.h"
#include "crypto/spk.h"
#include "shim/pbc_ext.h"
#include "shim/hash.h"
#include "sys/mem.h"

int ksap23_get_joinseq(uint8_t *seq) {
  *seq = ksap23_JOIN_SEQ;
  return IOK;
}

int ksap23_get_joinstart(uint8_t *start) {
  *start = ksap23_JOIN_START;
  return IOK;
}

/**
 * This process deviates slightly from what the ksap23 paper defines, as the PKI
 * functionality is not integrated here. See the comment in the join_mem 
 * function for a detailed explanation.
 * 
 * In the join_mgr implemented here, we do not verify any signature of tau using
 * a "standard" keypair+certificate. Nor do we add the signature of tau to the
 * GML (because we don't receive such signature). Rather, it should be the caller
 * who takes care of that using some well tested library/software for PKI 
 * management.
 *
 * This can be easily done by a calling library as follows:
 *   1) The member digitally signs, using his PKI-backed identity, the bytearray
 *      representation of the <i>min</i> parameter when <i>seq</i>=2 (this
 *      contains the challenge response). 
 *   2) If the join is successful, the manager exports the newly created GML
 *      entry, producing a byte array (which contains the libgroupsig-internal
 *      identity -- an integer). 
 *   3) All the server running the issuer needs to store in its database, is
 *      the output of the previous steps. This can then be queried when an open
 *      is requested.
 */
int ksap23_join_mgr(message_t **mout,
		  gml_t *gml,
		  groupsig_key_t *mgrkey,
		  int seq,
		  message_t *min,
		  groupsig_key_t *grpkey) {

  ksap23_mgr_key_t *ksap23_mgrkey;
  ksap23_grp_key_t *ksap23_grpkey;
  gml_entry_t *ksap23_entry;
  pbcext_element_G1_t *n, *f1, *f2, *u, *v , *w;
  pbcext_element_GT_t *tau;
  spk_rep_t *pi;
  hash_t *h;
  message_t *_mout;
  //byte_t *bn, *bf, *bv;
  //void *y[6], *g[5];  
  //uint64_t len, nlen, flen, wlen, SS0len, SS1len, ff0len, ff1len, pilen, offset;
  uint64_t len, nlen, f1len, f2len, wlen, ulen, pilen, offset;
  byte_t *bn, *bw, *bu, *bpi, *bmsg, *bf1 ,*bf2, *bv; 
  uint8_t ok;
  int rc;
  uint16_t i[8][2], prods[6];  
  pbcext_element_G1_t *u_tmp = NULL, *w_tmp = NULL;
  pbcext_element_G1_t *u_comp = NULL;
  

  if((seq != 0 && seq != 2) ||
     !mout || !gml || gml->scheme != GROUPSIG_ksap23_CODE ||
     !mgrkey || mgrkey->scheme != GROUPSIG_ksap23_CODE ||
     !grpkey || grpkey->scheme != GROUPSIG_ksap23_CODE) {
    LOG_EINVAL(&logger, __FILE__, "ksap23_join_mgr", __LINE__, LOGERROR);
    return IERROR;
  }

  ksap23_mgrkey = (ksap23_mgr_key_t *) mgrkey->key;
  ksap23_grpkey = (ksap23_grp_key_t *) grpkey->key;
  ksap23_entry = NULL;
  bn = bf1 = bw = bf2 = bu = bmsg = bpi = bv = NULL;
  n = f1 = f2 = u = v = w = NULL;
  tau = NULL;
  h = NULL;
  pi = NULL;
  rc = IOK;
  
  if (!seq) { /* First step */

    if(!(n = pbcext_element_G1_init())) GOTOENDRC(IERROR, ksap23_join_mgr);
    if(pbcext_element_G1_random(n) == IERROR) GOTOENDRC(IERROR, ksap23_join_mgr);
    
    /* Dump the element into a message */
    if(pbcext_dump_element_G1_bytes(&bn, &len, n) == IERROR) 
      GOTOENDRC(IERROR, ksap23_join_mgr);
    
    if(!*mout) {   
      if(!(_mout = message_from_bytes(bn, len))) {
        mem_free(bn);
	      GOTOENDRC(IERROR, ksap23_join_mgr);
      }

      *mout = _mout;
      
    } else {

      _mout = *mout;
      if(message_set_bytes(*mout, bn, len) == IERROR){
        mem_free(bn);
	      GOTOENDRC(IERROR, ksap23_join_mgr);
      }
    }
    mem_free(bn); 
    bn = NULL;
    
  } else { /* Third step */

    /* Import the (n, f1, f2, u, w, pi, sigmads) ad hoc message */

    if (!(n = pbcext_element_G1_init())) GOTOENDRC(IERROR, ksap23_join_mgr);
    if (pbcext_get_element_G1_bytes(n, &nlen, min->bytes) == IERROR)
      GOTOENDRC(IERROR, ksap23_join_mgr);
    offset = nlen;
    if (!(f1 = pbcext_element_G1_init())) GOTOENDRC(IERROR, ksap23_join_mgr);
    if (pbcext_get_element_G1_bytes(f1, &f1len, min->bytes + offset) == IERROR)
      GOTOENDRC(IERROR, ksap23_join_mgr);
    offset += f1len;
    if (!(f2 = pbcext_element_G1_init())) GOTOENDRC(IERROR, ksap23_join_mgr);
    if (pbcext_get_element_G1_bytes(f2, &f2len, min->bytes + offset) == IERROR)
      GOTOENDRC(IERROR, ksap23_join_mgr);
    offset += f2len;
    if (!(u = pbcext_element_G1_init())) GOTOENDRC(IERROR, ksap23_join_mgr);
    if (pbcext_get_element_G1_bytes(u, &ulen, min->bytes + offset) == IERROR)
      GOTOENDRC(IERROR, ksap23_join_mgr);
    offset += ulen;
    if (!(w = pbcext_element_G1_init())) GOTOENDRC(IERROR, ksap23_join_mgr);
    if (pbcext_get_element_G1_bytes(w, &wlen, min->bytes + offset) == IERROR)
      GOTOENDRC(IERROR, ksap23_join_mgr);
    offset += wlen;
    if (!(pi = spk_rep_import(min->bytes + offset, &pilen)))
      GOTOENDRC(IERROR, ksap23_join_mgr);
    offset += pilen;

    if (pbcext_element_G1_to_bytes(&bn, &nlen, n) == IERROR)
      GOTOENDRC(IERROR, ksap23_join_mgr);

    /* Check the NIZK  */

    /* u = Hash(f) */
    if(pbcext_dump_element_G1_bytes(&bf1, &len, f1) == IERROR) 
      GOTOENDRC(IERROR, ksap23_join_mgr);    
    if(!(h = hash_init(HASH_BLAKE2)))
      GOTOENDRC(IERROR, ksap23_join_mgr);
    if(hash_update(h, bf1, len) == IERROR)
      GOTOENDRC(IERROR, ksap23_join_mgr);
    if(hash_finalize(h) == IERROR)
      GOTOENDRC(IERROR, ksap23_join_mgr);
    if(!(u_comp = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, ksap23_join_mgr);
    if(pbcext_element_G1_from_hash(u_comp, h->hash, h->length) == IERROR)
      GOTOENDRC(IERROR, ksap23_join_mgr);   

    if (ksap23_nizk1_verify(&ok, pi, 
          ksap23_grpkey->g, 
          ksap23_grpkey->h, 
          u_comp, f1, f2, w) == IERROR) {
      GOTOENDRC(IERROR, ksap23_join_mgr);
    }
    if (!ok) GOTOENDRC(IERROR, ksap23_join_mgr);
        
    if (!(u_tmp = pbcext_element_G1_init())) GOTOENDRC(IERROR, ksap23_join_mgr);
    if (!(w_tmp = pbcext_element_G1_init())) GOTOENDRC(IERROR, ksap23_join_mgr);

    if (!(v = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, ksap23_join_mgr);
    if (pbcext_element_G1_mul(w_tmp, w, ksap23_mgrkey->y) == IERROR)
      GOTOENDRC(IERROR, ksap23_join_mgr);
    if (pbcext_element_G1_mul(u_tmp, u, ksap23_mgrkey->x) == IERROR)
      GOTOENDRC(IERROR, ksap23_join_mgr);
    if (pbcext_element_G1_add(v, u_tmp, w_tmp) == IERROR)
      GOTOENDRC(IERROR, ksap23_join_mgr);    

    /*NEW Add the tuple (i,f1,f2,u,w,pi,sigmads) to the GML NEW*/

    /*if (!(tau = pbcext_element_GT_init()))
      GOTOENDRC(IERROR, ksap23_join_mgr);
    if (pbcext_pairing(tau, f, ksap23_grpkey->gg) == IERROR)
      GOTOENDRC(IERROR, ksap23_join_mgr);*/

    if(!(ksap23_entry = ksap23_gml_entry_init()))
      GOTOENDRC(IERROR, ksap23_join_mgr);
    
    /* Currently, ksap23 identities are just uint64_t's */
    ksap23_entry->id = gml->n;
    if (!(ksap23_entry->data = mem_malloc(sizeof(ksap23_gml_entry_data_t))))
      GOTOENDRC(IERROR, ksap23_join_mgr);
    ((ksap23_gml_entry_data_t *) ksap23_entry->data)->f1 = f1;
    ((ksap23_gml_entry_data_t *) ksap23_entry->data)->f2 = f2;
    ((ksap23_gml_entry_data_t *) ksap23_entry->data)->u = u;
    ((ksap23_gml_entry_data_t *) ksap23_entry->data)->w = w;
    ((ksap23_gml_entry_data_t *) ksap23_entry->data)->pi = pi;
    //((ksap23_gml_entry_data_t *) ksap23_entry->data)->tau = tau;

    if(gml_insert(gml, ksap23_entry) == IERROR) GOTOENDRC(IERROR, ksap23_join_mgr);

    /* Export v into a msg */
    bv = NULL;
    if(pbcext_dump_element_G1_bytes(&bv, &len, v) == IERROR) 
      GOTOENDRC(IERROR, ksap23_join_mgr);

    if(!*mout) {
      
      if(!(_mout = message_from_bytes(bv, len)))
      {
        mem_free(bv);
        GOTOENDRC(IERROR, ksap23_join_mgr);
      }
	
      *mout = _mout;

    } else {

      _mout = *mout;
      if(message_set_bytes(_mout, bv, len) == IERROR){
        mem_free(bv);
        GOTOENDRC(IERROR, ksap23_join_mgr);
      }
    }  
    mem_free(bv); 
    bv = NULL;
    
  }
  
 ksap23_join_mgr_end:

  if (rc == IERROR) { 
    if (ksap23_entry) { 
      ksap23_gml_entry_free(ksap23_entry);
       ksap23_entry = NULL;
      }

    if (pi) { 
      spk_rep_free(pi); 
      pi = NULL; 
    }
  }

  if (!ksap23_entry){
    if (f1) { pbcext_element_G1_free(f1); f1 = NULL; }
    if (f2) { pbcext_element_G1_free(f2); f2 = NULL; }
    if (u)  { pbcext_element_G1_free(u);  u = NULL; }
    if (w)  { pbcext_element_G1_free(w);  w = NULL; }
  }

  if (n) { pbcext_element_G1_free(n); n = NULL; }
  if (v) { pbcext_element_G1_free(v); v = NULL; }
  if (tau) { pbcext_element_GT_free(tau); tau = NULL; } 
  
  if (h) { hash_free(h); h = NULL; }
  //if (pi) { spk_rep_free(pi); pi = NULL; }

  if (bn) { mem_free(bn); bn = NULL; }  
  if (bv) { mem_free(bv); bv = NULL; }
  if (bw) { mem_free(bw); bw = NULL; }
  if (bu) { mem_free(bu); bu = NULL; }
  if (bf1) { mem_free(bf1); bf1 = NULL; }
  if (bf2) { mem_free(bf2); bf2 = NULL; }

  if (u_tmp) { pbcext_element_G1_free(u_tmp); u_tmp = NULL; }
  if (u_comp) { pbcext_element_G1_free(u_comp); u_comp = NULL; }
  if (w_tmp) { pbcext_element_G1_free(w_tmp); w_tmp = NULL; }

  //if (f) { pbcext_element_G1_free(f); f = NULL; }  
  //if (u) { pbcext_element_G1_free(u); u = NULL; }
  //if (f1) { pbcext_element_G1_free(f1); f1 = NULL; }
  //if (f2) { pbcext_element_G1_free(f2); f2 = NULL; }
  //if (u) { pbcext_element_G1_free(u); u = NULL; }
  //if (w) { pbcext_element_G1_free(w); w = NULL; }
  //if (w) { pbcext_element_G1_free(w); w = NULL; }
  //if (bf) { mem_free(bf); bf = NULL; }
  
  return rc;

}

/* join_mgr.c ends here */


//cize najprv zacina komunikaciu manazer potom sa vygeneruju nejake parametre f1, f2, u, w
//dokazy zatial neriesim takze skip
// DSSig f1 || f2 skip, to sa riesi externe (nejakym PKI - asi OpenSSL)
//