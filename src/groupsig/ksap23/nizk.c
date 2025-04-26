#include "crypto/spk.h"
#include "groupsig/ksap23/nizk.h"
#include "shim/hash.h"
#include "sys/mem.h"

#include "groupsig/common.h"
#include "pbcext.h"
#include "hash.h"
#include "mem.h"
#include "logger.h"
#include "crypto/spk.h"


int ksap23_nizk1_sign(spk_rep_t *pi,
                pbcext_element_G1_t *g,
                pbcext_element_G1_t *h,
                pbcext_element_G1_t *u,
                pbcext_element_G1_t *f1,
                pbcext_element_G1_t *f2,
                pbcext_element_G1_t *w,
                pbcext_element_Fr_t *alpha) { 

  pbcext_element_Fr_t *k = NULL, *s = NULL;
  pbcext_element_G1_t *gr = NULL, *hr = NULL, *ur = NULL;
  hash_t *hc = NULL;
  byte_t *bg = NULL;
  uint64_t len;
  int rc = IOK;

  if (!pi || !g || !h || !u || !f1 || !f2 || !w || !alpha) {
    LOG_EINVAL(&logger, __FILE__, "nizk1_prove", __LINE__, LOGERROR);
    return IERROR;
  }

  if (!(k = pbcext_element_Fr_init())) GOTOENDRC(IERROR, ksap23_nizk1_sign);
  if (!(gr = pbcext_element_G1_init())) GOTOENDRC(IERROR, ksap23_nizk1_sign);
  if (!(hr = pbcext_element_G1_init())) GOTOENDRC(IERROR, ksap23_nizk1_sign);
  if (!(ur = pbcext_element_G1_init())) GOTOENDRC(IERROR, ksap23_nizk1_sign);

  /* náhodné k ← Z_p */
  if (pbcext_element_Fr_random(k) == IERROR)
    GOTOENDRC(IERROR, ksap23_nizk1_sign);

  /* kommitmenty: gr = g^k, hr = h^k, ur = u^k */
  if (pbcext_element_G1_mul(gr, g, k) == IERROR)
    GOTOENDRC(IERROR, ksap23_nizk1_sign);
  if (pbcext_element_G1_mul(hr, h, k) == IERROR)
    GOTOENDRC(IERROR, ksap23_nizk1_sign);
  if (pbcext_element_G1_mul(ur, u, k) == IERROR)
    GOTOENDRC(IERROR, ksap23_nizk1_sign);

  /* Inicializacia hashu pre výzvu c */
  if(!(hc = hash_init(HASH_BLAKE2))) GOTOENDRC(IERROR, ksap23_nizk1_sign);

  /* Hash verejnych parametrov a kommitmentov */
  const pbcext_element_G1_t *elements[] = {g, h, u, f1, f2, w, gr, hr, ur};
  for (int i = 0; i < 9; i++) {
    if(pbcext_element_G1_to_bytes(&bg, &len, elements[i]) == IERROR)
        GOTOENDRC(IERROR, ksap23_nizk1_sign);
    if(hash_update(hc, bg, len) == IERROR) GOTOENDRC(IERROR, ksap23_nizk1_sign);
    mem_free(bg); bg = NULL;  
  }

  /* Finalizovanie hashu*/
  if(hash_finalize(hc) == IERROR) GOTOENDRC(IERROR, ksap23_nizk1_sign);

  /* Hash na skalár c */
  if (!(pi->c = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, ksap23_nizk1_sign);
  if (pbcext_element_Fr_from_hash(pi->c, hc->hash, hc->length) == IERROR)
    GOTOENDRC(IERROR, ksap23_nizk1_sign);


  /* s = k - c * α */
  if (!(s = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, ksap23_nizk1_sign);
  if (pbcext_element_Fr_mul(s, pi->c, alpha) == IERROR)
    GOTOENDRC(IERROR, ksap23_nizk1_sign);
  if (!(pi->s = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, ksap23_nizk1_sign);
  if (pbcext_element_Fr_sub(pi->s, k, s) == IERROR)
    GOTOENDRC(IERROR, ksap23_nizk1_sign);

  
  ksap23_nizk1_sign_end:
  /* Cleanup */
  if (k) pbcext_element_Fr_free(k);
  if (gr) pbcext_element_G1_free(gr);
  if (hr) pbcext_element_G1_free(hr);
  if (ur) pbcext_element_G1_free(ur);
  if (hc) hash_free(hc);
  if (bg) mem_free(bg);
  if (s) pbcext_element_Fr_free(s);

  return rc;
}

int ksap23_nizk1_verify(uint8_t *ok,
    spk_rep_t *pi, //toto je nieco z crypto/spk.c treba bud urobit vlastnu implementaaciu alebo vyuzit tu spk ak sa da
    pbcext_element_G1_t *g,
    pbcext_element_G1_t *h,
    pbcext_element_G1_t *u,
    pbcext_element_G1_t *f1,
    pbcext_element_G1_t *f2,
    pbcext_element_G1_t *w) {

pbcext_element_G1_t *gr_verif, *gr_tmp1, *gr_tmp2;
pbcext_element_G1_t *hr_verif, *hr_tmp1, *hr_tmp2;
pbcext_element_G1_t *ur_verif, *ur_tmp1, *ur_tmp2;

hash_t *hc = NULL;
byte_t *bg = NULL;
uint64_t len;
int rc = IOK;

if (!ok || !pi || !g || !h || !u || !f1 || !f2 || !w) {
LOG_EINVAL(&logger, __FILE__, "nizk1_verify", __LINE__, LOGERROR);
return IERROR;
}

/* kommitmenty: g^s * f1^c, h^s * f2^c, u^s * w^c */
if (!(gr_verif = pbcext_element_G1_init()))
     GOTOENDRC(IERROR, ksap23_nizk1_verify);
if (!(gr_tmp1 = pbcext_element_G1_init()))
     GOTOENDRC(IERROR, ksap23_nizk1_verify);
if (!(gr_tmp2 = pbcext_element_G1_init()))
     GOTOENDRC(IERROR, ksap23_nizk1_verify);

if (!(hr_verif = pbcext_element_G1_init()))
     GOTOENDRC(IERROR, ksap23_nizk1_verify);
if (!(hr_tmp1 = pbcext_element_G1_init()))
     GOTOENDRC(IERROR, ksap23_nizk1_verify);
if (!(hr_tmp2 = pbcext_element_G1_init()))
     GOTOENDRC(IERROR, ksap23_nizk1_verify);

if (!(ur_verif = pbcext_element_G1_init()))
     GOTOENDRC(IERROR, ksap23_nizk1_verify);
if (!(ur_tmp1 = pbcext_element_G1_init()))
     GOTOENDRC(IERROR, ksap23_nizk1_verify);
if (!(ur_tmp2 = pbcext_element_G1_init()))
     GOTOENDRC(IERROR, ksap23_nizk1_verify);

//g^s * f1^c
if (pbcext_element_G1_mul(gr_tmp1, g, pi->s) == IERROR)
     GOTOENDRC(IERROR, ksap23_nizk1_verify);
if (pbcext_element_G1_mul(gr_tmp2, f1, pi->c) == IERROR)
    GOTOENDRC(IERROR, ksap23_nizk1_verify);
if (pbcext_element_G1_add(gr_verif, gr_tmp1, gr_tmp2) == IERROR)
    GOTOENDRC(IERROR, ksap23_nizk1_verify);   
    
//h^s * f2^c
if (pbcext_element_G1_mul(hr_tmp1, h, pi->s) == IERROR)
     GOTOENDRC(IERROR, ksap23_nizk1_verify);
if (pbcext_element_G1_mul(hr_tmp2, f2, pi->c) == IERROR)
    GOTOENDRC(IERROR, ksap23_nizk1_verify);
if (pbcext_element_G1_add(hr_verif, hr_tmp1, hr_tmp2) == IERROR)
    GOTOENDRC(IERROR, ksap23_nizk1_verify);

//u^s * w^c 
if (pbcext_element_G1_mul(ur_tmp1, u, pi->s) == IERROR)
     GOTOENDRC(IERROR, ksap23_nizk1_verify);
if (pbcext_element_G1_mul(ur_tmp2, w, pi->c) == IERROR)
    GOTOENDRC(IERROR, ksap23_nizk1_verify);
if (pbcext_element_G1_add(ur_verif, ur_tmp1, ur_tmp2) == IERROR)
    GOTOENDRC(IERROR, ksap23_nizk1_verify);

/* Hash Y a kommitmentov */
if(!(hc = hash_init(HASH_BLAKE2))) GOTOENDRC(IERROR, ksap23_nizk1_verify);

const pbcext_element_G1_t *elements[] = {g, h, u, f1, f2, w, gr_verif, hr_verif, ur_verif};
for (int i = 0; i < 9; i++) {
  if(pbcext_element_G1_to_bytes(&bg, &len, elements[i]) == IERROR)
      GOTOENDRC(IERROR, ksap23_nizk1_verify);
  if(hash_update(hc, bg, len) == IERROR) GOTOENDRC(IERROR, ksap23_nizk1_verify);
  mem_free(bg); bg = NULL;  
}

if(hash_finalize(hc) == IERROR) GOTOENDRC(IERROR, ksap23_nizk1_verify);

/* Porovnanie c s hashom */
pbcext_element_Fr_t *c_verif = NULL;
c_verif = pbcext_element_Fr_init();

//pbcext_element_Fr_from_hash(c_verif, hc->hash, hc->length);
if (pbcext_element_Fr_from_hash(c_verif, hc->hash, hc->length) == IERROR)
      GOTOENDRC(IERROR, ksap23_nizk1_verify);

if(pbcext_element_Fr_cmp(c_verif, pi->c)) {
  *ok = 0;
} else {
  *ok = 1;
}

ksap23_nizk1_verify_end:

if (gr_verif) pbcext_element_G1_free(gr_verif);
if (hr_verif) pbcext_element_G1_free(hr_verif);
if (ur_verif) pbcext_element_G1_free(ur_verif);
if (gr_tmp1) pbcext_element_G1_free(gr_tmp1);
if (gr_tmp2) pbcext_element_G1_free(gr_tmp2);
if (hr_tmp1) pbcext_element_G1_free(hr_tmp1);
if (hr_tmp2) pbcext_element_G1_free(hr_tmp2);
if (ur_tmp1) pbcext_element_G1_free(ur_tmp1);
if (ur_tmp2) pbcext_element_G1_free(ur_tmp2);
if (hc) hash_free(hc);
if (bg) mem_free(bg);
if (c_verif) pbcext_element_Fr_free(c_verif);

return rc;
}

int ksap23_snizk2_sign(spk_rep_t *pi,
                     pbcext_element_G1_t *tilde_u,
                     pbcext_element_G1_t *g,
                     pbcext_element_G1_t *h,
                     pbcext_element_G1_t *D1,
                     pbcext_element_G1_t *D2,
                     pbcext_element_G1_t *tilde_w,
                     pbcext_element_G1_t *c0,
                     pbcext_element_G1_t *c1,
                     pbcext_element_G1_t *c2,
                     pbcext_element_Fr_t *alpha,
                     pbcext_element_Fr_t *s,
                     byte_t *m,
                     uint64_t m_len) {

    pbcext_element_Fr_t *k1 = NULL, *k2 = NULL, *s1 = NULL, *s2 = NULL;
    pbcext_element_G1_t *com1 = NULL, *com2 = NULL, *com3 = NULL, *com4 = NULL;
    hash_t *hc = NULL;
    byte_t *bg = NULL;
    uint64_t len;
    int rc = IOK;

    if (!pi || !tilde_u || !g || !h || !D1 || !D2 || !tilde_w || 
        !c0 || !c1 || !c2 || !alpha || !s || !m) {
        LOG_EINVAL(&logger, __FILE__, "snizk2_sign", __LINE__, LOGERROR);
        return IERROR;
    }

    if (!(k1 = pbcext_element_Fr_init())) GOTOENDRC(IERROR, ksap23_snizk2_sign);
    if (!(k2 = pbcext_element_Fr_init())) GOTOENDRC(IERROR, ksap23_snizk2_sign);
    if (!(com1 = pbcext_element_G1_init())) GOTOENDRC(IERROR, ksap23_snizk2_sign);
    if (!(com2 = pbcext_element_G1_init())) GOTOENDRC(IERROR, ksap23_snizk2_sign);
    if (!(com3 = pbcext_element_G1_init())) GOTOENDRC(IERROR, ksap23_snizk2_sign);
    if (!(com4 = pbcext_element_G1_init())) GOTOENDRC(IERROR, ksap23_snizk2_sign);

    /* 1. Generovanie k1 a k2 */
    if (pbcext_element_Fr_random(k1) == IERROR)
      GOTOENDRC(IERROR, ksap23_snizk2_sign);
    if (pbcext_element_Fr_random(k2) == IERROR)
      GOTOENDRC(IERROR, ksap23_snizk2_sign);

    /* 2. Výpočet kommitmentov */
    // com1 = tilde_u^k1
    if (pbcext_element_G1_mul(com1, tilde_u, k1) == IERROR)
      GOTOENDRC(IERROR, ksap23_snizk2_sign);
    
    // com2 = g^k2
    if (pbcext_element_G1_mul(com2, g, k2) == IERROR)
      GOTOENDRC(IERROR, ksap23_snizk2_sign);
    
    // com3 = g^k1 * D1^k2
    //pbcext_element_G1_t *temp = pbcext_element_G1_init();
    pbcext_element_G1_t *temp;
    if (!(temp = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, ksap23_snizk2_sign);


    if (pbcext_element_G1_mul(temp, g, k1) == IERROR)
      GOTOENDRC(IERROR, ksap23_snizk2_sign);
    if (pbcext_element_G1_mul(com3, D1, k2) == IERROR)
      GOTOENDRC(IERROR, ksap23_snizk2_sign);
    if (pbcext_element_G1_add(com3, temp, com3) == IERROR)
      GOTOENDRC(IERROR, ksap23_snizk2_sign); 
    pbcext_element_G1_free(temp);
    
    // com4 = h^k1 * D2^k2
    if (pbcext_element_G1_mul(temp, h, k1) == IERROR)
      GOTOENDRC(IERROR, ksap23_snizk2_sign);
    if (pbcext_element_G1_mul(com4, D2, k2) == IERROR)
      GOTOENDRC(IERROR, ksap23_snizk2_sign);
    if (pbcext_element_G1_add(com4, temp, com4) == IERROR)
      GOTOENDRC(IERROR, ksap23_snizk2_sign); 
    pbcext_element_G1_free(temp);

    /* 3. Hashovanie  */
    if (!(hc = hash_init(HASH_BLAKE2))) GOTOENDRC(IERROR, ksap23_snizk2_sign);
    
    /* Hash všetkých verejných parametrov + kommitmentov */
    const pbcext_element_G1_t *elements[] = {tilde_u, g, h, D1, D2, tilde_w,
                                            c0, c1, c2, com1, com2, com3, com4};

    for (int i = 0; i < 13; i++) {
    if(pbcext_element_G1_to_bytes(&bg, &len, elements[i]) == IERROR)
        GOTOENDRC(IERROR, ksap23_snizk2_sign);
    if(hash_update(hc, bg, len) == IERROR) GOTOENDRC(IERROR, ksap23_snizk2_sign);
    mem_free(bg); bg = NULL;  
    }
    
    /* Pridanie správy do hashu */
    if(hash_update(hc, m, m_len) == IERROR) GOTOENDRC(IERROR, ksap23_snizk2_sign);

    /* 4. Výzva c = H(...|m) */
    if(hash_finalize(hc) == IERROR) GOTOENDRC(IERROR, ksap23_snizk2_sign);

    if (!(pi->c = pbcext_element_Fr_init()))
      GOTOENDRC(IERROR, ksap23_snizk2_sign);
    if (pbcext_element_Fr_from_hash(pi->c, hc->hash, hc->length) == IERROR)
      GOTOENDRC(IERROR, ksap23_snizk2_sign);

    /* 5. Výpočet odpovedí */
    // s1 = k1 - c*alpha
    if (!(s1 = pbcext_element_Fr_init()))
      GOTOENDRC(IERROR, ksap23_snizk2_sign);
    if (pbcext_element_Fr_mul(s1, pi->c, alpha) == IERROR)
      GOTOENDRC(IERROR, ksap23_snizk2_sign);
    if (!(pi->s1 = pbcext_element_Fr_init()))
      GOTOENDRC(IERROR, ksap23_snizk2_sign);
    if (pbcext_element_Fr_sub(pi->s1, k1, s1) == IERROR)
      GOTOENDRC(IERROR, ksap23_snizk2_sign);
    
    // s2 = k2 - c*s
    if (!(s2 = pbcext_element_Fr_init()))
      GOTOENDRC(IERROR, ksap23_snizk2_sign);
    if (pbcext_element_Fr_mul(s2, pi->c, s) == IERROR)
      GOTOENDRC(IERROR, ksap23_snizk2_sign);
    if (!(pi->s2 = pbcext_element_Fr_init()))
      GOTOENDRC(IERROR, ksap23_snizk2_sign);
    if (pbcext_element_Fr_sub(pi->s2, k2, s2) == IERROR)
      GOTOENDRC(IERROR, ksap23_snizk2_sign);


ksap23_snizk2_sign_end:
    /* Cleanup */
    if (k1) pbcext_element_Fr_free(k1);
    if (k2) pbcext_element_Fr_free(k2);
    if (s1) pbcext_element_Fr_free(s1);
    if (s2) pbcext_element_Fr_free(s2);
    if (com1) pbcext_element_G1_free(com1);
    if (com2) pbcext_element_G1_free(com2);
    if (com3) pbcext_element_G1_free(com3);
    if (com4) pbcext_element_G1_free(com4);
    if (hc) hash_free(hc);
    if (bg) mem_free(bg);

    return rc;
}

int ksap23_snizk2_verify(uint8_t *ok,
                       spk_rep_t *pi,
                       pbcext_element_G1_t *tilde_u,
                       pbcext_element_G1_t *g,
                       pbcext_element_G1_t *h,
                       pbcext_element_G1_t *D1,
                       pbcext_element_G1_t *D2,
                       pbcext_element_G1_t *tilde_w,
                       pbcext_element_G1_t *c0,
                       pbcext_element_G1_t *c1,
                       pbcext_element_G1_t *c2,
                       byte_t *m,
                       uint64_t m_len) {

    pbcext_element_G1_t *com1 = NULL, *com2 = NULL, *com3 = NULL, *com4 = NULL;
    hash_t *hc = NULL;
    byte_t *bg = NULL;
    int rc = IOK;

    if (!ok || !pi || !tilde_u || !g || !h || !D1 || !D2 || 
        !tilde_w || !c0 || !c1 || !c2 || !m) {
        LOG_EINVAL(&logger, __FILE__, "snizk2_verify", __LINE__, LOGERROR);
        return IERROR;
    }

    /* 1. Rekonstrukcia kommitmentov */
    // com1 = tilde_u^s1 * tilde_w^c
    pbcext_element_G1_t *t1 = pbcext_element_G1_init();
    pbcext_element_G1_t *t2 = pbcext_element_G1_init();

    if (pbcext_element_G1_mul(t1, tilde_u, pi->s1) == IERROR)
      GOTOENDRC(IERROR, ksap23_snizk2_verify);
    if (pbcext_element_G1_mul(t2, tilde_w, pi->c) == IERROR)
      GOTOENDRC(IERROR, ksap23_snizk2_verify);
    if (pbcext_element_G1_add(com1, t1, t2) == IERROR)
      GOTOENDRC(IERROR, ksap23_snizk2_verify); 

    // com2 = g^s2 * c0^c
    if (pbcext_element_G1_mul(t1, g, pi->s2) == IERROR)
      GOTOENDRC(IERROR, ksap23_snizk2_verify);
    if (pbcext_element_G1_mul(t2, c0, pi->c) == IERROR)
      GOTOENDRC(IERROR, ksap23_snizk2_verify);
    if (pbcext_element_G1_add(com2, t1, t2) == IERROR)
      GOTOENDRC(IERROR, ksap23_snizk2_verify); 

    // com3 = g^s1 * D1^s2 * c1^c
    pbcext_element_G1_t *t3 = pbcext_element_G1_init();

    if (pbcext_element_G1_mul(t1, g, pi->s1) == IERROR)
      GOTOENDRC(IERROR, ksap23_snizk2_verify);
    if (pbcext_element_G1_mul(t2, D1, pi->s2) == IERROR)
      GOTOENDRC(IERROR, ksap23_snizk2_verify);
    if (pbcext_element_G1_mul(t3, c1, pi->c) == IERROR)
      GOTOENDRC(IERROR, ksap23_snizk2_verify);
    if (pbcext_element_G1_add(com3, t1, t2) == IERROR)
      GOTOENDRC(IERROR, ksap23_snizk2_verify);
    if (pbcext_element_G1_add(com3, com3, t3) == IERROR)
      GOTOENDRC(IERROR, ksap23_snizk2_verify); 

    // com4 = h^s1 * D2^s2 * c2^c
    if (pbcext_element_G1_mul(t1, h, pi->s1) == IERROR)
      GOTOENDRC(IERROR, ksap23_snizk2_verify);
    if (pbcext_element_G1_mul(t2, D2, pi->s2) == IERROR)
      GOTOENDRC(IERROR, ksap23_snizk2_verify);
    if (pbcext_element_G1_mul(t3, c2, pi->c) == IERROR)
      GOTOENDRC(IERROR, ksap23_snizk2_verify);
    if (pbcext_element_G1_add(com4, t1, t2) == IERROR)
      GOTOENDRC(IERROR, ksap23_snizk2_verify);
    if (pbcext_element_G1_add(com4, com4, t3) == IERROR)
      GOTOENDRC(IERROR, ksap23_snizk2_verify);

    /* 2. Hashovanie so spravou */
    if (!(hc = hash_init(HASH_BLAKE2))) GOTOENDRC(IERROR, ksap23_snizk2_verify);
    
    const pbcext_element_G1_t *elements[] = {tilde_u, g, h, D1, D2, tilde_w,
                                            c0, c1, c2, com1, com2, com3, com4};

    for (int i = 0; i < 13; i++) {
    if(pbcext_element_G1_to_bytes(&bg, &len, elements[i]) == IERROR)
        GOTOENDRC(IERROR, ksap23_snizk2_verify);
    if(hash_update(hc, bg, len) == IERROR) GOTOENDRC(IERROR, ksap23_snizk2_verify);
    mem_free(bg); bg = NULL;  
    }
    
    /* Pridanie spravy do hashu */
    if(hash_update(hc, m, m_len) == IERROR) GOTOENDRC(IERROR, ksap23_snizk2_verify);


    /* 3. Porovnanie vyziev */
    //pbcext_element_Fr_t *c_verif = pbcext_element_Fr_init();

    if(hash_finalize(hc) == IERROR) GOTOENDRC(IERROR, ksap23_snizk2_verify);

    //pbcext_element_Fr_t *c_verif = NULL;
    //c_verif = pbcext_element_Fr_init();

    pbcext_element_Fr_t *c_verif;
    if (!(c_verif = pbcext_element_Fr_init())) GOTOENDRC(IERROR, ksap23_snizk2_verify);


    //pbcext_element_Fr_from_hash(c_verif, hc->hash, hc->length);
    if (pbcext_element_Fr_from_hash(c_verif, hc->hash, hc->length) == IERROR)
      GOTOENDRC(IERROR, ksap23_snizk2_verify);

    
    if(pbcext_element_Fr_cmp(c_verif, pi->c)) {
      *ok = 0;
    } else {
      *ok = 1;
    }

ksap23_snizk2_verify_end:
    /* Cleanup */
    pbcext_element_G1_free(com1);
    pbcext_element_G1_free(com2);
    pbcext_element_G1_free(com3);
    pbcext_element_G1_free(com4);
    pbcext_element_G1_free(t1);
    pbcext_element_G1_free(t2);
    pbcext_element_G1_free(t3);
    hash_free(hc);
    mem_free(bg);
    pbcext_element_Fr_free(c_verif);
    
    return rc;
}

int ksap23_nizk3_sign(spk_rep3_t *pi,
                      pbcext_element_Fr_t *d1,
                      pbcext_element_Fr_t *d2,
                      pbcext_element_G1_t *g,
                      pbcext_element_G1_t *c0,
                      pbcext_element_G1_t *c1,
                      pbcext_element_G1_t *c2,
                      pbcext_element_G1_t *f1,
                      pbcext_element_G1_t *f2,
                      pbcext_element_G1_t *D1,
                      pbcext_element_G1_t *D2,
                      byte_t *m,
                      uint64_t m_len) {

    pbcext_element_G1_t *c1_f1_inv = NULL, *c2_f2_inv = NULL, *f1_inv = NULL, *f2_inv = NULL;
    pbcext_element_G1_t *t1 = NULL, *t2 = NULL, *t3 = NULL, *t4 = NULL;
    pbcext_element_Fr_t *k1 = NULL, *k2 = NULL, *s1 = NULL, *s2 = NULL;
    hash_t *hc = NULL;
    byte_t *bg = NULL;
    size_t len;
    int rc = IOK;

    if (!pi || !d1 || !d2 || !g || !c0 || !c1 || !c2 || !f1 || !f2 || !D1 || !D2 || !m) {
        LOG_EINVAL(&logger, __FILE__, "nizk3_sign", __LINE__, LOGERROR);
        return IERROR;
    }

    if (!(c1_f1_inv = pbcext_element_G1_init()) ||
        !(c2_f2_inv = pbcext_element_G1_init()) ||
        !(t1 = pbcext_element_G1_init()) ||
        !(t2 = pbcext_element_G1_init()) ||
        !(t3 = pbcext_element_G1_init()) ||
        !(t4 = pbcext_element_G1_init()) ||
        !(k1 = pbcext_element_Fr_random()) ||   // Náhodné k1, k2 ∈ Zp
        !(k2 = pbcext_element_Fr_random())) {
        GOTOENDRC(IERROR, ksap23_nizk3_sign);
    }

    /* Krok 1: Výpočet c1/f1 a c2/f2 v G1 */
    if (!(f1_inv = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, ksap23_nizk3_sign);
    if (pbcext_element_G1_neg(f1_inv, f1) == IERROR) 
      GOTOENDRC(IERROR, ksap23_nizk3_sign);
    if (pbcext_element_G1_add(c1_f1_inv, c1, f1_inv) == IERROR) 
      GOTOENDRC(IERROR, ksap23_nizk3_sign);  

    if (!(f2_inv = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, ksap23_nizk3_sign);
    if (pbcext_element_G1_neg(f2_inv, f2) == IERROR) 
      GOTOENDRC(IERROR, ksap23_nizk3_sign);
    if (pbcext_element_G1_add(c2_f2_inv, c2, f2_inv) == IERROR) 
      GOTOENDRC(IERROR, ksap23_nizk3_sign);    
    
    /*if (pbcext_element_G1_mul(c1_f1_inv, c1, f1) == IERROR)
      GOTOENDRC(IERROR, ksap23_nizk3_sign);
    if (pbcext_element_G1_neg(c1_f1_inv, c1_f1_inv) == IERROR) 
      GOTOENDRC(IERROR, ksap23_nizk3_sign);

    if (pbcext_element_G1_mul(c2_f2_inv, c2, f2) == IERROR)
      GOTOENDRC(IERROR, ksap23_nizk3_sign);
    if (pbcext_element_G1_neg(c2_f2_inv, c2_f2_inv) == IERROR) 
      GOTOENDRC(IERROR, ksap23_nizk3_sign);*/

    /* Krok 2: Generovanie komitmentov */
    // t1 = (c1/f1)^k1
    if (pbcext_element_G1_mul(t1, c1_f1_inv, k1) == IERROR)
      GOTOENDRC(IERROR, ksap23_nizk3_sign);

    // t2 = g^k1
    if (pbcext_element_G1_mul(t2, g, k1) == IERROR)
      GOTOENDRC(IERROR, ksap23_nizk3_sign);

    // (c2 * f2^{-1})^k2
    // t3 = (c2/f2)^k2
    if (pbcext_element_G1_mul(t3, c2_f2_inv, k2) == IERROR)
      GOTOENDRC(IERROR, ksap23_nizk3_sign);

    // t4 = g^k2
    if (pbcext_element_G1_mul(t4, g, k2) == IERROR)
      GOTOENDRC(IERROR, ksap23_nizk3_sign);

    /* Krok 3: Hashovanie pre výzvu c */
    if(!(hc = hash_init(HASH_BLAKE2))) GOTOENDRC(IERROR, ksap23_nizk3_sign);

    // Hashuje sa Y = (g, c0, c1, c2, f1, f2, D1, D2, t1, t2, t3, t4)
    const pbcext_element_G1_t *elements[] = {g, c0, c1, c2, f1, f2, D1, D2, t1, t2, t3, t4};
    for (int i = 0; i < 12; i++) {
      if(pbcext_element_G1_to_bytes(&bg, &len, elements[i]) == IERROR)
        GOTOENDRC(IERROR, ksap23_nizk3_sign);
      if(hash_update(hc, bg, len) == IERROR) GOTOENDRC(IERROR, ksap23_nizk3_sign);
      mem_free(bg); bg = NULL; 
    }

    // Pridanie správy m
    if(hash_update(hc, m, m_len) == IERROR) GOTOENDRC(IERROR, ksap23_nizk3_sign);

    /* Krok 4: Výpočet výziev a odpovedí */
    // c = H(Y, t1, t2, t3, t4, m)
    if(hash_finalize(hc) == IERROR) GOTOENDRC(IERROR, ksap23_nizk3_sign);

    if (!(pi->c = pbcext_element_Fr_init()))
      GOTOENDRC(IERROR, ksap23_nizk3_sign);
    if (pbcext_element_Fr_from_hash(pi->c, hc->hash, hc->length) == IERROR)
      GOTOENDRC(IERROR, ksap23_nizk3_sign);

    // s1 = k1 - c * d1
    if (!(s1 = pbcext_element_Fr_init()))
      GOTOENDRC(IERROR, ksap23_nizk3_sign);
    if (pbcext_element_Fr_mul(s1, pi->c, d1) == IERROR)
      GOTOENDRC(IERROR, ksap23_nizk3_sign);
    if (!(pi->s1 = pbcext_element_Fr_init()))
      GOTOENDRC(IERROR, ksap23_nizk3_sign);
    if (pbcext_element_Fr_sub(pi->s1, k1, s1) == IERROR)
      GOTOENDRC(IERROR, ksap23_nizk3_sign);


    // s2 = k2 - c * d2
    if (!(s2 = pbcext_element_Fr_init()))
      GOTOENDRC(IERROR, ksap23_nizk3_sign);
    if (pbcext_element_Fr_mul(s2, pi->c, d2) == IERROR)
      GOTOENDRC(IERROR, ksap23_nizk3_sign);
    if (!(pi->s2 = pbcext_element_Fr_init()))
      GOTOENDRC(IERROR, ksap23_nizk3_sign);
    if (pbcext_element_Fr_sub(pi->s2, k2, s2) == IERROR)
      GOTOENDRC(IERROR, ksap23_nizk3_sign);

ksap23_nizk3_sign_end:
    
    if (c1_f1_inv) pbcext_element_G1_free(c1_f1_inv);
    if (c2_f2_inv) pbcext_element_G1_free(c2_f2_inv);
    if (f1_inv) pbcext_element_G1_free(f1_inv);
    if (f2_inv) pbcext_element_G1_free(f2_inv);
    if (t1) pbcext_element_G1_free(t1);
    if (t2) pbcext_element_G1_free(t2);
    if (t3) pbcext_element_G1_free(t3);
    if (t4) pbcext_element_G1_free(t4);
    if (k1) pbcext_element_Fr_free(k1);
    if (k2) pbcext_element_Fr_free(k2);
    if (hc) hash_free(hc);
    if (bg) mem_free(bg);
    
    return rc;
}

int ksap23_nizk3_verify(uint8_t *ok,
                        spk_rep3_t *pi,
                        pbcext_element_G1_t *g,
                        pbcext_element_G1_t *c0,
                        pbcext_element_G1_t *c1,
                        pbcext_element_G1_t *c2,
                        pbcext_element_G1_t *f1,
                        pbcext_element_G1_t *f2,
                        pbcext_element_G1_t *D1,
                        pbcext_element_G1_t *D2,
                        byte_t *m,
                        uint64_t m_len) { 

    pbcext_element_G1_t *t1 = NULL, *t2 = NULL, *t3 = NULL, *t4 = NULL;
    pbcext_element_G1_t *c1_f1_inv = NULL, *c2_f2_inv = NULL, *f1_inv = NULL, *f2_inv = NULL;
    pbcext_element_G1_t *temp = NULL;
    hash_t *hc = NULL;
    byte_t *bg = NULL;
    size_t len;
    int rc = IOK;

    if (!ok || !pi || !g || !c0 || !c1 || !c2 || !f1 || !f2 || !D1 || !D2 || !m) {
        LOG_EINVAL(&logger, __FILE__, "nizk3_verify", __LINE__, LOGERROR);
        return IERROR;
    }

    if (!(c1_f1_inv = pbcext_element_G1_init()) ||
        !(c2_f2_inv = pbcext_element_G1_init()) ||
        !(t1 = pbcext_element_G1_init()) ||
        !(t2 = pbcext_element_G1_init()) ||
        !(t3 = pbcext_element_G1_init()) ||
        !(t4 = pbcext_element_G1_init()) ||
        !(temp = pbcext_element_G1_init())) {
        GOTOENDRC(IERROR, ksap23_nizk3_verify);
    }

    /* Výpočet c1/f1 a c2/f2 v G1 */
    if (!(f1_inv = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, ksap23_nizk3_verify);
    if (pbcext_element_G1_neg(f1_inv, f1) == IERROR) 
      GOTOENDRC(IERROR, ksap23_nizk3_verify);
    if (pbcext_element_G1_add(c1_f1_inv, c1, f1_inv) == IERROR) 
      GOTOENDRC(IERROR, ksap23_nizk3_verify);  

    if (!(f2_inv = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, ksap23_nizk3_verify);
    if (pbcext_element_G1_neg(f2_inv, f2) == IERROR) 
      GOTOENDRC(IERROR, ksap23_nizk3_verify);
    if (pbcext_element_G1_add(c2_f2_inv, c2, f2_inv) == IERROR) 
      GOTOENDRC(IERROR, ksap23_nizk3_verify);     

    /*if (pbcext_element_G1_mul(c1_f1_inv, c1, f1) == IERROR)
      GOTOENDRC(IERROR, ksap23_nizk3_verify);
    if (pbcext_element_G1_neg(c1_f1_inv, c1_f1_inv) == IERROR) 
      GOTOENDRC(IERROR, ksap23_nizk3_verify);

    if (pbcext_element_G1_mul(c2_f2_inv, c2, f2) == IERROR)
      GOTOENDRC(IERROR, ksap23_nizk3_verify);
    if (pbcext_element_G1_neg(c2_f2_inv, c2_f2_inv) == IERROR) 
      GOTOENDRC(IERROR, ksap23_nizk3_verify);*/

    /* Rekonštrukcia komitmentov t1-t4 */ 
    // t1 = (c1/f1)^s1 * c0^{c}
    if (pbcext_element_G1_mul(temp, c1_f1_inv, pi->s1) == IERROR)
      GOTOENDRC(IERROR, ksap23_nizk3_verify);
    if (pbcext_element_G1_mul(t1, c0, pi->c) == IERROR)
      GOTOENDRC(IERROR, ksap23_nizk3_verify);
    if(pbcext_element_G1_add(t1, temp, t1) == IERROR)
      GOTOENDRC(IERROR, ksap23_nizk3_verify);

    // t2 = D1^s1 * g^c
    if (pbcext_element_G1_mul(temp, D1, pi->s1) == IERROR)
      GOTOENDRC(IERROR, ksap23_nizk3_verify);
    if (pbcext_element_G1_mul(t2, g, pi->c) == IERROR)
      GOTOENDRC(IERROR, ksap23_nizk3_verify);
    if(pbcext_element_G1_add(t2, temp, t2) == IERROR)
      GOTOENDRC(IERROR, ksap23_nizk3_verify);

    // t3 = (c2/f2)^s2 * c0^{c}
    if (pbcext_element_G1_mul(temp, c2_f2_inv, pi->s2) == IERROR)
      GOTOENDRC(IERROR, ksap23_nizk3_verify);
    if (pbcext_element_G1_mul(t3, c0, pi->c) == IERROR)
      GOTOENDRC(IERROR, ksap23_nizk3_verify);
    if(pbcext_element_G1_add(t3, temp, t3) == IERROR)
      GOTOENDRC(IERROR, ksap23_nizk3_verify);

    // t4 = D2^s2 * g^c
    if (pbcext_element_G1_mul(temp, D2, pi->s2) == IERROR)
      GOTOENDRC(IERROR, ksap23_nizk3_verify);
    if (pbcext_element_G1_mul(t4, g, pi->c) == IERROR)
      GOTOENDRC(IERROR, ksap23_nizk3_verify);
    if(pbcext_element_G1_add(t4, temp, t4) == IERROR)
      GOTOENDRC(IERROR, ksap23_nizk3_verify);

    /* Hashovanie všetkých prvkov a správy */
    if(!(hc = hash_init(HASH_BLAKE2))) GOTOENDRC(IERROR, ksap23_nizk3_verify);

    // Zoznam prvkov: Y = (g, c0, c1, c2, f1, f2, D1, D2)
    const pbcext_element_G1_t *elements[] = {g, c0, c1, c2, f1, f2, D1, D2, t1, t2, t3, t4};
    for (int i = 0; i < 12; i++) {
        if(pbcext_element_G1_to_bytes(&bg, &len, elements[i]) == IERROR)
            GOTOENDRC(IERROR, ksap23_nizk3_verify);
        if(hash_update(hc, bg, len) == IERROR){
          mem_free(bg);
          GOTOENDRC(IERROR, ksap23_nizk3_verify);
        } 
        mem_free(bg); bg = NULL;  
    }

    // Pridanie správy do hashu
    if(hash_update(hc, m, m_len) == IERROR) GOTOENDRC(IERROR, ksap23_nizk3_verify);

    /* Výpočet a porovnanie výziev */
    //pbcext_element_Fr_t *c_verif = pbcext_element_Fr_init();

    pbcext_element_Fr_t *c_verif;
    if (!(c_verif = pbcext_element_Fr_init()))
     GOTOENDRC(IERROR, ksap23_nizk3_verify);
    /*if(c_verif = pbcext_element_Fr_init() == IERROR) GOTOENDRC(IERROR, ksap23_nizk3_verify);*/

    if(hash_finalize(hc) == IERROR) GOTOENDRC(IERROR, ksap23_nizk3_verify);

    //pbcext_element_Fr_from_hash(c_verif, hc->hash, hc->length);

    if (pbcext_element_Fr_from_hash(c_verif, hc->hash, hc->length) == IERROR)
      GOTOENDRC(IERROR, ksap23_nizk3_verify);

    
    if(pbcext_element_Fr_cmp(c_verif, pi->c)) { 
      *ok = 0;
    } else {
      *ok = 1;
    }

ksap23_nizk3_verify_end:
    
    if (c1_f1_inv) pbcext_element_G1_free(c1_f1_inv);
    if (c2_f2_inv) pbcext_element_G1_free(c2_f2_inv);
    if (f1_inv) pbcext_element_G1_free(f1_inv);
    if (f2_inv) pbcext_element_G1_free(f2_inv);
    if (t1) pbcext_element_G1_free(t1);
    if (t2) pbcext_element_G1_free(t2);
    if (t3) pbcext_element_G1_free(t3);
    if (t4) pbcext_element_G1_free(t4);
    if (temp) pbcext_element_G1_free(temp);
    if (hc) hash_free(hc);
    if (bg) mem_free(bg);
    if (c_verif) pbcext_element_Fr_free(c_verif);

    return rc;
}