/**
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

 #ifndef GROUPSIG_KSAP23_NIZK_H
 #define GROUPSIG_KSAP23_NIZK_H
 
 #include "types.h"
 #include "crypto/spk.h"
 #include "sysenv.h"
 #include "shim/pbc_ext.h"
 
 #ifdef __cplusplus
 extern "C" {
 #endif
 
 /**
  * @file groupsig/ksap23/nizk.h
  * @brief Non-interactive zero-knowledge proofs for KSAP23 group signatures.
  */
 
 /**
  * @brief Signs a NIZK1 proof for knowledge of α in G1 elements.
  * 
  * @param[out] pi The SPK representation to store the proof.
  * @param[in] g Generator of G1.
  * @param[in] h Group element in G1.
  * @param[in] u Group element in G1.
  * @param[in] f1 Group element in G1.
  * @param[in] f2 Group element in G1.
  * @param[in] w Group element in G1.
  * @param[in] alpha Secret exponent α.
  * @return IOK on success, IERROR on failure.
  */
 int ksap23_nizk1_sign(spk_rep_t *pi,
                       pbcext_element_G1_t *g,
                       pbcext_element_G1_t *h,
                       pbcext_element_G1_t *u,
                       pbcext_element_G1_t *f1,
                       pbcext_element_G1_t *f2,
                       pbcext_element_G1_t *w,
                       pbcext_element_Fr_t *alpha);
 
 /**
  * @brief Verifies a NIZK1 proof of knowledge.
  * 
  * @param[out] ok Verification result (1 valid, 0 invalid).
  * @param[in] pi The SPK proof to verify.
  * @param[in] g Generator of G1.
  * @param[in] h Group element in G1.
  * @param[in] u Group element in G1.
  * @param[in] f1 Group element in G1.
  * @param[in] f2 Group element in G1.
  * @param[in] w Group element in G1.
  * @return IOK on success, IERROR on failure.
  */
 int ksap23_nizk1_verify(uint8_t *ok,
                         spk_rep_t *pi,
                         pbcext_element_G1_t *g,
                         pbcext_element_G1_t *h,
                         pbcext_element_G1_t *u,
                         pbcext_element_G1_t *f1,
                         pbcext_element_G1_t *f2,
                         pbcext_element_G1_t *w);
 
 /**
  * @brief Signs a SNIZK2 proof with message binding.
  * 
  * @param[out] pi The SPK representation to store the proof.
  * @param[in] tilde_u Group element in G1.
  * @param[in] g Generator of G1.
  * @param[in] h Group element in G1.
  * @param[in] D1 Group element in G1.
  * @param[in] D2 Group element in G1.
  * @param[in] tilde_w Group element in G1.
  * @param[in] c0 Group element in G1.
  * @param[in] c1 Group element in G1.
  * @param[in] c2 Group element in G1.
  * @param[in] alpha Secret exponent α.
  * @param[in] s Secret exponent s.
  * @param[in] m Message to sign.
  * @param[in] m_len Message length in bytes.
  * @return IOK on success, IERROR on failure.
  */
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
                        uint64_t m_len);
 
 /**
  * @brief Verifies a SNIZK2 proof with message binding.
  * 
  * @param[out] ok Verification result (1 valid, 0 invalid).
  * @param[in] pi The SPK proof to verify.
  * @param[in] tilde_u Group element in G1.
  * @param[in] g Generator of G1.
  * @param[in] h Group element in G1.
  * @param[in] D1 Group element in G1.
  * @param[in] D2 Group element in G1.
  * @param[in] tilde_w Group element in G1.
  * @param[in] c0 Group element in G1.
  * @param[in] c1 Group element in G1.
  * @param[in] c2 Group element in G1.
  * @param[in] m Signed message.
  * @param[in] m_len Message length in bytes.
  * @return IOK on success, IERROR on failure.
  */
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
                          uint64_t m_len);
 
 /**
  * @brief Signs a NIZK3 proof for secret exponents d1, d2.
  * 
  * @param[out] pi The SPK3 representation to store the proof.
  * @param[in] d1 Secret exponent d1.
  * @param[in] d2 Secret exponent d2.
  * @param[in] g Generator of G1.
  * @param[in] c0 Group element in G1.
  * @param[in] c1 Group element in G1.
  * @param[in] c2 Group element in G1.
  * @param[in] f1 Group element in G1.
  * @param[in] f2 Group element in G1.
  * @param[in] D1 Group element in G1.
  * @param[in] D2 Group element in G1.
  * @param[in] m Message to sign.
  * @param[in] m_len Message length in bytes.
  * @return IOK on success, IERROR on failure.
  */
 int ksap23_nizk3_sign(spk_rep_t *pi,
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
                       uint64_t m_len);
 
 /**
  * @brief Verifies a NIZK3 proof of knowledge.
  * 
  * @param[out] ok Verification result (1 valid, 0 invalid).
  * @param[in] pi The SPK3 proof to verify.
  * @param[in] g Generator of G1.
  * @param[in] c0 Group element in G1.
  * @param[in] c1 Group element in G1.
  * @param[in] c2 Group element in G1.
  * @param[in] f1 Group element in G1.
  * @param[in] f2 Group element in G1.
  * @param[in] D1 Group element in G1.
  * @param[in] D2 Group element in G1.
  * @param[in] m Signed message.
  * @param[in] m_len Message length in bytes.
  * @return IOK on success, IERROR on failure.
  */
 int ksap23_nizk3_verify(uint8_t *ok,
                         spk_rep_t *pi,
                         pbcext_element_G1_t *g,
                         pbcext_element_G1_t *c0,
                         pbcext_element_G1_t *c1,
                         pbcext_element_G1_t *c2,
                         pbcext_element_G1_t *f1,
                         pbcext_element_G1_t *f2,
                         pbcext_element_G1_t *D1,
                         pbcext_element_G1_t *D2,
                         byte_t *m,
                         uint64_t m_len);
 
 #ifdef __cplusplus
 }
 #endif
 
 #endif /* GROUPSIG_KSAP23_NIZK_H */