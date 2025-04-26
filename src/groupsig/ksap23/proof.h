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

 #ifndef GROUPSIG_KSAP23_PROOF_H
 #define GROUPSIG_KSAP23_PROOF_H
 
 #include "groupsig/ksap23/nizk.h"
 #include "include/proof.h"
 #include "ksap23.h"
 #include "crypto/spk.h"
 
 /**
  * @struct ksap23_proof_t
  * @brief Open proofs for ksap23.
  */
// typedef spk_rep_t ksap23_proof_t;
/**
 * @struct ksap23_proof_t
 * @brief Open proofs for ksap23. Upravené podľa dokumentácie Π = (f1, f2, π3)
 */
typedef struct {
  pbcext_element_G1_t *f1;          // Prvok f1 ∈ G1
  pbcext_element_G1_t *f2;          // Prvok f2 ∈ G1
  spk_rep_t *pi;        // Dôkaz π3
} ksap23_proof_t;
 
 /** 
  * @fn struct groupsig_proof_t* ksap23_proof_init()
  * @brief Initializes the fields of a ksap23 proof.
  *
  * @return A pointer to the allocated proof or NULL if error.
  */
 groupsig_proof_t* ksap23_proof_init();
 
 /** 
  * @fn int ksap23_proof_free(groupsig_proof_t *proof)
  * @brief Frees the alloc'ed fields of the given ksap23 proof.
  *
  * @param[in,out] proof The proof to free.
  * 
  * @return IOK or IERROR
  */
 int ksap23_proof_free(groupsig_proof_t *proof);
 
 /** 
  * @fn int ksap23_proof_to_string
  * @brief Returns a printable string representing the current proof.
  *
  * @param[in] proof The proof to print.
  * 
  * @return A string or NULL if error.
  */
 char* ksap23_proof_to_string(groupsig_proof_t *proof);
 
 /** 
  * @fn int ksap23_proof_get_size(groupsig_proof_t *proof)
  * @brief Returns the size of the proof as an array of bytes.
  *
  * @param[in] proof The proof.
  * 
  * @return -1 if error. Otherwise, the size of the proof in bytes.
  */
 int ksap23_proof_get_size(groupsig_proof_t *proof);
 
 /** 
  * @fn int ksap23_proof_export(byte_t **bytes, uint32_t *size, groupsig_proof_t *proof);
  * @brief Exports the proof to a byte array.
  *
  * @param[in,out] bytes A pointer to the array that will contain the exported proof.
  * @param[in,out] size Will be set to the number of bytes written.
  * @param[in] proof The proof to export.
  * 
  * @return IOK or IERROR
  */
 int ksap23_proof_export(byte_t **bytes, uint32_t *size, groupsig_proof_t *proof);
 
 /** 
  * @fn groupsig_proof_t* ksap23_proof_import(byte_t *source, uint32_t size)
  * @brief Imports a proof from a byte array.
  *
  * @param[in] source The byte array containing the proof.
  * @param[in] size The number of bytes in the array.
  * 
  * @return A pointer to the imported proof or NULL if error.
  */
 groupsig_proof_t* ksap23_proof_import(byte_t *source, uint32_t size);
 
 /**
  * @var ksap23_proof_handle
  * @brief Set of functions to manage ksap23 proofs.
  */
 static const groupsig_proof_handle_t ksap23_proof_handle = {
   .scheme = GROUPSIG_ksap23_CODE,
   .init = &ksap23_proof_init,
   .free = &ksap23_proof_free,
   .get_size = &ksap23_proof_get_size,
   .gexport = &ksap23_proof_export,
   .gimport = &ksap23_proof_import,
   .to_string = &ksap23_proof_to_string
 };
 
 #endif /* GROUPSIG_KSAP23_PROOF_H */