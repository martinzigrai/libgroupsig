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

#ifndef _ksap23_H
#define _ksap23_H

#include <stdlib.h>

#include "key.h"
#include "gml.h"
#include "crl.h"
#include "signature.h"
#include "proof.h"
#include "bld_key.h"
#include "grp_key.h"
#include "mgr_key.h"
#include "mem_key.h"
#include "groupsig.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @def GROUPSIG_ksap23_CODE
 * @brief ksap23 scheme code.
 */
#define GROUPSIG_ksap23_CODE 5

/**
 * @def GROUPSIG_ksap23_NAME
 * @brief ksap23 scheme name.
 */
#define GROUPSIG_ksap23_NAME "ksap23"

/**
 * @var ksap23_description
 * @brief ksap23's description.
 */
static const groupsig_description_t ksap23_description = {
  GROUPSIG_ksap23_CODE, /**< ksap23's scheme code. */
  GROUPSIG_ksap23_NAME, /**< ksap23's scheme name. */
  1, /**< ksap23 has a GML. */
  0, /**< ksap23 does not have a CRL. */
  1, /**< ksap23 uses PBC. */
  1,  /**< ksap23 has verifiable openings. */
  1, /**< ksap23's issuer key is the first manager key. */
  2 /**< ksap23's inspector (opener) key is the second manager key. */
};

/* Metadata for the join protocol */

/* 0 means the first message is sent by the manager, 1 means the first message
   is sent by the member */
#define ksap23_JOIN_START 0

/* Number of exchanged messages */
#define ksap23_JOIN_SEQ 3

/** 
 * @fn int ksap23_init()
 * @brief Initializes the internal variables needed by ksap23. In this case,
 *  it only sets up the pairing module.
 *
 * @return IOK or IERROR.
 */  
int ksap23_init();

/** 
 * @fn int ksap23_clear()
 * @brief Frees the memory initialized by ksap23_init.
 *
 * @return IOK or IERROR.
 */   
int ksap23_clear();  

/** 
 * @fn int ksap23_setup(groupsig_key_t *grpkey, 
 *                      groupsig_key_t *mgrkey, 
 *                      gml_t *gml)
 * @brief The setup function for the ksap23 scheme. Used to generate group public
 *  key and the managers keys.
 * 
 *  In ksap23, we have two central entities (managers in libgroupsig jargon): the 
 *  Issuer, and the Opener. Both managers have public-private keypairs, their
 *  public parts being a part of the overall group public key. In order to 
 *  properly create the group public key and the manager's keys, we need to call
 *  setup twice. The first time it is called, a partial group public key will be
 *  generated, along with the Issuer's private key (i.e., the Issuer is expected
 *  to initiate this process.) The second call must receive as input the partial
 *  group public key obtained in the first call, and a new manager key. As a
 *  result of the second call, the group public key is completely set up, and the
 *  Opener's private key is also generated. Therefore, this second call is 
 *  expected to be made by the Opener.
 *
 *  To be precise, whenever an empty group public key (i.e., an initialized ksap23
 *  groupsig_key_t struct, with all fields in the key sub-struct set to NULL), 
 *  is received, the function assumes that this is a first call.
 *
 * @param[in,out] grpkey An initialized group key. In the first call, a partial
 *  group public key will be returned.
 * @param[in,out] mgrkey An initialized manager key. In the first call, it will
 *  be set to the Issuer's private key. In the second call, it will be set to 
 *  the converter's private key..
 * @param[in] gml Ignored.
 * 
 * @return IOK or IERROR.
 */
int ksap23_setup(groupsig_key_t *grpkey,
		 groupsig_key_t *mgrkey,
		 gml_t *gml);

/**
 * @fn int ksap23_get_joinseq(uint8_t *seq)
 * @brief Returns the number of messages to be exchanged in the join protocol.
 * 
 * @param seq A pointer to store the number of messages to exchange.
 *
 * @return IOK or IERROR.
 */ 
int ksap23_get_joinseq(uint8_t *seq);

/**
 * @fn int ksap23_get_joinstart(uint8_t *start)
 * @brief Returns who sends the first message in the join protocol.
 * 
 * @param start A pointer to store the who starts the join protocol. 0 means
 *  the Manager starts the protocol, 1 means the Member starts the protocol.
 *
 * @return IOK or IERROR.
 */ 
int ksap23_get_joinstart(uint8_t *start);

/** 
* @fn int ksap23_join_mem(message_t **mout, groupsig_key_t *memkey,
 *			      int seq, message_t *min, groupsig_key_t *grpkey)
 * @brief Executes the member-side join of the ksap23 scheme.
 *
 * @param[in,out] mout Message to be produced by the current step of the
 *  join/issue protocol.
 * @param[in,out] memkey An initialized group member key. Must have been
 *  initialized by the caller. Will be set to the final member key once
 *  the join/issue protocol is completed.
 * @param[in] seq The step to run of the join/issue protocol.
 * @param[in] min Input message received from the manager for the current step
 *  of the join/issue protocol.
 * @param[in] grpkey The group key.
 * 
 * @return IOK or IERROR.
 */
int ksap23_join_mem(message_t **mout,
		    groupsig_key_t *memkey,
		    int seq,
		    message_t *min,
		    groupsig_key_t *grpkey);

/** 
 * @fn int ksap23_join_mgr(message_t **mout, 
 *                       gml_t *gml,
 *                       groupsig_key_t *mgrkey,
 *                       int seq, 
 *                       message_t *min, 
 *			 groupsig_key_t *grpkey)
 * @brief Executes the manager-side join of the join procedure.
 *
 * @param[in,out] mout Message to be produced by the current step of the join/
 *  issue protocol.
 * @param[in,out] gml The group membership list that may be updated with
 *  information related to the new member.
// * @param[in,out] memkey The partial member key to be completed by the group
* @param[in] seq The step to run of the join/issue protocol.
 *  manager.
 * @param[in] min Input message received from the member for the current step of
 *  the join/issue protocol.
 * @param[in] mgrkey The group manager key.
 * @param[in] grpkey The group key.
 * 
 * @return IOK or IERROR.
 */
int ksap23_join_mgr(message_t **mout,
		  gml_t *gml,
		  groupsig_key_t *mgrkey,
		  int seq,
		  message_t *min,
		  groupsig_key_t *grpkey);

/** 
 * @fn int ksap23_sign(groupsig_signature_t *sig, 
 *                   message_t *msg, 
 *                   groupsig_key_t *memkey, 
 *	             groupsig_key_t *grpkey, 
 *                   unsigned int seed)
 * @brief Issues ksap23 group signatures.
 *
 * Using the specified member and group keys, issues a signature for the specified
 * message.
 *
 * @param[in,out] sig An initialized ksap23 group signature. Will be updated with
 *  the generated signature data.
 * @param[in] msg The message to sign.
 * @param[in] memkey The member key to use for signing.
 * @param[in] grpkey The group key.
 * @param[in] seed The seed. If it is set to UINT_MAX, the current system PRNG
 *  will be used normally. Otherwise, it will be reseeded with the specified
 *  seed before issuing the signature. 
 * 
 * @return IOK or IERROR.
 */
int ksap23_sign(groupsig_signature_t *sig,
	      message_t *msg,
	      groupsig_key_t *memkey, 
	      groupsig_key_t *grpkey,
	      unsigned int seed);

/** 
 * @fn int ksap23_verify(uint8_t *ok, 
 *                     groupsig_signature_t *sig, 
 *                     message_t *msg, 
 *		       groupsig_key_t *grpkey);
 * @brief Verifies a ksap23 group signature.
 *
 * @param[in,out] ok Will be set to 1 if the verification succeeds, to 0 if
 *  it fails.
 * @param[in] sig The signature to verify.
 * @param[in] msg The corresponding message.
 * @param[in] grpkey The group key.
 * 
 * @return IOK or IERROR.
 */
int ksap23_verify(uint8_t *ok,
		groupsig_signature_t *sig,
		message_t *msg, 
		groupsig_key_t *grpkey);

/** 
 * @fn int ksap23_verify_batch(uint8_t *ok, 
 *                             groupsig_signature_t **sigs, 
 *                             message_t **msgs, 
 *                             uint32_t n,
 *		               groupsig_key_t *grpkey);
 * @brief Verifies a ksap23 group signature.
 *
 * @param[in,out] ok Will be set to 1 if the verification succeeds, to 0 if
 *  it fails.
 * @param[in] sigs The signatures to verify.
 * @param[in] msgs The corresponding messagse.
 * @param[in] n The size of the sigs and msgs array.
 * @param[in] grpkey The group key.
 * 
 * @return IOK or IERROR.
 */
int ksap23_verify_batch(uint8_t *ok,
			groupsig_signature_t **sigs,
			message_t **msgs,
			uint32_t n,
			groupsig_key_t *grpkey);  

/** 
 * @fn int ksap23_open(uint64_t *index, groupsig_proof_t *proof, crl_t *crl, 
 *                    groupsig_signature_t *sig, groupsig_key_t *grpkey, 
 *	              groupsig_key_t *mgrkey, gml_t *gml)
 * @brief Opens a ksap23 group signature.
 * 
 * Opens the specified group signature, obtaining the signer's identity.
 *
 * @param[in,out] index Will be updated with the signer's index in the GML.
 * @param[in,out] proof ksap23 ignores this parameter.
 * @param[in,out] crl Unused. Ignore.
 * @param[in] sig The signature to open.
 * @param[in] grpkey The group key.
 * @param[in] mgrkey The manager's key.
 * @param[in] gml The GML.
 * 
 * @return IOK if it was possible to open the signature. IFAIL if the open
 *  trapdoor was not found, IERROR otherwise.
 */
int ksap23_open(uint64_t *index,
		groupsig_proof_t *proof,
		crl_t *crl,
		groupsig_signature_t *sig,
		groupsig_key_t *grpkey,
		groupsig_key_t *mgrkey,
		gml_t *gml);

/** 
 * @fn int ksap23_open_verify(uint8_t *ok,
 *                          groupsig_proof_t *proof, 
 *                          groupsig_signature_t *sig,
 *                          groupsig_key_t *grpkey)
 * 
 * @param[in,out] ok Will be set to 1 if the proof is correct, to 0 otherwise.
 *  signature.
 * @param[in] id The identity produced by the open algorithm. Unused. Can be NULL.
 * @param[in] proof The proof of opening.
 * @param[in] sig The group signature associated to the proof.
 * @param[in] grpkey The group key.
 * 
 * @return IOK or IERROR
 */
int ksap23_open_verify(uint8_t *ok,
		       groupsig_proof_t *proof, 
		       groupsig_signature_t *sig,
		       groupsig_key_t *grpkey);  
  
/**
 * @var ksap23_groupsig_bundle
 * @brief The set of functions to manage ksap23 groups.
 */
static const groupsig_t ksap23_groupsig_bundle = {
 desc: &ksap23_description, /**< Contains the ksap23 scheme description. */
 init: &ksap23_init, /**< Initializes the variables needed by ksap23. */
 clear: &ksap23_clear, /**< Frees the varaibles needed by ksap23. */  
 setup: &ksap23_setup, /**< Sets up ksap23 groups. */
 get_joinseq: &ksap23_get_joinseq, /**< Returns the number of messages in the join 
			protocol. */
 get_joinstart: &ksap23_get_joinstart, /**< Returns who begins the join protocol. */
 join_mem: &ksap23_join_mem, /**< Executes member-side joins. */
 join_mgr: &ksap23_join_mgr, /**< Executes manager-side joins. */
 sign: &ksap23_sign, /**< Issues ksap23 signatures. */
 verify: &ksap23_verify, /**< Verifies ksap23 signatures. */
 verify_batch: &ksap23_verify_batch, /**< Verifies batches of ksap23 signatures. */
 open: &ksap23_open, /**< Opens ksap23 signatures. */
 open_verify: &ksap23_open_verify, /**< ksap23 does not create proofs of opening. */
 reveal: NULL, // &ksap23_reveal, /**< Reveals the tracing trapdoor from ksap23 signatures. */
 trace: NULL, // &ksap23_trace, /**< Traces the issuer of a signature. */ 
 claim: NULL, // &ksap23_claim, /**< Claims, in ZK, "ownership" of a signature. */
 claim_verify: NULL, // &ksap23_claim_verify, /**< Verifies claims. */
 prove_equality: NULL, // &ksap23_prove_equality, /**< Issues "same issuer" ZK proofs for several signatures. */
 prove_equality_verify: NULL, // &ksap23_prove_equality_verify, /**< Verifies "same issuer" ZK proofs. */
 blind: NULL, /**< Blinds group signatures. */
 convert: NULL, /**< Converts blinded group signatures. */
 unblind: NULL, /**< Unblinds converted group signatures. */
 identify: NULL, // &identify, /**< Determines whether a signature has been issued by a member. */
 link: NULL, // &link, 
 verify_link: NULL, // &link_verify
 seqlink: NULL, // &seqlink, 
 verify_seqlink: NULL, // &seqlink_verify
};

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
/* Write any cplusplus specific code here */
#endif
  
#endif /* _ksap23_H */

/* ksap23.h ends here */
