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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "misc/misc.h"
#include "sys/mem.h"
#include "ksap23.h"
#include "groupsig/ksap23/gml.h"
#include "shim/pbc_ext.h"
 #include "crypto/spk.h"

gml_t* ksap23_gml_init() {

  gml_t *gml;

  if(!(gml = (gml_t *) malloc(sizeof(gml_t)))) {
    LOG_ERRORCODE(&logger, __FILE__, "ksap23_gml_init", __LINE__, errno, LOGERROR);
    return NULL;
  }

  gml->scheme = GROUPSIG_ksap23_CODE;
  gml->entries = NULL;
  gml->n = 0;

  return gml;

}

int ksap23_gml_free(gml_t *gml) {

  uint64_t i;

  if(!gml || gml->scheme != GROUPSIG_ksap23_CODE) {
    LOG_EINVAL_MSG(&logger, __FILE__, "ksap23_gml_free", __LINE__,
  		   "Nothing to free.", LOGWARN);
    return IOK;
  }

  if (gml->entries) {
    for(i=0; i<gml->n; i++) {
      ksap23_gml_entry_free(gml->entries[i]); gml->entries[i] = NULL;
    }
    mem_free(gml->entries); gml->entries = NULL;    
  }

  mem_free(gml); gml = NULL;

  return IOK;

}

int ksap23_gml_insert(gml_t *gml, gml_entry_t *entry) {

  if(!gml || gml->scheme != GROUPSIG_ksap23_CODE ||
     gml->scheme != entry->scheme) {
    LOG_EINVAL(&logger, __FILE__, "ksap23_gml_insert", __LINE__, LOGERROR);
    return IERROR;
  }

  if(!(gml->entries = (gml_entry_t **) 
       realloc(gml->entries, sizeof(gml_entry_t *)*(gml->n+1)))) {
    LOG_ERRORCODE(&logger, __FILE__, "ksap23_gml_insert", __LINE__, errno,
		  LOGERROR);
    return IERROR;
  }

  gml->entries[gml->n] = entry;
  gml->n++;

  return IOK;

}

int ksap23_gml_remove(gml_t *gml, uint64_t index) {

  if(!gml || gml->scheme != GROUPSIG_ksap23_CODE) {
    LOG_EINVAL(&logger, __FILE__, "ksap23_gml_remove", __LINE__, LOGERROR);
    return IERROR;
  }

  if(index >= gml->n) {
    LOG_EINVAL_MSG(&logger, __FILE__, "ksap23_gml_remove", __LINE__,
		   "Invalid index.", LOGERROR);
    return IERROR;
  }

  /* Just set it to NULL */
  /** @todo This will generate a lot of unused memory! Use some other ADT */
  gml->entries[index] = NULL;
  
  /* Decrement the number of entries */
  gml->n--;

  return IOK;

}

gml_entry_t* ksap23_gml_get(gml_t *gml, uint64_t index) {

  if(!gml || gml->scheme != GROUPSIG_ksap23_CODE) {
    LOG_EINVAL(&logger, __FILE__, "ksap23_gml_get", __LINE__, LOGERROR);
    return NULL;
  }

  if(index >= gml->n) {
    LOG_EINVAL_MSG(&logger, __FILE__, "ksap23_gml_get", __LINE__, "Invalid index.",
  		   LOGERROR);
    return NULL;
  }

  return gml->entries[index];
  
}

int ksap23_gml_export(byte_t **bytes, uint32_t *size, gml_t *gml) {

  byte_t *bentry, *_bytes;
  uint64_t i;
  int rc;  
  uint32_t total_size, entry_size;
  
  if (!bytes || !size || !gml || gml->scheme != GROUPSIG_ksap23_CODE) {
    LOG_EINVAL(&logger, __FILE__, "ksap23_gml_export", __LINE__, LOGERROR);
    return IERROR;
  }

  rc = IOK;
  total_size = entry_size = 0;
  bentry = _bytes = NULL;

  /* Dump the number of entries */
  if (!(_bytes = mem_malloc(sizeof(uint64_t))))
    GOTOENDRC(IERROR, ksap23_gml_export);
  memcpy(_bytes, &gml->n, sizeof(uint64_t));
  total_size = sizeof(uint64_t);

  /* Export the entries one by one */
  for (i=0; i<gml->n; i++) {
    if (gml_entry_export(&bentry, &entry_size, gml->entries[i]) == IERROR)
      GOTOENDRC(IERROR, ksap23_gml_export);
    total_size += entry_size;
    if (!(_bytes = mem_realloc(_bytes, total_size)))
      GOTOENDRC(IERROR, ksap23_gml_export);
    memcpy(&_bytes[total_size-entry_size], bentry, entry_size);
    mem_free(bentry); bentry = NULL;
  }

  if (!*bytes) {
    *bytes = _bytes;
  } else {
    memcpy(*bytes, _bytes, total_size);
    mem_free(_bytes); _bytes = NULL;
  }

  *size = total_size;

 ksap23_gml_export_end:

  if (rc == IERROR) {
    if (_bytes) { mem_free(_bytes); _bytes = NULL; }
  }

  if (bentry) { mem_free(bentry); bentry = NULL; }
  
  return rc;

}

gml_t* ksap23_gml_import(byte_t *bytes, uint32_t size) {

  gml_t *gml;
  uint64_t i;
  uint32_t read;
  int entry_size;
  int rc;
  FILE *fd;
  
  if(!bytes || !size) {
    LOG_EINVAL(&logger, __FILE__, "ksap23_gml_import", __LINE__, LOGERROR);
    return NULL;
  }

  read = 0;
  gml = NULL;
  rc = IOK;

  if (!(gml = ksap23_gml_init())) GOTOENDRC(IERROR, ksap23_gml_import);

  /* Read the nubmer of entries to process */
  memcpy(&gml->n, bytes, sizeof(uint64_t));
  read += sizeof(uint64_t);

  if (!(gml->entries = mem_malloc(sizeof(gml_entry_t *)*gml->n)))
    GOTOENDRC(IERROR, ksap23_gml_import);

  /* Import the entries one by one */
  for (i=0; i<gml->n; i++) {

    if (!(gml->entries[i] = ksap23_gml_entry_import(&bytes[read], size-read)))
      GOTOENDRC(IERROR, ksap23_gml_import);

    if ((entry_size = ksap23_gml_entry_get_size(gml->entries[i])) == -1)
      GOTOENDRC(IERROR, ksap23_gml_import);

    read += entry_size;
    
  }

 ksap23_gml_import_end:
  
  if (rc == IERROR) {
    ksap23_gml_free(gml);
    gml = NULL;
  }
  
  return gml;
 
}

gml_entry_t* ksap23_gml_entry_init() {

  gml_entry_t *entry;

  if(!(entry = (gml_entry_t *) malloc(sizeof(gml_entry_t)))) {
    LOG_ERRORCODE(&logger, __FILE__, "ksap23_gml_entry_init", __LINE__,
		  errno, LOGERROR);
    return NULL;
  }

  entry->scheme = GROUPSIG_ksap23_CODE;
  entry->id = UINT64_MAX;
  entry->data = NULL;
  
  return entry;

}


int ksap23_gml_entry_free(gml_entry_t *entry) {

  ksap23_gml_entry_data_t *data;
  int rc;
  
  if(!entry) {
    LOG_EINVAL_MSG(&logger, __FILE__, "ksap23_gml_entry_free", __LINE__,
		   "Nothing to free.", LOGWARN);
    return IOK;
  }

  rc = IOK;
  data = (ksap23_gml_entry_data_t *) entry->data;

  if (data) {
    if (data->f1) { rc |= pbcext_element_G1_free(data->f1); data->f1 = NULL; }
    if (data->f2) { rc |= pbcext_element_G1_free(data->f2); data->f2 = NULL; }
    if (data->u)  { rc |= pbcext_element_G1_free(data->u);  data->u  = NULL; }
    if (data->w)  { rc |= pbcext_element_G1_free(data->w);  data->w  = NULL; }
    if (data->pi) { rc |= spk_rep_free(data->pi);           data->pi = NULL; }

    /*if (data->f1) { pbcext_element_G1_free(data->f1); data->f1 = NULL; }
    if (data->f2) { pbcext_element_G1_free(data->f2); data->f2 = NULL; }
    if (data->u) { pbcext_element_G1_free(data->u); data->u = NULL; }
    if (data->w) { pbcext_element_G1_free(data->w); data->w = NULL; }
    if (data->pi) { spk_rep_free(data->pi); data->pi = NULL; }*/


    /*if (data->f1) { rc = pbcext_element_G1_free(data->f1); data->f1 = NULL; }
    if (data->f2) { rc = pbcext_element_G1_free(data->f2); data->f2 = NULL; }
    if (data->u) { rc = pbcext_element_G1_free(data->u); data->u = NULL; }
    if (data->w) { rc = pbcext_element_G1_free(data->w); data->w = NULL; }
    if (data->pi) { rc = spk_rep_free(data->pi); data->pi = NULL; }*/
    
    mem_free(entry->data); entry->data = NULL;
  }
  
  mem_free(entry); //entry = NULL;

  if (rc) rc = IERROR;
  return rc;

}

int ksap23_gml_entry_get_size(gml_entry_t *entry) {

  uint64_t sf1, sf2, su, sw, ss, sc; //spi;
  
  if (!entry) {
    LOG_EINVAL(&logger, __FILE__, "ksap23_gml_entry_get_size", __LINE__, LOGERROR);
    return -1;
  }

  if (pbcext_element_G1_byte_size(&sf1) == -1)
    return -1;
  
  if (pbcext_element_G1_byte_size(&sf2) == -1)
    return -1;

  if (pbcext_element_G1_byte_size(&su) == -1)
    return -1;

  if (pbcext_element_G1_byte_size(&sw) == -1)
    return -1;  

  if (pbcext_element_Fr_byte_size(&ss) == -1)
    return -1;
    
  if (pbcext_element_Fr_byte_size(&sc) == -1)
    return -1;
  

  if (sf1 + sf2 + su + sw + ss + sc > INT_MAX) return -1;

  return (int) sf1 + sf2 + su + sw + ss + sc + sizeof(int)*6;
  
}

int ksap23_gml_entry_export(byte_t **bytes,
			    uint32_t *size,
			    gml_entry_t *entry) {

  ksap23_gml_entry_data_t *ksap23_data;
  byte_t *_bytes, *__bytes;
  uint64_t _size, len, offset;
  
  if (!bytes || !size || !entry) {
    LOG_EINVAL(&logger, __FILE__, "ksap23_gml_entry_export", __LINE__, LOGERROR);
    return IERROR;    
  }

  ksap23_data = (ksap23_gml_entry_data_t *) entry->data;  
  
  /* Calculate size */
  if ((_size = ksap23_gml_entry_get_size(entry)) == -1) return IERROR;
  _size += sizeof(int) + sizeof(uint64_t);
  
  if (!(_bytes = mem_malloc(sizeof(byte_t)*_size))) return IERROR;

  /* First, dump the identity */
  memcpy(_bytes, &entry->id, sizeof(uint64_t));
  offset = sizeof(uint64_t);

  /* Next, dump the data */
  __bytes = &_bytes[offset];
  if (pbcext_dump_element_G1_bytes(&__bytes, &len, ksap23_data->f1) == IERROR) {
    mem_free(_bytes); _bytes = NULL;
    return IERROR;
  }
  offset += len;

  __bytes = &_bytes[offset];  
  if (pbcext_dump_element_G1_bytes(&__bytes, &len, ksap23_data->f2) == IERROR) {
    mem_free(_bytes); _bytes = NULL;
    return IERROR;
  }
  offset += len;

  __bytes = &_bytes[offset];  
  if (pbcext_dump_element_G1_bytes(&__bytes, &len, ksap23_data->u) == IERROR) {
    mem_free(_bytes); _bytes = NULL;
    return IERROR;
  }
  offset += len;

  __bytes = &_bytes[offset];  
  if (pbcext_dump_element_G1_bytes(&__bytes, &len, ksap23_data->w) == IERROR) {
    mem_free(_bytes); _bytes = NULL;
    return IERROR;
  }
  offset += len;

  __bytes = &_bytes[offset];  
  if (spk_rep_export(&__bytes, &len, ksap23_data->pi) == IERROR) {
    mem_free(_bytes); _bytes = NULL;
    return IERROR;
  }

  /* Prepare exit */
  if (!*bytes) {
    *bytes = _bytes;
  } else {
    memcpy(*bytes, _bytes, _size);
    mem_free(_bytes); _bytes = NULL;
  }

  *size = _size;

  return IOK;
  
}

gml_entry_t* ksap23_gml_entry_import(byte_t *bytes, uint32_t size) {

  gml_entry_t *entry;
  ksap23_gml_entry_data_t *ksap23_data;
  uint64_t len, offset;
  FILE *fd;

  if (!bytes || !size) {
    LOG_EINVAL(&logger, __FILE__, "ksap23_gml_entry_import", __LINE__, LOGERROR);
    return NULL;    
  }

  if (!(entry = ksap23_gml_entry_init())) return NULL;

  /* First, read the identity */
  memcpy(&entry->id, bytes, sizeof(uint64_t));
  offset = sizeof(uint64_t);

  /* Next, read the data */

  if (!(entry->data = mem_malloc(sizeof(ksap23_gml_entry_data_t)))) {
    ksap23_gml_entry_free(entry); entry = NULL;
    return NULL;
  }

  ksap23_data = (ksap23_gml_entry_data_t *) entry->data;
  
  if(!(ksap23_data->f1 = pbcext_element_G1_init())) {
    ksap23_gml_entry_free(entry); entry = NULL;
    return NULL;
  }

  if (pbcext_get_element_G1_bytes(ksap23_data->f1,
				  &len,
				  &bytes[offset]) == IERROR) {
    ksap23_gml_entry_free(entry); entry = NULL;
    return NULL;    
  }

  if (!len) {
    ksap23_gml_entry_free(entry); entry = NULL;
    return NULL;    
  }

  offset += len;

  if(!(ksap23_data->f2 = pbcext_element_G1_init())) {
    ksap23_gml_entry_free(entry); entry = NULL;
    return NULL;
  }

  if (pbcext_get_element_G1_bytes(ksap23_data->f2,
				  &len,
				  &bytes[offset]) == IERROR) {
    ksap23_gml_entry_free(entry); entry = NULL;
    return NULL;    
  }

  if (!len) {
    ksap23_gml_entry_free(entry); entry = NULL;
    return NULL;    
  }

  offset += len;

  if(!(ksap23_data->u = pbcext_element_G1_init())) {
    ksap23_gml_entry_free(entry); entry = NULL;
    return NULL;
  }

  if (pbcext_get_element_G1_bytes(ksap23_data->u,
				  &len,
				  &bytes[offset]) == IERROR) {
    ksap23_gml_entry_free(entry); entry = NULL;
    return NULL;    
  }

  if (!len) {
    ksap23_gml_entry_free(entry); entry = NULL;
    return NULL;    
  }

  offset += len;

  if(!(ksap23_data->w = pbcext_element_G1_init())) {
    ksap23_gml_entry_free(entry); entry = NULL;
    return NULL;
  }

  if (pbcext_get_element_G1_bytes(ksap23_data->w,
				  &len,
				  &bytes[offset]) == IERROR) {
    ksap23_gml_entry_free(entry); entry = NULL;
    return NULL;    
  }

  if (!len) {
    ksap23_gml_entry_free(entry); entry = NULL;
    return NULL;    
  }

  offset += len;  

  if(!(ksap23_data->pi = spk_rep_init(1))) {
    ksap23_gml_entry_free(entry); entry = NULL;
    return NULL;
  }

  if (!(ksap23_data->pi->c = pbcext_element_Fr_init())) {
    ksap23_gml_entry_free(entry); entry = NULL;
    return NULL;
  }
  if (pbcext_get_element_Fr_bytes(ksap23_data->pi->c, &len, &bytes[offset]) == IERROR) {
    ksap23_gml_entry_free(entry); 
    return NULL;
  }
  offset += len;

  if (!(ksap23_data->pi->s[0] = pbcext_element_Fr_init())) {
    ksap23_gml_entry_free(entry); entry = NULL;
    return NULL;
  }
  if (pbcext_get_element_Fr_bytes(ksap23_data->pi->s[0], &len, &bytes[offset]) == IERROR) {
    ksap23_gml_entry_free(entry); 
    return NULL;
  }
  offset += len;

  /*if (spk_rep_import(ksap23_data->pi,
				  &len,
				  &bytes[offset]) == IERROR) {
    ksap23_gml_entry_free(entry); entry = NULL;
    return NULL;    
  }*/

  if (!len) {
    ksap23_gml_entry_free(entry); entry = NULL;
    return NULL;    
  }

  offset += len; 

  return entry;
  
}

char* ksap23_gml_entry_to_string(gml_entry_t *entry) {

  ksap23_gml_entry_data_t *ksap23_data;
  char *sf1, *sf2, *su, *sw, *sid, *sentry;
  uint64_t sf1_len, sf2_len, su_len, sw_len, sentry_len;
  int rc;

  if(!entry) {
    LOG_EINVAL(&logger, __FILE__, "ksap23_gml_entry_to_string", __LINE__, LOGERROR);
    return NULL;
  }

  rc = IOK;
  sf1 = sf2 = su = sw = sid = sentry = NULL;

  ksap23_data = (ksap23_gml_entry_data_t *) entry->data;

  /* A string representation of a GML entry will be: 
     <id>\t<f1>\t<f2>\t<u>\t<w> */

  /* Get the string representations of the entry's fields */
  if(!(sid = misc_uint642string(entry->id))) {
    return NULL;
  }

  sf1 = NULL;
  if(pbcext_element_G1_to_string(&sf1, &sf1_len, 16, ksap23_data->f1) == IERROR)
    GOTOENDRC(IERROR, ksap23_gml_entry_to_string);

  sf2 = NULL;
  if(pbcext_element_G1_to_string(&sf2, &sf2_len, 16, ksap23_data->f2) == IERROR)
    GOTOENDRC(IERROR, ksap23_gml_entry_to_string);    

  su = NULL;
  if(pbcext_element_G1_to_string(&su, &su_len, 16, ksap23_data->u) == IERROR)
    GOTOENDRC(IERROR, ksap23_gml_entry_to_string);   

  sw = NULL;
  if(pbcext_element_G1_to_string(&sw, &sw_len, 16, ksap23_data->w) == IERROR)
    GOTOENDRC(IERROR, ksap23_gml_entry_to_string);

  sentry_len = strlen(sid)+sf1_len+sf2_len+su_len+sw_len+5;

  if(!(sentry = (char *) mem_malloc(sizeof(char)*sentry_len))) {
    LOG_ERRORCODE(&logger, __FILE__, "ksap23_gml_entry_to_string",
		  __LINE__, errno, LOGERROR);
    GOTOENDRC(IERROR, ksap23_gml_entry_to_string);    
  }

  sprintf(sentry, "%s\t%s\t%s\t%s\t%s", sid, sf1, sf2, su, sw);

 ksap23_gml_entry_to_string_end:
  
  if (sid) { mem_free(sid); sid = NULL; }
  if (sf1) { mem_free(sf1); sf1 = NULL; }
  if (sf2) { mem_free(sf2); sf2 = NULL; }
  if (su) { mem_free(su); su = NULL; }
  if (sw) { mem_free(sw); sw = NULL;  }

  return sentry;
 
}

/* gml.c ends here */