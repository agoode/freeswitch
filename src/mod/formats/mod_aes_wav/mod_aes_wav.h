/*
* FreeSWITCH Modular Media Switching Software Library / Soft-Switch Application
* Copyright (C) 2005-2012, Anthony Minessale II <anthm@freeswitch.org>
*
* Version: MPL 1.1
*
* The contents of this file are subject to the Mozilla Public License Version
* 1.1 (the "License"); you may not use this file except in compliance with
* the License. You may obtain a copy of the License at
* http://www.mozilla.org/MPL/
*
* Software distributed under the License is distributed on an "AS IS" basis,
* WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
* for the specific language governing rights and limitations under the
* License.
*
* The Original Code is FreeSWITCH Modular Media Switching Software Library / Soft-Switch Application
*
* The Initial Developer of the Original Code is
* Anthony Minessale II <anthm@freeswitch.org>
* Portions created by the Initial Developer are Copyright (C)
* the Initial Developer. All Rights Reserved.
*
* William King <william.king@quentustech.com>
*
* mod_aed_ctr_wav -- Read and write from encrypted wav files.
*
*/

#ifndef MOD_AES_CTR_WAV_H
#define MOD_AES_CTR_WAV_H

#include <switch.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

typedef struct mod_aes_wav_context_s {
	switch_memory_pool_t *pool;
	int debug;
	BIO *raw;
	BIO	*enc;
	BIO *io;
	switch_buffer_t *audio_buffer;
	switch_mutex_t *audio_buffer_mutex;
	switch_file_handle_t *handle;
	uint8_t buf[4096];
	switch_thread_t *thread;
	switch_threadattr_t *thd_attr;
	int running;
	int end_of_file;
	int noenc;
	switch_thread_cond_t *read_cond;
	switch_mutex_t *read_cond_mutex;
	switch_thread_cond_t *write_cond;
	switch_mutex_t *write_cond_mutex;
	int read_buf_len; /* In KB */
	
	EVP_CIPHER_CTX *ctx;
	const EVP_CIPHER *cipher;
	const EVP_MD *digest;

	switch_event_t *params;
	char *path;
	unsigned char key[EVP_MAX_KEY_LENGTH];
	unsigned char iv[EVP_MAX_IV_LENGTH];
	unsigned char salt[PKCS5_SALT_LEN];
} mod_aes_wav_context_t;

typedef struct mod_aes_wav_globals_s {
  switch_memory_pool_t *pool;
} mod_aes_wav_globals_t;

extern mod_aes_wav_globals_t mod_aes_ctr_wav_globals;

#endif /* MOD_AES_CTR_WAV_H */

/* For Emacs:
 * Local Variables:
 * mode:c
 * indent-tabs-mode:t
 * tab-width:4
 * c-basic-offset:4
 * End:
 * For VIM:
 * vim:set softtabstop=4 shiftwidth=4 tabstop=4
 */
