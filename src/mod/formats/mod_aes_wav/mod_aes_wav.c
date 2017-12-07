/* 
 * FreeSWITCH Modular Media Switching Software Library / Soft-Switch Application
 * Copyright (C) 2005-2014, Anthony Minessale II <anthm@freeswitch.org>
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

#include "mod_aes_wav.h"

SWITCH_MODULE_LOAD_FUNCTION(mod_aes_wav_load);
SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_aes_wav_shutdown);
SWITCH_MODULE_DEFINITION(mod_aes_wav, mod_aes_wav_load, mod_aes_wav_shutdown, NULL);

mod_aes_wav_globals_t mod_aes_wav_globals;

static switch_status_t mod_aes_wav_cipher_init(mod_aes_wav_context_t *context, uint32_t offset /* in encrypted bytes */)
{
	unsigned char iv[EVP_MAX_IV_LENGTH] = {0};
	uint32_t *oiv_32 = (uint32_t *)context->iv;
	uint32_t *iv_32 = (uint32_t *) iv;

	if ( context->enc ) {
		BIO_pop(context->enc);
		BIO_free(context->enc);
		context->enc = NULL;
		context->ctx = NULL;
	}
	
	if ( context->noenc ) {
		if ( !context->io ) {
			context->io = context->raw;
		}
		BIO_seek(context->raw, offset);
		return SWITCH_STATUS_SUCCESS;
	}
	
	iv_32[0] = oiv_32[0];
	iv_32[1] = oiv_32[1];
	iv_32[2] = oiv_32[2];
	iv_32[3] = oiv_32[3];

	context->enc = BIO_new(BIO_f_cipher());
	BIO_get_cipher_ctx(context->enc, &context->ctx);

	if ( context->debug ) {
		BIO_set_callback(context->enc, BIO_debug_callback);
	}

	if ( offset ) {
		/* 'round' down the sample seeking so that it ends on a reasonable encrypted block */
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "offset[%u]\n", offset);
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "offset at boundry?[%u]\n", offset % 4096);
		offset &= (UINT64_MAX ^ 4095);
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "offset[%u]\n", offset);
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "offset at boundry?[%u]\n", offset % 4096);
	}

	BIO_seek(context->raw, 16 + offset);
	
	if ( offset ) {
		uint32_t iv_offset = offset * 16; /* TODO: This could pose an issue with max size and wrapping */

		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "SEEK iv32 work[%u %u %u %u]\n", iv_32[0], iv_32[1], iv_32[2], iv_32[3]);
		iv_32[3] += iv_offset;
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "SEEK iv32 work[%u %u %u %u]\n", iv_32[0], iv_32[1], iv_32[2], iv_32[3]);

		BIO_set_cipher(context->enc, context->cipher, context->key, iv, 0);
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "cipher init with offset[%u]\n", iv_offset);
	} else {
		BIO_set_cipher(context->enc, context->cipher, context->key, iv, 0);
	}

	BIO_push(context->enc, context->raw);
	context->io = context->enc;

	return SWITCH_STATUS_SUCCESS;
}

static void *SWITCH_THREAD_FUNC mod_aes_wav_read_buffer_thread(switch_thread_t *thread, void *obj)
{
	mod_aes_wav_context_t *context = obj;
	uint8_t buf[4096];
	int blen = sizeof(buf);

	/* Read from file, play to caller */
	while ( context->running ) {
		int rlen = 0, wlen_orig = 0, wlen = 0;
		rlen = BIO_read(context->io, buf, blen);

		if ( rlen ) {
			/* Have data from file */
			if ( rlen != blen ) {
				if ( BIO_eof(context->io) ) { /* No more audio*/
					context->running = 0;
					context->end_of_file = 1;
				} else {
					switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Tried to read[%d] got[%d]\n", rlen, blen);
				}
			}
		write:
			switch_mutex_lock(context->read_cond_mutex);
			//			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Write start wlen[%d] wlen_orig[%d] rlen[%d]\n", wlen, wlen_orig, rlen);
			switch_mutex_lock(context->audio_buffer_mutex);
			wlen = switch_buffer_write(context->audio_buffer, buf + wlen_orig, rlen - wlen_orig);
			//			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Write end   wlen[%d] wlen_orig[%d] rlen[%d]\n",
			//							  wlen, wlen_orig, rlen);
			switch_mutex_unlock(context->audio_buffer_mutex);

			switch_thread_cond_signal(context->write_cond);

			if ( !wlen ) {
				//				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Write thread blocked on full audio_buffer\n");
				switch_thread_cond_wait(context->read_cond, context->read_cond_mutex);
				switch_yield(10000);
				goto write;
			}
			
			switch_mutex_unlock(context->read_cond_mutex);
			//			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Wrote[%d] bytes\n", wlen);
		} else {
			if ( BIO_eof(context->io) ) {
				context->running = 0;
				context->end_of_file = 1;				
			}
		}
	}

	return NULL;
}

static switch_status_t mod_aes_wav_thread_start(mod_aes_wav_context_t *context)
{
	context->running = 1;
	switch_threadattr_create(&context->thd_attr, context->pool);
	switch_threadattr_detach_set(context->thd_attr, 1);
	switch_threadattr_stacksize_set(context->thd_attr, SWITCH_THREAD_STACKSIZE);
	switch_thread_create(&context->thread, context->thd_attr, mod_aes_wav_read_buffer_thread, context, context->pool);

	return SWITCH_STATUS_SUCCESS;
}

static switch_status_t mod_aes_wav_thread_stop(mod_aes_wav_context_t *context)
{
	switch_status_t status = SWITCH_STATUS_SUCCESS;

	if ( context->running ) {
		context->running = 0;
		switch_thread_cond_signal(context->read_cond);
	}
	switch_buffer_toss(context->audio_buffer, switch_buffer_len(context->audio_buffer));
	switch_thread_join(&status, context->thread);

	return status;
}

static switch_status_t mod_aes_wav_file_init(mod_aes_wav_context_t *context)
{
	switch_status_t status = SWITCH_STATUS_SUCCESS;

	/* Confirm permissions to open file. If playback, then read the first 16 bytes unencrypted, and check for salted. */
	if (switch_test_flag(context->handle, SWITCH_FILE_FLAG_READ)) {
		context->raw = BIO_new(BIO_s_file());

		if (BIO_read_filename(context->raw, context->path) <= 0 ) {
			status = SWITCH_STATUS_GENERR;
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to open the file\n");
			goto done;
		}
	} else if (switch_test_flag(context->handle, SWITCH_FILE_FLAG_WRITE)) {
		context->raw = BIO_new(BIO_s_file());

		if (BIO_write_filename(context->raw, context->path) <= 0 ) {
			status = SWITCH_STATUS_GENERR;
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to open the file\n");
			goto done;
		}
	} else {
		status = SWITCH_STATUS_GENERR;
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Unknown file open flags. Not read nor write.\n");
		goto done;
	}
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "File [%s] opened\n", context->path);

 done:
	return status;
}

static switch_status_t mod_aes_wav_open_process_params(mod_aes_wav_context_t *context)
{
	switch_status_t status = SWITCH_STATUS_SUCCESS;
	char *password = switch_event_get_header(context->params, "pass");
	char *salt = switch_event_get_header(context->params, "salt");
	char *noenc = switch_event_get_header(context->params, "noenc");
	char *iv = switch_event_get_header(context->params, "iv");
	char *key = switch_event_get_header(context->params, "key");
	char *debug = switch_event_get_header(context->params, "debug");

	/* TODO: possible future params:
	   
	   read_size
	   BIO_set_read_buffer_size(context->raw, 4096 * 16 * 16);
	 */

	if ( debug ) {
		context->debug = switch_true(debug);

		if ( context->raw ) {
			BIO_set_callback(context->raw, BIO_debug_callback);
		}
	}
	
	if ( noenc ) {
		context->noenc = 1;
		goto done;
	}
	/* If encryption is expected, then proceed to process the values */
	
	if ( password ) {
		/* We need a valid salt in order to generate key and iv from password */

		if ( iv || key ) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "If pass is provided, then you can not specify key nor iv.\n");
			status = SWITCH_STATUS_GENERR;
			goto done;
		}

		if (switch_test_flag(context->handle, SWITCH_FILE_FLAG_WRITE)) {
			char salt_prefix[16] = {0};
			if ( salt ) { /* user supplied salt */
				char *salt_bin = NULL;
				switch_status_t err = SWITCH_STATUS_SUCCESS;
				/* User passed us in a salt to use for the password. */
				err = switch_unescape_hex(&salt_bin, context->salt, 16, 0, NULL);
				free(salt_bin);

				if ( err != SWITCH_STATUS_SUCCESS ) {
					switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Salt was not valid hex characters\n");
					status = err;
					goto done;
				}
			} else { /* Generate a secure salt */
				if (RAND_bytes(context->salt, 8) < 0) {
					switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Salt generation failed\n");
					status = SWITCH_STATUS_GENERR;
					goto done;					
				}
			}

			memcpy(salt_prefix, "Salted__", 8);
			memcpy(salt_prefix + 8, context->salt, 8);

			/* TODO: add initial write error handling */
			BIO_write(context->raw, salt_prefix, 16);

		} else if (switch_test_flag(context->handle, SWITCH_FILE_FLAG_READ)) {
			char salt_prefix[16] = {0};

			if ( salt ) {
				char *salt_bin = NULL;
				switch_status_t err = SWITCH_STATUS_SUCCESS;
				/* User passed us in a salt to use for the password. */
				err = switch_unescape_hex(&salt_bin, context->salt, 16, 0, NULL);
				free(salt_bin);

				if ( err != SWITCH_STATUS_SUCCESS ) {
					switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Salt was not valid hex characters\n");
					status = err;
					goto done;
				}
			}
		
			BIO_read(context->raw, salt_prefix, sizeof(salt_prefix));

			if ( memcmp(salt_prefix, "Salted__", 8) ) {
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "File not salted. Rejecting. In AES CTR mode unsalted files are insecure.\n");
				status = SWITCH_STATUS_GENERR;
				goto done;
			}
	
			if ( salt && memcmp(salt_prefix + 8, context->salt, 8) ) {
				char *out_buf = NULL;
				size_t out_len = 0;

				switch_escape_hex(&out_buf, context->salt, 8, 0, &out_len);
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "The provided salt[%s] does not match what is in the file[%.*s]\n",
								  salt, (int)out_len, out_buf);
				switch_safe_free(out_buf);
				status = SWITCH_STATUS_GENERR;
				goto done;			
			} else {
				memcpy(context->salt, salt_prefix + 8, sizeof(context->salt));
			}
		}
			
		EVP_BytesToKey(context->cipher, context->digest, context->salt, (unsigned char *)password, strlen(password), 1, context->key, context->iv);
	}

	if ( iv ) {
		int iv_len = strlen(iv);
		char *iv_bin = NULL;
		switch_status_t err = SWITCH_STATUS_SUCCESS;

		if ( iv_len != ( 2 * EVP_CIPHER_iv_length(context->cipher)) ) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "aes iv of wrong length. Was[%d] should be [%d] written as hex values.\n",
							  iv_len, EVP_CIPHER_iv_length(context->cipher) * 2 );
			status = SWITCH_STATUS_GENERR;
			goto done;
		}
		err = switch_unescape_hex(&iv_bin, context->iv, 2 * EVP_CIPHER_iv_length(context->cipher), 0, NULL);
		free(iv_bin);

		if ( err != SWITCH_STATUS_SUCCESS ) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "IV was not valid hex characters\n");
			status = err;
			goto done;
		}
	}

	if ( key ) {
		switch_status_t err = SWITCH_STATUS_SUCCESS;
		int key_len = strlen(key);
		char *key_bin = NULL;

		if ( key_len != ( 2 * EVP_CIPHER_key_length(context->cipher)) ) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "aes key of wrong length. Was[%d] should be [%d] written as hex values\n",
							  key_len, EVP_CIPHER_key_length(context->cipher) * 2);
			status = SWITCH_STATUS_GENERR;
			goto done;
		}
		err = switch_unescape_hex(&key_bin, context->key, 2 * EVP_CIPHER_key_length(context->cipher), 0, NULL);
		free(key_bin);

		if ( err != SWITCH_STATUS_SUCCESS ) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "key was not valid hex characters\n");
			status = err;
			goto done;
		}
	}

	/* TODO: Validate that salt, key and iv are defined 
	   switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "param 'key', 'iv' and 'salt' is required\n");
	   status = SWITCH_STATUS_GENERR;
	   goto done;
	*/

	if ( context->debug ) {
		char *out_buf = NULL;

		switch_escape_hex(&out_buf, context->salt, sizeof(context->salt), 0, NULL);
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "salt[%s]\n", out_buf);
		switch_safe_free(out_buf);

		switch_escape_hex(&out_buf, context->key, EVP_CIPHER_key_length(context->cipher), 0, NULL);
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "key[%s]\n", out_buf);
		switch_safe_free(out_buf);
		
		switch_escape_hex(&out_buf, context->iv, EVP_CIPHER_iv_length(context->cipher), 0, NULL);
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "iv[%s]\n", out_buf);
		switch_safe_free(out_buf);
	}
	
 done:
	return status;
}

static switch_status_t mod_aes_wav_open(switch_file_handle_t *handle, const char *path_full)
{
	switch_status_t status = SWITCH_STATUS_SUCCESS;
	mod_aes_wav_context_t *context = NULL;
	char *path_dup = NULL;

	if ((context = switch_core_alloc(handle->memory_pool, sizeof(*context))) == 0) {
		status = SWITCH_STATUS_MEMERR;
		goto done;
	}

	context->pool = handle->memory_pool;
	context->debug = 0;
	context->cipher = EVP_aes_256_ctr();
	context->digest = EVP_sha256();
	context->raw = NULL;
	context->enc = NULL;
	context->io = NULL;
	context->end_of_file = 0;
	context->read_buf_len = 8;
	context->noenc = 0;
	switch_thread_cond_create(&context->read_cond, context->pool);
	switch_mutex_init(&context->audio_buffer_mutex, SWITCH_MUTEX_NESTED, context->pool);
	switch_mutex_init(&context->read_cond_mutex, SWITCH_MUTEX_NESTED, context->pool);
	switch_mutex_init(&context->write_cond_mutex, SWITCH_MUTEX_NESTED, context->pool);
	switch_thread_cond_create(&context->write_cond, context->pool);

	context->handle = handle;
	handle->pos = 0; 
	//	handle->pre_buffer_datalen = 8 * 1024;

	path_dup = switch_core_strdup(context->pool, path_full);
	switch_event_create_brackets(path_dup, '{', '}', ',', &context->params, &context->path, SWITCH_FALSE);
	
	if ( !context->params ) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Unable to process a file without pass in params\n");
		status = SWITCH_STATUS_GENERR;
		goto done;
	}

	/* TODO:
	   The order of operations here needs to be confirm we can open the file (for read or write).
	   If read, and salt not passed, then we HAVE to read the salt before trying to generate the password and IV.
	   Then deal with key and iv confirmation.
	   Then deal with wav file header.
	 */

	if ( (status = mod_aes_wav_file_init(context)) != SWITCH_STATUS_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to open file for io.\n");		
		goto done;
	}

	if ( (status = mod_aes_wav_open_process_params(context)) != SWITCH_STATUS_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to parse required io params.\n");
		goto done;
	}

	switch_buffer_create(context->pool, &(context->audio_buffer), context->read_buf_len * 1024);
	
	if (switch_test_flag(handle, SWITCH_FILE_FLAG_READ)) {
		char header[44];
		int16_t *header_16 = (int16_t *)header;
		int32_t *header_32 = (int32_t *)header;
		uint32_t file_size = 0, sample_rate = 0, data_size = 0, bytes_per_second = 0;
		uint16_t bits_per_sample = 0, format = 0, channels = 0;
		
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Attempting read of file.\n");

		mod_aes_wav_cipher_init(context, 0);

		BIO_read(context->io, header, 44);

		if ( memcmp(header, "RIFF", 4) || memcmp(header + 8, "WAVE", 4) || memcmp(header + 12, "fmt ", 4) || memcmp(header + 36, "data", 4)) {
			/* Not a valid decryption of a wav file */
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Decryption failed.\n");
			status = SWITCH_STATUS_GENERR;
			goto done;
		}

		file_size = header_32[1];
		sample_rate = header_32[6];
		bytes_per_second = header_32[7];
		data_size = header_32[10];

		format = header_16[10];
		channels = header_16[11];
		bits_per_sample = header_16[17];

		if ( context->debug ) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "SEEK file size[%d] format(1)[%d] channels[%d]\n",
							  file_size, format, channels);
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "SEEK sample_rate[%d] data_size[%d] bits_per_sample[%d] bytes_per_second[%d]\n",
							  sample_rate, data_size, bits_per_sample, bytes_per_second);
		}

		handle->seekable = 1;
		handle->samplerate = sample_rate;
		handle->channels = channels;
		handle->format = format;
		/*
		  handle->samples = 0;
		  handle->sections = 0;
		  handle->speed = 0;
		*/
		//handle->flags |= SWITCH_FILE_DATA_SHORT;
		//	handle->flags |= SWITCH_FILE_NATIVE;
		//handle->flags |= SWITCH_FILE_DATA_RAW;
		
	} else {
		char header[44] = {0};
		int16_t *header_16 = (int16_t *)header;
		int32_t *header_32 = (int32_t *)header;

		memcpy(header, "RIFF", 4);
		memcpy(header + 8, "WAVE", 4);
		memcpy(header + 12, "fmt ", 4);
		memcpy(header + 36, "data", 4);
		
	    header_32[4] = 16;
	    header_32[6] = handle->samplerate;
		header_32[7] = (handle->samplerate * handle->channels * 2); /* the times two is a simplified version of 16 bits to bytes */

		/* These will need to be filled in on file close */
		header_32[1] = 0; /* file size */
		header_32[10] = 0; /* data size */

		header_16[10] = handle->format;
		header_16[11] = handle->channels;
		header_16[16] = 2 * handle->channels;
		header_16[17] = 16;

		mod_aes_wav_cipher_init(context, 0);
		
		BIO_write(context->io, header, 44);		
	}

	handle->private_info = context;

	if (switch_test_flag(handle, SWITCH_FILE_FLAG_READ)) {
		mod_aes_wav_thread_start(context);
	}
	
 done:
 	return status;
}

static switch_status_t mod_aes_wav_read(switch_file_handle_t *handle, void *data, size_t *len)
{
	mod_aes_wav_context_t *context = handle->private_info;
	
	size_t bytes_per_sample = 2, bytes = *len * bytes_per_sample, rlen = 0;
 read:
	switch_mutex_lock(context->write_cond_mutex);
	switch_mutex_lock(context->audio_buffer_mutex);
	rlen = switch_buffer_read(context->audio_buffer, data, bytes);
	switch_mutex_unlock(context->audio_buffer_mutex);

	if ( rlen == 0 && !context->end_of_file ) {
		switch_thread_cond_wait(context->write_cond, context->write_cond_mutex);
		goto read;
	}
	switch_mutex_unlock(context->write_cond_mutex);

	*len = rlen / 2;
	switch_thread_cond_signal(context->read_cond);

	handle->pos += *len;
	
	return SWITCH_STATUS_SUCCESS;
}

static switch_status_t mod_aes_wav_truncate(switch_file_handle_t *handle, int64_t offset)
{
	mod_aes_wav_context_t *context = handle->private_info;
	(void) context;

	return SWITCH_STATUS_FALSE;
}

static switch_status_t mod_aes_wav_close(switch_file_handle_t *handle)
{
	mod_aes_wav_context_t *context = handle->private_info;

	if (switch_test_flag(handle, SWITCH_FILE_FLAG_WRITE)) {
		/* Finish writing data to file */
		BIO_flush(context->io);

		/* TODO: Update file sizes =>
		   
		   read 44 byte header
		   make the two changes
		   write 44 byte header
		 */
	}

	mod_aes_wav_thread_stop(context);

	/* TODO: properly cleanup all of the context bits */

	if ( context->params ) {
		switch_event_destroy(&context->params);
	}

	if ( context->enc ) {
		BIO_pop(context->enc);
		BIO_free(context->enc);
		context->enc = NULL;
		context->ctx = NULL;
	}

	if ( context->raw ) {
		BIO_free(context->raw);
		context->raw = NULL;
	}
	
	return SWITCH_STATUS_SUCCESS;
}

static switch_status_t mod_aes_wav_seek(switch_file_handle_t *handle, unsigned int *cur_sample, int64_t samples, int whence)
{
	mod_aes_wav_context_t *context = handle->private_info;

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "SEEK cur_sample[%u] samples[%ld] pos[%ld] whence[%d] in[%d] enc[%d], 2*samples[%ld]\n",
					  *cur_sample, samples, handle->pos, whence, BIO_tell(context->raw), BIO_tell(context->enc), samples * 2);

	switch_mutex_lock(context->audio_buffer_mutex);

	mod_aes_wav_cipher_init(context, samples * 2);
	context->handle->pos = samples;
	
	switch_mutex_unlock(context->audio_buffer_mutex);

	return SWITCH_STATUS_SUCCESS;
}

static switch_status_t mod_aes_wav_write(switch_file_handle_t *handle, void *data, size_t *len)
{
	mod_aes_wav_context_t *context = handle->private_info;
	int wlen = 0;

	wlen = BIO_write(context->io, data, *len * 2);

	*len = wlen / 2;
	handle->pos += *len;

	return SWITCH_STATUS_SUCCESS;
}

static switch_status_t mod_aes_wav_do_config()
{
	return SWITCH_STATUS_SUCCESS;
}

static char *supported_formats[2] = { 0 };

SWITCH_MODULE_LOAD_FUNCTION(mod_aes_wav_load)
{
	switch_file_interface_t *file_interface;

	supported_formats[0] = (char *)"aes_wav";

	if (mod_aes_wav_do_config() != SWITCH_STATUS_SUCCESS) {
		return SWITCH_STATUS_FALSE;
	}

	*module_interface = switch_loadable_module_create_module_interface(pool, modname);
	file_interface = switch_loadable_module_create_interface(*module_interface, SWITCH_FILE_INTERFACE);
	file_interface->interface_name = modname;
	file_interface->extens = supported_formats;
	file_interface->file_open = mod_aes_wav_open;
	file_interface->file_close = mod_aes_wav_close;
	file_interface->file_truncate = mod_aes_wav_truncate;
	file_interface->file_read = mod_aes_wav_read;
	file_interface->file_write = mod_aes_wav_write;
	file_interface->file_seek = mod_aes_wav_seek;

	return SWITCH_STATUS_SUCCESS;
}

SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_aes_wav_shutdown)
{
	return SWITCH_STATUS_SUCCESS;
}

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
