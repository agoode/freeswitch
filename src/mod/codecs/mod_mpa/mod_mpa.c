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
 * Contributor(s):
 *
 * Brian K. West <brian@freeswitch.org>
 * Noel Morgan <noel@vwci.com>
 * Christian Hoene <christian.hoene@symonics.com>
 *
 * mod_mpa.c -- The MPEG1/2/3 audio codec
 *
 */

/* https://tools.ietf.org/html/rfc3551#page-28

4.5.13 MPA

   MPA denotes MPEG-1 or MPEG-2 audio encapsulated as elementary
   streams.  The encoding is defined in ISO standards ISO/IEC 11172-3
   and 13818-3.  The encapsulation is specified in RFC 2250 [14].

   The encoding may be at any of three levels of complexity, called
   Layer I, II and III.  The selected layer as well as the sampling rate
   and channel count are indicated in the payload.  The RTP timestamp
   clock rate is always 90,000, independent of the sampling rate.
   MPEG-1 audio supports sampling rates of 32, 44.1, and 48 kHz (ISO/IEC
   11172-3, section 1.1; "Scope").  MPEG-2 supports sampling rates of
   16, 22.05 and 24 kHz.  The number of samples per frame is fixed, but
   the frame size will vary with the sampling rate and bit rate.

   The MIME registration for MPA in RFC 3555 [7] specifies parameters
   that MAY be used with MIME or SDP to restrict the selection of layer,
   channel count, sampling rate, and bit rate.
*/

/* https://tools.ietf.org/html/rfc3555

4.1.17. Registration of MIME media type audio/MPA

   MIME media type name: audio

   MIME subtype name: MPA (MPEG audio)

   Required parameters: None

   Optional parameters:
        layer: which layer of MPEG audio encoding; permissible values
        are 1, 2, 3.

        samplerate: the rate at which audio is sampled.  MPEG-1 audio
        supports sampling rates of 32, 44.1, and 48 kHz; MPEG-2
        supports sampling rates of 16, 22.05 and 24 kHz.  This parameter
        is separate from the RTP timestamp clock rate which is always
        90000 Hz for MPA.

        mode: permissible values are "stereo", "joint_stereo",
        "single_channel", "dual_channel".  The "channels" parameter
        does not apply to MPA.  It is undefined to put a number of
        channels in the SDP rtpmap attribute for MPA.

        bitrate: the data rate for the audio bit stream.

        ptime: RECOMMENDED duration of each packet in milliseconds.

        maxptime: maximum duration of each packet in milliseconds.

        Parameters which are omitted are left to the encoder to choose
        based on the session bandwidth, configuration information, or
        other constraints.  The selected layer as well as the sampling
        rate and mode are indicated in the payload so receivers can
        process the data without these parameters being specified
        externally.
*/


#include "switch.h"
#include <twolame.h>
#include <mpg123.h>

//#define DEBUG

SWITCH_MODULE_LOAD_FUNCTION(mod_mpa_load);
SWITCH_MODULE_DEFINITION(mod_mpa, mod_mpa_load, NULL, NULL);

/*! \brief Various codec settings */
struct mpa_codec_settings {
	int layer;
	int samplerate;
	int actual_samplerate;
	TWOLAME_MPEG_mode mode;
	int bitrate;
	int ptime;
	int maxptime;
};

typedef struct mpa_codec_settings mpa_codec_settings_t;

static mpa_codec_settings_t default_codec_settings = {
	/*.layer */ 2,
	/*.samplerate */ 48000,
	/*.mode */ TWOLAME_STEREO,
	/*.bitrate */ 128000,
	/*.ptime*/ 0,
	/*.maxptime*/ 0
};

struct mpa_context {
	twolame_options *encoder;
	mpg123_handle *decoder;
	int decode_channels;
};

static int mpa_samplerates[] = { 22050, 24000, 32000, 44100, 48000 };

static switch_codec_interface_t *codec_interface;

static switch_status_t switch_mpa_fmtp_parse(const char *fmtp, switch_codec_fmtp_t *codec_fmtp)
{
#ifdef DEBUG
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "MPA parse %s - %p\n",fmtp,(void*)codec_fmtp);
#endif
	if (codec_fmtp) {
		mpa_codec_settings_t local_settings = default_codec_settings;
		mpa_codec_settings_t *codec_settings = &local_settings;
        
		if (codec_fmtp->private_info) {
			codec_settings = codec_fmtp->private_info;
			if (zstr(fmtp)) {
				memcpy(codec_settings, &default_codec_settings, sizeof(*codec_settings));
			}
		}
        
		if (fmtp && codec_settings) {
			int x, argc;
			char *argv[10];
			char *fmtp_dup = strdup(fmtp);
            
			switch_assert(fmtp_dup);
            
			argc = switch_separate_string(fmtp_dup, ';', argv, (sizeof(argv) / sizeof(argv[0])));
			for (x = 0; x < argc; x++) {
				char *data = argv[x];
				char *arg;
				switch_assert(data);
				while (*data == ' ') {
					data++;
				}
				
                
				if ((arg = strchr(data, '='))) {
					*arg++ = '\0';
#ifdef DEBUG
					switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Argument %s %s\n",data,arg);
#endif                    
					if (!strcasecmp(data, "layer")) {
						codec_settings->layer = atoi(arg);
						if ( codec_settings->layer < 1 || codec_settings->layer > 3 ) {
							codec_settings->layer = 0; 
						}
	
					}
                        
					if (!strcasecmp(data, "samplerate")) {
						int r, rate = atoi(arg);
						codec_settings->samplerate = 0;
						for (r = 0; r < sizeof(mpa_samplerates) / sizeof(mpa_samplerates[0]); r++) {
							if (rate == mpa_samplerates[r]) {
								codec_settings->samplerate = rate;
								break;
							}
						}
//						codec_fmtp->actual_samples_per_second = codec_settings->samplerate;
					}
                        
					if (!strcasecmp(data, "mode")) {
						if (!strcasecmp(arg,"stereo")) {
							codec_settings->mode = TWOLAME_STEREO;
						} else if (!strcasecmp(arg,"joint_stereo")) {
							codec_settings->mode = TWOLAME_JOINT_STEREO;
						} else if (!strcasecmp(arg,"single_channel")) {
							codec_settings->mode = TWOLAME_MONO;
						} else if (!strcasecmp(arg,"dual_channel")) {
							codec_settings->mode = TWOLAME_DUAL_CHANNEL;
						} else {
							codec_settings->mode = TWOLAME_AUTO_MODE;
						}
					}

					if (!strcasecmp(data, "bitrate")) {
						codec_settings->bitrate = atoi(arg);
						if ( codec_settings->bitrate < 6000 || codec_settings->bitrate > 510000 ) {
							codec_settings->bitrate = 0; 
						}
					}                       
				}
			}
			free(fmtp_dup);
		}
		codec_fmtp->stereo = TRUE;
		return SWITCH_STATUS_SUCCESS;
	}
	return SWITCH_STATUS_FALSE;
}

static char *gen_fmtp(mpa_codec_settings_t *settings, switch_memory_pool_t *pool)
{
	char *p;
	switch_stream_handle_t stream = { 0 };

	SWITCH_STANDARD_STREAM(stream);

	if (settings->layer) {
		stream.write_function(&stream, "layer=%d; ",settings->layer);
	}
    
	if (settings->samplerate) {
		stream.write_function(&stream, "samplerate=%d; ",settings->samplerate);
	}
    
	if (settings->mode==TWOLAME_STEREO) {
		stream.write_function(&stream, "mode=stereo; ");
	}
	if (settings->mode==TWOLAME_JOINT_STEREO) {
		stream.write_function(&stream, "mode=joint_stereo; ");
	}
	if (settings->mode==TWOLAME_MONO) {
		stream.write_function(&stream, "mode=single_channel; ");
	}
	if (settings->mode==TWOLAME_DUAL_CHANNEL) {
		stream.write_function(&stream, "mode=dual_channel; ");
	}
	if (settings->bitrate) {
		stream.write_function(&stream, "bitrate=%d; ", settings->bitrate);
	}
	if (settings->ptime) {
		stream.write_function(&stream, "ptime=%d; ", settings->ptime);
	}
	if (settings->maxptime) {
		stream.write_function(&stream, "maxptime=%d; ", settings->maxptime);
	}
    
	p = switch_core_strdup(pool, stream.data);

	if (end_of(p) == ' ') {
		*(end_of_p(p) - 1) = '\0';
	}
	
#ifdef DEBUG
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "MPA gen fmtp %s==%s\n",(char*)stream.data,p);
#endif
	free(stream.data);
	return p;
}

static switch_status_t switch_mpa_init(switch_codec_t *codec, switch_codec_flag_t flags, const switch_codec_settings_t *codec_settings)
{
	int result;
	struct mpa_context *context = NULL;
	int encoding = (flags & SWITCH_CODEC_FLAG_ENCODE);
	int decoding = (flags & SWITCH_CODEC_FLAG_DECODE);
	int channels;
	const switch_codec_implementation_t *iptr;

	switch_codec_fmtp_t codec_fmtp;
	mpa_codec_settings_t mpa_codec_settings = default_codec_settings;

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "MPA init start %04X\n",flags);
    
	if (!(encoding || decoding) || (!(context = switch_core_alloc(codec->memory_pool, sizeof(*context))))) {
		return SWITCH_STATUS_FALSE;
	}
    
	memset(&codec_fmtp, '\0', sizeof(struct switch_codec_fmtp));
	codec_fmtp.private_info = &mpa_codec_settings;
	switch_mpa_fmtp_parse(codec->fmtp_in, &codec_fmtp);

	codec->fmtp_out = gen_fmtp(&mpa_codec_settings, codec->memory_pool);

	channels = mpa_codec_settings.mode == TWOLAME_MONO ? 1 : 2;

#ifdef DEBUG
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "MPA init %s %s\n",codec->fmtp_in,codec->fmtp_out);
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "MPA init parameters %d/%d %d\n",mpa_codec_settings.samplerate,channels,mpa_codec_settings.bitrate
);
#endif

	if (encoding) {

		context->encoder = twolame_init();
		if (!context->encoder) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "MPA enc cannot init");
			return SWITCH_STATUS_FALSE;
		}
#ifdef DEBUG
		result = twolame_set_verbosity(context->encoder, 5);
#endif

		result |= twolame_set_out_samplerate(context->encoder, mpa_codec_settings.samplerate);
		result |= twolame_set_version(context->encoder, mpa_codec_settings.samplerate<32000?TWOLAME_MPEG2:TWOLAME_MPEG1);
		result |= twolame_set_bitrate(context->encoder, mpa_codec_settings.bitrate/1000);
		result |= twolame_set_mode(context->encoder, mpa_codec_settings.mode);
		result |= twolame_set_in_samplerate(context->encoder, mpa_codec_settings.samplerate);
		result |= twolame_set_num_channels(context->encoder, channels);

		if (result!=0) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "MPA enc Failed setting parameters\n");
			return SWITCH_STATUS_FALSE;
		}

		if (mpa_codec_settings.layer != 2) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "MPA enc Only layer 2 is supported, not %d.\n",mpa_codec_settings.layer);
			return SWITCH_STATUS_FALSE;
		}

		if (twolame_init_params(context->encoder)) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "MPA enc Failed init parameters\n");
			return SWITCH_STATUS_FALSE;
		}	
	}

	if (decoding) {
		context->decoder = mpg123_new(NULL,&result);
		context->decode_channels = channels;
		if (!context->decoder) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "MPA dec Failed init parameters %s\n",
				mpg123_plain_strerror(result));
			return SWITCH_STATUS_FALSE;
		}

#ifdef DEBUG
		result = mpg123_param(context->decoder, MPG123_VERBOSE, 4, 4.);
		if (result != MPG123_OK) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "MPA dec Param error %s",
			mpg123_plain_strerror(result));
			return SWITCH_STATUS_FALSE;
		}
#endif
	
		result = mpg123_format_all(context->decoder);
		if (result != MPG123_OK) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "MPA dec Format error %s",
				mpg123_plain_strerror(result));
				return SWITCH_STATUS_FALSE;
		}

		result = mpg123_open_feed(context->decoder);
		if (result != MPG123_OK) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "MPA dec Open feed error %s",
				mpg123_plain_strerror(result));
			return SWITCH_STATUS_FALSE;
		}
	}
	
	/* find proper codec implementation */
	for (iptr = codec_interface->implementations; iptr; iptr = iptr->next) {
			if (mpa_codec_settings.samplerate == iptr->actual_samples_per_second && channels == iptr->number_of_channels) {
				codec->implementation = iptr;				
				break;
			}
	}

	codec->private_info = context;
#ifdef DEBUG
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "MPA init found %d/%d %dus\n",codec->implementation->actual_samples_per_second,
		codec->implementation->number_of_channels,codec->implementation->microseconds_per_packet);
#endif
	return SWITCH_STATUS_SUCCESS;
}

static switch_status_t switch_mpa_destroy(switch_codec_t *codec)
{
	struct mpa_context *context = codec->private_info;
    
	if (context) {
		if (context->decoder) {
			mpg123_close(context->decoder);
			mpg123_delete(context->decoder);
		}
		if (context->encoder) {
			twolame_close(&context->encoder);
		}
	}
    
	codec->private_info = NULL;
	return SWITCH_STATUS_SUCCESS;
}

static switch_status_t switch_mpa_encode(switch_codec_t *codec,
										  switch_codec_t *other_codec,
										  void *decoded_data,
										  uint32_t decoded_data_len,
										  uint32_t decoded_rate, void *encoded_data, uint32_t *encoded_data_len, uint32_t *encoded_rate,
										  unsigned int *flag)
{
	struct mpa_context *context = codec->private_info;
	int n;

#ifdef DEBUG
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "MPA enc start %d to %d at rates %d to %d and channels %d to %d\n", 
			decoded_data_len, *encoded_data_len, 
			decoded_rate, *encoded_rate, 
			 codec->implementation->number_of_channels, other_codec->implementation->number_of_channels);
#endif
	if (!context) {
		return SWITCH_STATUS_FALSE;
	}

	/* check if enough samples are available */
	if (decoded_data_len / 2 != TWOLAME_SAMPLES_PER_FRAME * codec->implementation->number_of_channels) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "MPA enc input buffer wrong %d %d\n",decoded_data_len,
			codec->implementation->number_of_channels);
		return SWITCH_STATUS_FALSE;
	}

	/* encode MP2 frame */
	n = twolame_encode_buffer_interleaved(context->encoder, decoded_data, TWOLAME_SAMPLES_PER_FRAME, 
				(unsigned char*)encoded_data+4, (*encoded_data_len)-4);
#ifdef DEBUG
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "MPA enc done %d\n", n);
#endif
	if (n<=0) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "MPA enc failed\n");
		return SWITCH_STATUS_FALSE;
	}
	*(uint32_t*)(encoded_data) = 0;
	*encoded_data_len = n+4;

	return SWITCH_STATUS_SUCCESS;
}

static switch_status_t switch_mpa_decode(switch_codec_t *codec,
										  switch_codec_t *other_codec,
										  void *encoded_data,
										  uint32_t encoded_data_len,
										  uint32_t encoded_rate, void *decoded_data, uint32_t *decoded_data_len, uint32_t *decoded_rate,
										  unsigned int *flag)
{
	struct mpa_context *context = codec->private_info;
	int result, channels, encoding;
	long samplerate;
	size_t n=0;

#ifdef DEBUG
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "MPA dec start %d to %d channels %d via %d to %d rate %d to %d flags %d\n", 
		encoded_data_len, *decoded_data_len, 
		other_codec->implementation->number_of_channels,context->decode_channels,other_codec->implementation->number_of_channels,
		encoded_rate, *decoded_rate,
		*flag);
#endif
	if (!context) {
		return SWITCH_STATUS_FALSE;
	}
	
	if (encoded_data_len >= 4 && !(*flag & SFF_PLC) ) {
		if (*(uint32_t*)encoded_data != 0) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "MPA dec, header is not zero %08X, not supported yet\n",
				*(uint32_t*)encoded_data);
			return SWITCH_STATUS_FALSE;
		}
		if(*decoded_data_len < TWOLAME_SAMPLES_PER_FRAME * 2 * 2) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "MPA dec, output buffer to small\n");
			return SWITCH_STATUS_FALSE;
		}
		result = mpg123_decode(context->decoder, ((unsigned char*)encoded_data)+4, encoded_data_len-4,
				(unsigned char*)decoded_data, TWOLAME_SAMPLES_PER_FRAME * 2 * context->decode_channels, &n);
#ifdef DEBUG
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "MPA dec result %d %ld channels %d/%d\n", result, n, 
			other_codec->implementation->number_of_channels,other_codec->implementation->number_of_channels);
#endif

		if (result == MPG123_NEW_FORMAT) {
			mpg123_getformat(context->decoder, &samplerate, &channels, &encoding);
			context->decode_channels = channels;
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "MPA dec format change %ld %d %04X\n",
					samplerate,channels,encoding);
		}
		if (result == MPG123_NEED_MORE || result == MPG123_NEW_FORMAT || n==0) {
			bzero(decoded_data,TWOLAME_SAMPLES_PER_FRAME * 2 * other_codec->implementation->number_of_channels );
			*decoded_data_len=TWOLAME_SAMPLES_PER_FRAME * 2 * other_codec->implementation->number_of_channels;
			return SWITCH_STATUS_SUCCESS;
		}
		else if (result != MPG123_OK) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "MPA dec feed error %d %s\n", result,
			mpg123_plain_strerror(result));
			return SWITCH_STATUS_FALSE;
		}
		else {
			*decoded_data_len=TWOLAME_SAMPLES_PER_FRAME * 2 * context->decode_channels; // context->decode_channels; //other_codec->implementation->number_of_channels; 
		}
	}
	else {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "MPA dec packet loss\n");
	}

	return SWITCH_STATUS_SUCCESS;
}

SWITCH_MODULE_LOAD_FUNCTION(mod_mpa_load)
{
	int r, x,res;

	*module_interface = switch_loadable_module_create_module_interface(pool, modname);
    
	/* init decoder library */
	res = mpg123_init();
	if (res != MPG123_OK) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "MPA libmpg123 init error %s",
			mpg123_plain_strerror(res));
		return SWITCH_STATUS_FALSE;
	}


	SWITCH_ADD_CODEC(codec_interface, "MPA (STANDARD)");
    
	codec_interface->parse_fmtp = switch_mpa_fmtp_parse;
#if 0 
	for (x = 1; x < 3; x++) {
			switch_core_codec_add_implementation(pool, codec_interface, SWITCH_CODEC_TYPE_AUDIO,	/* enumeration defining the type of the codec */
											 14,	/* the IANA code number */
											 "MPA", /* the IANA code name */
											 NULL,	/* default fmtp to send (can be overridden by the init function) */
											 90000,	/* samples transferred per second */
											 48000,	/* actual samples transferred per second */
											 384000,		/* bits transferred per second */
											 0,		/* number of microseconds per frame */
											 480,	/* number of samples per frame */
											 480 * 2 * x,	/* number of bytes per frame decompressed */
											 0,		/* number of bytes per frame compressed */
											 x, /* number of channels represented */
											 1,	/* number of frames per network packet */
											 switch_mpa_init,	/* function to initialize a codec handle using this implementation */
											 switch_mpa_encode,	/* function to encode raw data into encoded data */
											 switch_mpa_decode,	/* function to decode encoded data into raw data */
											 switch_mpa_destroy);	/* deinitalize a codec handle using this implementation */
		
	}
#endif
 
	for (r = 0; r < sizeof(mpa_samplerates) / sizeof(mpa_samplerates[0]); r++) {
		for (x = 1; x < 3; x++) {
			char string[128];
			snprintf(string,sizeof(string),"layer2; bitrate=128000; mode=%s; samplerate=%d", x==2?"stereo":"single_channel", mpa_samplerates[r]);
			switch_core_codec_add_implementation(pool, codec_interface, SWITCH_CODEC_TYPE_AUDIO,	/* enumeration defining the type of the codec */
											 14,	/* the IANA code number */
											 "MPA", /* the IANA code name */
											 string,	/* default fmtp to send (can be overridden by the init function) */
											 90000,	/* samples transferred per second */
											 mpa_samplerates[r],	/* actual samples transferred per second */
											 0,		/* bits transferred per second */
											 TWOLAME_SAMPLES_PER_FRAME * 1000000LL / mpa_samplerates[r],		/* number of microseconds per frame */
											 TWOLAME_SAMPLES_PER_FRAME * 90000 / mpa_samplerates[r],	/* number of samples per frame */
											 TWOLAME_SAMPLES_PER_FRAME * 2 * x,	/* number of bytes per frame decompressed */
											 0,		/* number of bytes per frame compressed */
											 x, /* number of channels represented */
											 1,	/* number of frames per network packet */
											 switch_mpa_init,	/* function to initialize a codec handle using this implementation */
											 switch_mpa_encode,	/* function to encode raw data into encoded data */
											 switch_mpa_decode,	/* function to decode encoded data into raw data */
											 switch_mpa_destroy);	/* deinitalize a codec handle using this implementation */
		
		}
	}
	/* indicate that the module should continue to be loaded */
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
 * vim:set softtabstop=4 shiftwidth=4 tabstop=4 noet:
 */
