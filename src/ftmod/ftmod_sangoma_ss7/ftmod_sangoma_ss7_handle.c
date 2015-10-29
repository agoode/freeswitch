/*
 * Copyright (c) 2009 Konrad Hammel <konrad@sangoma.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms|with or without
 * modification|are permitted provided that the following conditions
 * are met:
 *
 * * Redistributions of source code must retain the above copyright
 * notice|this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright
 * notice|this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * * Neither the name of the original author; nor the names of any contributors
 * may be used to endorse or promote products derived from this software
 * without specific prior written permission.
 *
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES|INCLUDING|BUT NOT
 * LIMITED TO|THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER
 * OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT|INDIRECT|INCIDENTAL|SPECIAL,
 * EXEMPLARY|OR CONSEQUENTIAL DAMAGES (INCLUDING|BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE|DATA|OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY|WHETHER IN CONTRACT|STRICT LIABILITY|OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE|EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Contributors: 
 *
 * Ricardo Barroetaveña <rbarroetavena@anura.com.ar>
 * James Zhang <jzhang@sangoma.com>
 * Kapil Gupta <kgupta@sangoma.com>
 * Pushkar Singh <psingh@sangoma.com>
 *
 */

/* INCLUDE ********************************************************************/
#include "ftmod_sangoma_ss7_main.h"

/******************************************************************************/

/* DEFINES ********************************************************************/
/******************************************************************************/

/* GLOBALS ********************************************************************/

/******************************************************************************/

/* PROTOTYPES *****************************************************************/
ftdm_status_t handle_con_ind(uint32_t suInstId, uint32_t spInstId, uint32_t circuit, SiConEvnt *siConEvnt);
ftdm_status_t handle_con_sta(uint32_t suInstId, uint32_t spInstId, uint32_t circuit, SiCnStEvnt *siCnStEvnt, uint8_t evntType);
ftdm_status_t handle_con_cfm(uint32_t suInstId, uint32_t spInstId, uint32_t circuit, SiConEvnt *siConEvnt);
ftdm_status_t handle_rel_ind(uint32_t suInstId, uint32_t spInstId, uint32_t circuit, SiRelEvnt *siRelEvnt);
ftdm_status_t handle_peer_rel_ind(uint32_t suInstId, uint32_t spInstId, uint32_t circuit, SiRelEvnt *siRelEvnt);

ftdm_status_t handle_rel_cfm(uint32_t suInstId, uint32_t spInstId, uint32_t circuit, SiRelEvnt *siRelEvnt);
ftdm_status_t handle_dat_ind(uint32_t suInstId, uint32_t spInstId, uint32_t circuit, SiInfoEvnt *siInfoEvnt);
ftdm_status_t handle_fac_ind(uint32_t suInstId, uint32_t spInstId, uint32_t circuit, uint8_t evntType, SiFacEvnt *siFacEvnt);
ftdm_status_t handle_fac_cfm(uint32_t suInstId, uint32_t spInstId, uint32_t circuit, uint8_t evntType, SiFacEvnt *siFacEvnt);
ftdm_status_t handle_umsg_ind(uint32_t suInstId, uint32_t spInstId, uint32_t circuit);
ftdm_status_t handle_susp_ind(uint32_t suInstId, uint32_t spInstId, uint32_t circuit, SiSuspEvnt *siSuspEvnt);
ftdm_status_t handle_resm_ind(uint32_t suInstId, uint32_t spInstId, uint32_t circuit, SiResmEvnt *siResmEvnt);
ftdm_status_t handle_sta_ind(uint32_t suInstId, uint32_t spInstId, uint32_t circuit, uint8_t globalFlg, uint8_t evntType, SiStaEvnt *siStaEvnt);

ftdm_status_t handle_reattempt(uint32_t suInstId, uint32_t spInstId, uint32_t circuit, uint8_t globalFlg, uint8_t evntType, SiStaEvnt *siStaEvnt);
ftdm_status_t handle_pause(uint32_t suInstId, uint32_t spInstId, uint32_t circuit, uint8_t globalFlg, uint8_t evntType, SiStaEvnt *siStaEvnt);
ftdm_status_t handle_resume(uint32_t suInstId, uint32_t spInstId, uint32_t circuit, uint8_t globalFlg, uint8_t evntType, SiStaEvnt *siStaEvnt);
ftdm_status_t handle_cot_start(uint32_t suInstId, uint32_t spInstId, uint32_t circuit, uint8_t globalFlg, uint8_t evntType, SiStaEvnt *siStaEvnt);
ftdm_status_t handle_cot_stop(uint32_t suInstId, uint32_t spInstId, uint32_t circuit, uint8_t globalFlg, uint8_t evntType, SiStaEvnt *siStaEvnt);
ftdm_status_t handle_cot(uint32_t suInstId, uint32_t spInstId, uint32_t circuit, uint8_t globalFlg, uint8_t evntType, SiStaEvnt *siStaEvnt);
ftdm_status_t handle_rsc_req(uint32_t suInstId, uint32_t spInstId, uint32_t circuit, uint8_t globalFlg, uint8_t evntType, SiStaEvnt *siStaEvnt);
ftdm_status_t handle_local_rsc_req(uint32_t suInstId, uint32_t spInstId, uint32_t circuit, uint8_t globalFlg, uint8_t evntType, SiStaEvnt *siStaEvnt);
ftdm_status_t handle_rsc_rsp(uint32_t suInstId, uint32_t spInstId, uint32_t circuit, uint8_t globalFlg, uint8_t evntType, SiStaEvnt *siStaEvnt);
ftdm_status_t handle_grs_req(uint32_t suInstId, uint32_t spInstId, uint32_t circuit, uint8_t globalFlg, uint8_t evntType, SiStaEvnt *siStaEvnt);
ftdm_status_t handle_grs_rsp(uint32_t suInstId, uint32_t spInstId, uint32_t circuit, uint8_t globalFlg, uint8_t evntType, SiStaEvnt *siStaEvnt);
ftdm_status_t handle_blo_req(uint32_t suInstId, uint32_t spInstId, uint32_t circuit, uint8_t globalFlg, uint8_t evntType, SiStaEvnt *siStaEvnt);
ftdm_status_t handle_blo_rsp(uint32_t suInstId, uint32_t spInstId, uint32_t circuit, uint8_t globalFlg, uint8_t evntType, SiStaEvnt *siStaEvnt);
ftdm_status_t handle_ubl_req(uint32_t suInstId, uint32_t spInstId, uint32_t circuit, uint8_t globalFlg, uint8_t evntType, SiStaEvnt *siStaEvnt);
ftdm_status_t handle_ubl_rsp(uint32_t suInstId, uint32_t spInstId, uint32_t circuit, uint8_t globalFlg, uint8_t evntType, SiStaEvnt *siStaEvnt);
ftdm_status_t handle_local_blk(uint32_t suInstId, uint32_t spInstId, uint32_t circuit, uint8_t globalFlg, uint8_t evntType, SiStaEvnt *siStaEvnt);
ftdm_status_t handle_local_ubl(uint32_t suInstId, uint32_t spInstId, uint32_t circuit, uint8_t globalFlg, uint8_t evntType, SiStaEvnt *siStaEvnt);
ftdm_status_t handle_ucic(uint32_t suInstId, uint32_t spInstId, uint32_t circuit, uint8_t globalFlg, uint8_t evntType, SiStaEvnt *siStaEvnt);
ftdm_status_t handle_cgb_req(uint32_t suInstId, uint32_t spInstId, uint32_t circuit, uint8_t globalFlg, uint8_t evntType, SiStaEvnt *siStaEvnt);
ftdm_status_t handle_cgu_req(uint32_t suInstId, uint32_t spInstId, uint32_t circuit, uint8_t globalFlg, uint8_t evntType, SiStaEvnt *siStaEvnt);
ftdm_status_t handle_olm_msg(uint32_t suInstId, uint32_t spInstId, uint32_t circuit, uint8_t globalFlg, uint8_t evntType, SiStaEvnt *siStaEvnt);
/******************************************************************************/

/* FUNCTIONS ******************************************************************/

#define ftdm_running_return(var) if (!ftdm_running()) { SS7_ERROR("Error: ftdm_running is not set! Ignoring\n"); return var; } 


ftdm_status_t handle_con_ind(uint32_t suInstId, uint32_t spInstId, uint32_t circuit, SiConEvnt *siConEvnt)
{
	SS7_FUNC_TRACE_ENTER(__FUNCTION__);

	sngss7_chan_data_t *sngss7_info = NULL;
	ftdm_channel_t *ftdmchan = NULL;
	char var[FTDM_DIGITS_LIMIT];
	char val[64];
	ftdm_status_t status = FTDM_FAIL;

	memset(var, '\0', sizeof(var));
	memset(val, 0, sizeof(val));

	ftdm_running_return(FTDM_FAIL);

	/* get the ftdmchan and ss7_chan_data from the circuit */
	if (extract_chan_data(circuit, &sngss7_info, &ftdmchan)) {
		SS7_ERROR("Failed to extract channel data for circuit = %d!\n", circuit);
		SS7_FUNC_TRACE_EXIT(__FUNCTION__);
		return FTDM_FAIL;
	}

	if( ftdmchan->span->trunk_type == FTDM_TRUNK_T1 ) {
		if( siConEvnt->usrServInfo.eh.pres == PRSNT_NODEF && 
			siConEvnt->usrServInfo.usrInfLyr1Prot.pres == PRSNT_NODEF &&
			siConEvnt->usrServInfo.usrInfLyr1Prot.val != 0x02 /* ulaw */ ) {
			SS7_ERROR("Codec other than ulaw being used on T1\n");
		}
	} else if( ftdmchan->span->trunk_type == FTDM_TRUNK_E1 ) {
		if( siConEvnt->usrServInfo.eh.pres == PRSNT_NODEF && 
			siConEvnt->usrServInfo.usrInfLyr1Prot.pres == PRSNT_NODEF &&
			siConEvnt->usrServInfo.usrInfLyr1Prot.val != 0x03 /* alaw */ ) {
			SS7_ERROR("Codec other than alaw being used on E1\n");
		}
	} else {
		SS7_ERROR("Wrong circuit type. circuit = %d\n", circuit);
		SS7_FUNC_TRACE_EXIT(__FUNCTION__);
		return FTDM_FAIL;
	}

	/* lock the channel */
	ftdm_mutex_lock(ftdmchan->mutex);

	if (sngss7_test_ckt_flag(sngss7_info, FLAG_GLARE)) {
		SS7_INFO_CHAN(ftdmchan,"[CIC:%d]Rx IAM (glare)\n", sngss7_info->circuit->cic);
	} 

	/* check if the circuit has a remote block */
	if ((sngss7_test_ckt_blk_flag(sngss7_info, FLAG_CKT_MN_BLOCK_RX)) ||
		(sngss7_test_ckt_blk_flag(sngss7_info, FLAG_GRP_HW_BLOCK_RX)) ||
		(sngss7_test_ckt_blk_flag(sngss7_info, FLAG_GRP_MN_BLOCK_RX))) {

		/* as per Q.764, 2.8.2.3 xiv ... remove the block from this channel */
		sngss7_clear_ckt_blk_flag(sngss7_info, FLAG_CKT_MN_BLOCK_RX);
		sngss7_clear_ckt_blk_flag(sngss7_info, FLAG_CKT_MN_BLOCK_RX_DN);
		sngss7_clear_ckt_blk_flag(sngss7_info, FLAG_GRP_HW_BLOCK_RX);
		sngss7_clear_ckt_blk_flag(sngss7_info, FLAG_GRP_HW_BLOCK_RX_DN);
		sngss7_clear_ckt_blk_flag(sngss7_info, FLAG_GRP_MN_BLOCK_RX);
		sngss7_clear_ckt_blk_flag(sngss7_info, FLAG_GRP_MN_BLOCK_RX_DN);

		/* KONRAD FIX ME : check in case there is a ckt and grp block */
	}
	
	sngss7_clear_ckt_flag(sngss7_info, FLAG_INR_TX);
	sngss7_clear_ckt_flag(sngss7_info, FLAG_INR_SENT);
	sngss7_clear_ckt_flag(sngss7_info, FLAG_INR_RX);
	sngss7_clear_ckt_flag(sngss7_info, FLAG_INR_RX_DN);
	sngss7_clear_ckt_flag(sngss7_info, FLAG_INF_TX);
	sngss7_clear_ckt_flag(sngss7_info, FLAG_INF_SENT);
	sngss7_clear_ckt_flag(sngss7_info, FLAG_INF_RX);
	sngss7_clear_ckt_flag(sngss7_info, FLAG_INF_RX_DN);
	sngss7_clear_ckt_flag(sngss7_info, FLAG_FULL_NUMBER);

	switch (ftdmchan->state) {
	 /* DOWN is the only state it is valid to get IAM (except if there is glare */
	case (FTDM_CHANNEL_STATE_DOWN):

		if (ftdm_test_flag(ftdmchan, FTDM_CHANNEL_INUSE)) {
			goto handle_glare;
		} else if(ftdm_channel_open_chan(ftdmchan) != FTDM_SUCCESS) {
			SS7_ERROR("Failed to open span: %d, chan: %d\n",
						ftdmchan->physical_span_id,
						ftdmchan->physical_chan_id);

			sngss7_set_ckt_flag(sngss7_info, FLAG_LOCAL_REL);
			ftdmchan->caller_data.hangup_cause = 41;  /* SIT_CCTMPFAIL - temporarily unavailable */
			ftdm_set_state(ftdmchan, FTDM_CHANNEL_STATE_CANCEL);
		} else {
			sngss7_info->suInstId = get_unique_id();
			sngss7_info->spInstId = spInstId;

			copy_cgPtyNum_from_sngss7(ftdmchan, siConEvnt, sngss7_info);

			if (ftdm_strlen_zero(ftdmchan->caller_data.cid_num.digits)) {

				if (g_ftdm_sngss7_data.cfg.force_inr) {
					sngss7_set_ckt_flag(sngss7_info, FLAG_INR_TX);
					sngss7_clear_ckt_flag(sngss7_info, FLAG_INR_SENT);
				}

				SS7_INFO_CHAN(ftdmchan,"No Calling party (ANI) information in IAM!%s\n", " ");
			} else {
				SS7_INFO_CHAN(ftdmchan,"Calling party (ANI) information [%s]  present in IAM!%s\n", ftdmchan->caller_data.cid_num.digits," ");
				/* fill in cid Name */
				ftdm_set_string(ftdmchan->caller_data.cid_name, ftdmchan->caller_data.cid_num.digits);

				/* fill in ANI */
				ftdm_set_string(ftdmchan->caller_data.ani.digits, ftdmchan->caller_data.cid_num.digits);
			}

			/* fill in called party infomation */
			if (siConEvnt->cdPtyNum.eh.pres) {
				if (siConEvnt->cdPtyNum.addrSig.pres) {
					/* fill in the called number/dnis */
					copy_tknStr_from_sngss7(siConEvnt->cdPtyNum.addrSig, 
											ftdmchan->caller_data.dnis.digits, 
											siConEvnt->cdPtyNum.oddEven);
				}
			} else {
				SS7_INFO_CHAN(ftdmchan,"No Called party (DNIS) information in IAM!%s\n", " ");
			}
			copy_NatureOfConnection_from_sngss7(ftdmchan, &siConEvnt->natConInd);
			copy_fwdCallInd_hex_from_sngss7(ftdmchan, &siConEvnt->fwdCallInd);
			copy_access_transport_from_sngss7(ftdmchan, &siConEvnt->accTrnspt);
			copy_ocn_from_sngss7(ftdmchan, &siConEvnt->origCdNum);
			copy_redirgNum_from_sngss7(ftdmchan, &siConEvnt->redirgNum);
			copy_redirgInfo_from_sngss7(ftdmchan, &siConEvnt->redirInfo);
			copy_genNmb_from_sngss7(ftdmchan, &siConEvnt->genNmb);
			copy_genNmbR_from_sngss7(ftdmchan, &siConEvnt->genNmbR);
#ifdef SS7_UK
			copy_presNmb_from_sngss7(ftdmchan, &siConEvnt->presntNum);
			copy_nflxl_from_sngss7(ftdmchan, &siConEvnt->natFwdCalIndLnk);
			copy_nfci_from_sngss7(ftdmchan, &siConEvnt->natFwdCalInd);
			copy_divtlineid_from_sngss7(ftdmchan, &siConEvnt->lstDvrtLineId);
#endif

			if (SNGSS7_SWITCHTYPE_ANSI(g_ftdm_sngss7_data.cfg.isupCkt[sngss7_info->circuit->id].switchType)) {
				copy_usrServInfoA_from_sngss7(ftdmchan, &siConEvnt->usrServInfoA);
			}
			copy_usrServInfoA_from_sngss7(ftdmchan, &siConEvnt->usrServInfo);
			copy_cgPtyCat_from_sngss7(ftdmchan, &siConEvnt->cgPtyCat);
			copy_cdPtyNum_from_sngss7(ftdmchan, &siConEvnt->cdPtyNum);
			copy_chargeNum_from_sngss7(ftdmchan, &siConEvnt->chargeNum);
			copy_usr2UsrInfo_from_sngss7(ftdmchan, &siConEvnt->usr2UsrInfo);
			copy_hopCounter_from_sngss7(ftdmchan, &siConEvnt->hopCounter);

			if (siConEvnt->hopCounter.eh.pres == PRSNT_NODEF &&
					siConEvnt->hopCounter.hopCounter.pres == PRSNT_NODEF) {

				/* If IAM received with Hop counter value 1 then reject the call as
				 * no point of sending call to SIP with max forward = 0 */
				if (!siConEvnt->hopCounter.hopCounter.val) {
					/* setup the hangup cause */
					ftdmchan->caller_data.hangup_cause = 25;	/* CCEXCHRTGERR  exchange routing error */
					/* move the state of the channel to Terminating to end the call
					   in TERMINATING state, the release cause is set to REMOTE_REL
					   in any means. So we don't have to set the release reason here.
					   */
					ftdm_set_state(ftdmchan, FTDM_CHANNEL_STATE_HANGUP);
					break;
				}
			}

			/* By default there will be no message priority */
			sngss7_info->priority = FTDM_FALSE;
			/* Check for self congestion or remote congestion */
			if (g_ftdm_sngss7_data.cfg.sng_acc) {
				if ((siConEvnt->cgPtyCat.eh.pres == PRSNT_NODEF) &&
					(siConEvnt->cgPtyCat.cgPtyCat.pres == PRSNT_NODEF)) {

					/* TODO - confirm priority cpc value  */
					if (siConEvnt->cgPtyCat.cgPtyCat.val == CAT_PRIOR) {
						SS7_DEBUG_CHAN(ftdmchan,"Allow message even if there is congestion as the message has a priority level%s\n", " ");

						snprintf(val, sizeof(val), "%d", siConEvnt->cgPtyCat.cgPtyCat.val);
						ftdm_log_chan(ftdmchan, FTDM_LOG_DEBUG, "Setting Priority as %s\n", val);
						sngss7_add_var(sngss7_info, "ss7_iam_priority", val);

						sngss7_info->priority = FTDM_TRUE;
					}
				}

				if (!(sngss7_info->priority)) {
					status = ftdm_sangoma_ss7_get_congestion_status(ftdmchan);
					if ((status == FTDM_SUCCESS) || (status == FTDM_BREAK)) {
						break;
					}
				}

				/* Increased number of received calls */
				ftdm_sangoma_ss7_received_call(ftdmchan);
			}

			/* fill in the TMR/bearer capability */
			if (siConEvnt->txMedReq.eh.pres) {
				if (siConEvnt->txMedReq.trMedReq.pres) {
					/* fill in the bearer type */
					ftdmchan->caller_data.bearer_capability = siConEvnt->txMedReq.trMedReq.val;
				}
			} else {
				SS7_DEBUG_CHAN(ftdmchan,"No TMR/Bearer Cap information in IAM!%s\n", " ");
			}

			/* TODO - Ideally we should have configured list of supported bearer capability against which we 
				  compare the received bearer capability */
#ifdef SS7_UK
			if ((g_ftdm_sngss7_data.cfg.isupCkt[sngss7_info->circuit->id].switchType == LSI_SW_UK) && 
				       (g_ftdm_sngss7_data.cfg.isupCkt[sngss7_info->circuit->id].bearcap_check)) {
				/* If bearer capability is not supported then reject call */
				if (sngss7_is_bearer_capability_supported(ftdmchan->caller_data.bearer_capability) == FTDM_FAIL) {
					SS7_DEBUG_CHAN(ftdmchan,"Received bearar capability[%d] unsupported %s \n",ftdmchan->caller_data.bearer_capability,"");
					ftdmchan->caller_data.hangup_cause = 88;	/* SIT_CCINCOMPDEST - Incompatible Destination */
					sngss7_set_ckt_flag (sngss7_info, FLAG_LOCAL_REL);
					ftdm_set_state(ftdmchan, FTDM_CHANNEL_STATE_CANCEL);
					break;
				}
			}
#endif

			/* add any special variables for the dialplan */
			sprintf(var, "%d", siConEvnt->cgPtyNum.natAddrInd.val);
			sngss7_add_var(sngss7_info, "ss7_clg_nadi", var);

			/* Retrieve the Location Number if present (see ITU Q.763, 3.30) */
			if (siConEvnt->cgPtyNum1.eh.pres) {
				if (siConEvnt->cgPtyNum1.addrSig.pres) {
					/* fill in the ss7 location address number */
					copy_tknStr_from_sngss7(siConEvnt->cgPtyNum1.addrSig, var, siConEvnt->cgPtyNum1.oddEven);
					sngss7_add_var(sngss7_info, "ss7_loc_digits", var);
				}

				if (siConEvnt->cgPtyNum1.scrnInd.pres) {
					/* fill in the screening indication value */
					sprintf(var, "%d", siConEvnt->cgPtyNum1.scrnInd.val);
					sngss7_add_var(sngss7_info, "ss7_loc_screen_ind", var);
				}

				if (siConEvnt->cgPtyNum1.presRest.pres) {
					/* fill in the presentation value */
					sprintf(var, "%d", siConEvnt->cgPtyNum1.presRest.val);
					sngss7_add_var(sngss7_info, "ss7_loc_pres_ind", var);
				}

				if (siConEvnt->cgPtyNum1.natAddrInd.pres) {
					sprintf(var, "%d", siConEvnt->cgPtyNum1.natAddrInd.val);
					sngss7_add_var(sngss7_info, "ss7_loc_nadi", var);
				}
			} else {
				SS7_DEBUG_CHAN(ftdmchan, "No Location Number information in IAM%s\n", " ");
			}

			sprintf(var, "%d", sngss7_info->circuit->cic);
			sngss7_add_var(sngss7_info, "ss7_cic", var);


			sprintf(var, "%d", g_ftdm_sngss7_data.cfg.isupIntf[sngss7_info->circuit->infId].dpc );
			sngss7_add_var(sngss7_info, "ss7_opc", var);
			
			if (siConEvnt->callRef.callId.pres) {
				ftdmchan->caller_data.call_reference = (unsigned int)siConEvnt->callRef.callId.val;
			} else {
				ftdmchan->caller_data.call_reference = 0;
			}
			
			if (sngss7_info->circuit->transparent_iam) {
				sngss7_save_iam(ftdmchan, siConEvnt);
			}

			/* check if a COT test is requested */
			if ((siConEvnt->natConInd.eh.pres) && 
				(siConEvnt->natConInd.contChkInd.pres) &&
				(siConEvnt->natConInd.contChkInd.val)) {

				SS7_INFO_CHAN(ftdmchan,"[CIC:%d]Found COT Request\n", sngss7_info->circuit->cic);

				/* tell the core to loop the channel */
				ftdm_channel_command(ftdmchan, FTDM_COMMAND_ENABLE_LOOP, NULL);

				/* move to in loop state */
				ftdm_set_state(ftdmchan, FTDM_CHANNEL_STATE_IN_LOOP);
			} else {
				/* set the state of the channel to collecting...the rest is done by the chan monitor */
				ftdm_set_state(ftdmchan, FTDM_CHANNEL_STATE_COLLECT);
			}

			if (strlen(ftdmchan->caller_data.cid_num.digits)) {
				/* Add Calling party number also for dialplan */
				sprintf(var, "%s", ftdmchan->caller_data.cid_num.digits);
				sngss7_add_var(sngss7_info, "ss7_clg_num", var);
			}

			if (strlen(ftdmchan->caller_data.cid_num.digits)) {
				/* Add Calling party number also for dialplan */
				sprintf(var, "%s", ftdmchan->caller_data.cid_num.digits);
				sngss7_add_var(sngss7_info, "ss7_clg_num", var);
			}

#ifdef ACC_TEST
			if (sngss7_info->priority == FTDM_FALSE) {
				sng_increment_acc_statistics(ftdmchan, ACC_IAM_RECV_DEBUG);
			} else {
				sng_increment_acc_statistics(ftdmchan, ACC_IAM_PRI_RECV_DEBUG);
			}
#endif
			if (strlen(ftdmchan->caller_data.cid_num.digits)) {
				/* Add Calling party number also for dialplan */
				sprintf(var, "%s", ftdmchan->caller_data.cid_num.digits);
				sngss7_add_var(sngss7_info, "ss7_clg_num", var);
			}

			SS7_INFO_CHAN(ftdmchan,"[CIC:%d]Rx IAM clg = \"%s\" (NADI=%d), cld = \"%s\" (NADI=%d)\n",
							sngss7_info->circuit->cic,
							ftdmchan->caller_data.cid_num.digits,
							siConEvnt->cgPtyNum.natAddrInd.val,
							ftdmchan->caller_data.dnis.digits,
							siConEvnt->cdPtyNum.natAddrInd.val);
		} /* if (channel is usable */

		break;

	case (FTDM_CHANNEL_STATE_DIALING):
	case (FTDM_CHANNEL_STATE_TERMINATING):
	case (FTDM_CHANNEL_STATE_HANGUP):
	case (FTDM_CHANNEL_STATE_HANGUP_COMPLETE):
handle_glare:
		/* the core already has plans for this channel...glare */
		SS7_INFO_CHAN(ftdmchan, "Got IAM on channel that is already inuse (state=%s|inuse=%d)...glare!\n", 
								ftdm_channel_state2str (ftdmchan->state),
								ftdm_test_flag(ftdmchan, FTDM_CHANNEL_INUSE));

		/* save the info so that we can use it later on */
		sngss7_info->glare.spInstId = spInstId;
		sngss7_info->glare.circuit = circuit;
		memcpy(&sngss7_info->glare.iam, siConEvnt, sizeof(*siConEvnt));

		if (!(sngss7_test_ckt_flag(sngss7_info, FLAG_GLARE))) {
			sngss7_set_ckt_flag(sngss7_info, FLAG_GLARE);
		
			/* setup the hangup cause */
			ftdmchan->caller_data.hangup_cause = 34;	/* SIT_CCNOCIRCUIT - Circuit Congrestion */
			
			/* move the state of the channel to Terminating to end the call 
			     in TERMINATING state, the release cause is set to REMOTE_REL 
			     in any means. So we don't have to set the release reason here.
			*/
			ftdm_set_state(ftdmchan, FTDM_CHANNEL_STATE_TERMINATING);
		}
		break;
	default:        /* should not have gotten an IAM while in this state */
		SS7_ERROR_CHAN(ftdmchan, "Got IAM on channel in invalid state(%s)...reset!\n", ftdm_channel_state2str (ftdmchan->state));

		/* throw the TX reset flag */
		if (!sngss7_tx_reset_status_pending(sngss7_info)) {
			sngss7_tx_reset_restart(sngss7_info);
			sngss7_set_ckt_flag (sngss7_info, FLAG_REMOTE_REL);

			/* go to RESTART */
			ftdm_set_state(ftdmchan, FTDM_CHANNEL_STATE_RESTART);
		}
		break;
	}

	ftdm_mutex_unlock(ftdmchan->mutex);

	SS7_FUNC_TRACE_EXIT(__FUNCTION__);
	return FTDM_SUCCESS;
}

/******************************************************************************/
ftdm_status_t handle_con_sta(uint32_t suInstId, uint32_t spInstId, uint32_t circuit, SiCnStEvnt *siCnStEvnt, uint8_t evntType)
{
	SS7_FUNC_TRACE_ENTER(__FUNCTION__);

	sngss7_chan_data_t  *sngss7_info ;
	ftdm_channel_t	  *ftdmchan;
	
	ftdm_running_return(FTDM_FAIL);

	if (extract_chan_data(circuit, &sngss7_info, &ftdmchan)) {
		SS7_ERROR("Failed to extract channel data for circuit = %d!\n", circuit);
		SS7_FUNC_TRACE_EXIT(__FUNCTION__);
		return FTDM_FAIL;
	}

	ftdm_mutex_lock(ftdmchan->mutex);

	switch (evntType) {
	case (ADDRCMPLT):
		SS7_INFO_CHAN(ftdmchan,"[CIC:%d]Rx ACM\n", sngss7_info->circuit->cic);

		switch (ftdmchan->state) {
		case FTDM_CHANNEL_STATE_DIALING:
			{
				ftdm_channel_state_t next_state = FTDM_CHANNEL_STATE_INVALID;

				/* need to grab the sp instance id */ 
				sngss7_info->spInstId = spInstId;

				/* RFC3398 - implementation -
				 * ACM - Called Party Status indicator - Subscriber free then 180
				 * ACM - In-Band media - 183
				 */

				if (siCnStEvnt->bckCallInd.eh.pres == PRSNT_NODEF) {
					if (siCnStEvnt->bckCallInd.cadPtyStatInd.pres == PRSNT_NODEF) {
						if (siCnStEvnt->bckCallInd.cadPtyStatInd.val == CADSTAT_NOIND ) {
							/* RFC3398 - section 7.2.5 explain Early ACM requirement where
							 * GW has to send 183 instead of 180 in case if the Called Party's
							 * Status Indicator is set to 00 (no indication). */
							next_state = FTDM_CHANNEL_STATE_PROGRESS_MEDIA;
						} else if (siCnStEvnt->bckCallInd.cadPtyStatInd.val == CADSTAT_SUBFREE) {
							next_state = FTDM_CHANNEL_STATE_RINGING;
						}
					}
					if (siCnStEvnt->bckCallInd.intInd.pres == PRSNT_NODEF &&
						siCnStEvnt->bckCallInd.intInd.val == INTIND_INTW) {
						next_state = FTDM_CHANNEL_STATE_PROGRESS_MEDIA;
					}
				} 

				if (siCnStEvnt->optBckCalInd.eh.pres == PRSNT_NODEF && 
				    siCnStEvnt->optBckCalInd.inbndInfoInd.pres == PRSNT_NODEF && 
				    siCnStEvnt->optBckCalInd.inbndInfoInd.val) {

					next_state = FTDM_CHANNEL_STATE_PROGRESS_MEDIA;
				}
				/* Ideally we should control below logic via dialplan variable
				 * but somehow dialplan variable not working, hence using gen config option
				 * to control this..need to revisit this */
				{
					const char *val = NULL;
					val = ftdm_usrmsg_get_var(ftdmchan->usrmsg, "ss7_force_early_media");
					if (!ftdm_strlen_zero(val) && ftdm_true(val)) {
						SS7_WARN_CHAN(ftdmchan, "ss7_force_early_media set..moving to PROGRESS_MEDIA state \n", sngss7_info->circuit->cic);
						next_state = FTDM_CHANNEL_STATE_PROGRESS_MEDIA;
					} else if (g_ftdm_sngss7_data.cfg.force_early_media) {
						SS7_WARN_CHAN(ftdmchan, "force_early_media configured..moving to PROGRESS_MEDIA state \n", sngss7_info->circuit->cic);
						/* forcefully moving to progress media */
						next_state = FTDM_CHANNEL_STATE_PROGRESS_MEDIA;
					}
				}

				if (next_state != FTDM_CHANNEL_STATE_INVALID) {
					ftdm_set_state(ftdmchan, next_state);
				}
			}	
			break;
		case FTDM_CHANNEL_STATE_DOWN:
			SS7_WARN_CHAN(ftdmchan, "RX ACM in DOWN state CIC[%d]. Ignore the message.\n",  sngss7_info->circuit->cic );
			break;
			
		default:
			SS7_ERROR_CHAN(ftdmchan, "RX ACM in invalid state :%s...CIC [%d]\n", 
							ftdm_channel_state2str (ftdmchan->state),  sngss7_info->circuit->cic);

#if 0
			/* throw the TX reset flag */
			if (!sngss7_tx_reset_status_pending(sngss7_info)) {
				sngss7_tx_reset_restart(sngss7_info);
				sngss7_set_ckt_flag (sngss7_info, FLAG_REMOTE_REL);

				/* go to RESTART */
				ftdm_set_state(ftdmchan, FTDM_CHANNEL_STATE_RESTART);
			}
#endif

			break;
		}

		break;
		
	case (MODIFY):
		SS7_INFO_CHAN(ftdmchan,"[CIC:%d]Rx MODIFY\n", sngss7_info->circuit->cic);
		break;
	case (MODCMPLT):
		SS7_INFO_CHAN(ftdmchan,"[CIC:%d]Rx MODIFY-COMPLETE\n", sngss7_info->circuit->cic);
		break;
	case (MODREJ):
		SS7_INFO_CHAN(ftdmchan,"[CIC:%d]Rx MODIFY-REJECT\n", sngss7_info->circuit->cic);
		break;
	case (PROGRESS):
		SS7_INFO_CHAN(ftdmchan,"[CIC:%d]Rx CPG\n", sngss7_info->circuit->cic);

		switch (ftdmchan->state) {
		case FTDM_CHANNEL_STATE_DIALING:
		case FTDM_CHANNEL_STATE_PROGRESS:
		case FTDM_CHANNEL_STATE_PROGRESS_MEDIA:
		case FTDM_CHANNEL_STATE_RING:
		case FTDM_CHANNEL_STATE_RINGING:

			SS7_INFO_CHAN(ftdmchan,"[CIC:%d]Rx CPG in state: %s \n", sngss7_info->circuit->cic, ftdm_channel_state2str (ftdmchan->state));

			sngss7_info->spInstId = spInstId;
			if (siCnStEvnt->evntInfo.eh.pres == PRSNT_NODEF && 
				siCnStEvnt->evntInfo.evntInd.pres == PRSNT_NODEF) {
				switch (siCnStEvnt->evntInfo.evntInd.val) {
				case EV_ALERT:
					/* #10999 - Even if Event indicator says alert , we also need to see 
					 * if CPG has in-band information present in Optional BCI parameter */
					if (siCnStEvnt->optBckCalInd.eh.pres == PRSNT_NODEF && 
							siCnStEvnt->optBckCalInd.inbndInfoInd.pres == PRSNT_NODEF && 
							siCnStEvnt->optBckCalInd.inbndInfoInd.val) {
						SS7_INFO_CHAN(ftdmchan,"[CIC:%d]Rx CPG with In-band information in Optional BCI params\n", sngss7_info->circuit->cic);
						if (ftdmchan->state != FTDM_CHANNEL_STATE_PROGRESS_MEDIA) {
							ftdm_set_state(ftdmchan, FTDM_CHANNEL_STATE_PROGRESS_MEDIA);
						}
					}
					else if ((ftdmchan->state == FTDM_CHANNEL_STATE_PROGRESS_MEDIA) && 
						 (g_ftdm_sngss7_data.cfg.isupCkt[sngss7_info->circuit->id].ignore_alert_on_cpg == FTDM_TRUE)) {
						/* #10999 Ignore 180 after 183..on ACM we have already sent 183, hence ignore 180..*/ 
						break;
					} else if (ftdmchan->state != FTDM_CHANNEL_STATE_RINGING) {
						sngss7_send_signal(sngss7_info, FTDM_SIGEVENT_ALERTING);
					}
					break;
				case EV_PROGRESS:
				case EV_INBAND:
				case EV_FWDONNOREP:
					if (ftdmchan->state != FTDM_CHANNEL_STATE_PROGRESS_MEDIA) {
						ftdm_set_state(ftdmchan, FTDM_CHANNEL_STATE_PROGRESS_MEDIA);
					}
					break;
				case EV_FWDONBUSY:
				case EV_FWDUNCONDIT:
					/* need to send SIP 181 in the future when type is above */
					break;
				default:
					SS7_INFO_CHAN(ftdmchan,"[CIC:%d]Wrong event info type %d. Ignoring.\n", 
								  sngss7_info->circuit->cic, siCnStEvnt->evntInfo.evntInd.val);
					break;
				}
			} else {
				if (ftdmchan->state != FTDM_CHANNEL_STATE_PROGRESS_MEDIA) {
					ftdm_set_state(ftdmchan, FTDM_CHANNEL_STATE_PROGRESS_MEDIA);
				}
			}
			break;
		default:	
			SS7_ERROR_CHAN(ftdmchan, "Rx CPG in invalid state :%s...... ignoring\n", 
									ftdm_channel_state2str (ftdmchan->state));

			break;
		}

		break;
	case (FRWDTRSFR):
		SS7_INFO_CHAN(ftdmchan,"[CIC:%d]Rx FOT\n", sngss7_info->circuit->cic);
		break;
	case (INFORMATION):
		SS7_INFO_CHAN(ftdmchan,"[CIC:%d]Rx INF\n", sngss7_info->circuit->cic);

		SS7_DEBUG_CHAN (ftdmchan, "Cancelling T.39 timer %s\n", " ");
		/* check if t39 is active */
		if (sngss7_info->t39.hb_timer_id) {
			ftdm_sched_cancel_timer (sngss7_info->t39.sched, sngss7_info->t39.hb_timer_id);
			SS7_DEBUG_CHAN (ftdmchan, "T.39 timer has been cancelled upon receiving INF message %s\n", " ");
		}

		sngss7_set_ckt_flag(sngss7_info, FLAG_INF_RX_DN);
		ftdm_set_state(ftdmchan, FTDM_CHANNEL_STATE_IDLE);		
		
		break;
	case (INFORMATREQ):
		SS7_INFO_CHAN(ftdmchan,"[CIC:%d]Rx INR\n", sngss7_info->circuit->cic);
		ft_to_sngss7_inf(ftdmchan, siCnStEvnt);
		sngss7_set_ckt_flag(sngss7_info, FLAG_INR_RX);
		
		break;
	case (SUBSADDR):
		SS7_INFO_CHAN(ftdmchan,"[CIC:%d]Rx SAM\n", sngss7_info->circuit->cic);

		/* check the channel state */
		switch (ftdmchan->state) {
		case (FTDM_CHANNEL_STATE_COLLECT):
			
			/* confirm that the event contains the subsquent number field */
			if (siCnStEvnt->subNum.eh.pres && siCnStEvnt->subNum.addrSig.pres) {
				/* add the digits to the ftdm channel variable */
				append_tknStr_from_sngss7(siCnStEvnt->subNum.addrSig, 
											ftdmchan->caller_data.dnis.digits, 
											siCnStEvnt->subNum.oddEven);
				SS7_DEBUG_CHAN(ftdmchan,"[CIC:%d]Rx SAM (digits = %s)\n", sngss7_info->circuit->cic,
								  ftdmchan->caller_data.dnis.digits);
			} else {
				SS7_INFO_CHAN(ftdmchan,"No Called party (DNIS) information in SAM!%s\n", " ");
			}

			/* go to idle so that collect state is processed again */
			ftdm_set_state(ftdmchan, FTDM_CHANNEL_STATE_IDLE);
			break;
		default:
			SS7_ERROR_CHAN(ftdmchan, "RX SAM in invalid state :%s...ignoring\n", 
										ftdm_channel_state2str (ftdmchan->state));
			break;
		}

		break;

	case (EXIT):
		SS7_INFO_CHAN(ftdmchan,"[CIC:%d]Rx EXIT\n", sngss7_info->circuit->cic);
		break;

	case (NETRESMGT):
		SS7_INFO_CHAN(ftdmchan,"[CIC:%d]Rx NRM\n", sngss7_info->circuit->cic);
		break;

	case (IDENTREQ):
		SS7_INFO_CHAN(ftdmchan,"[CIC:%d]Rx IDR\n", sngss7_info->circuit->cic);
		break;

	case (IDENTRSP):
		SS7_INFO_CHAN(ftdmchan,"[CIC:%d]Rx IRS\n", sngss7_info->circuit->cic);
		break;

	case (MALCLLPRNT):
		SS7_INFO_CHAN(ftdmchan,"[CIC:%d]Rx MALICIOUS CALL\n", sngss7_info->circuit->cic);
		break;

	case (CHARGE):
		SS7_INFO_CHAN(ftdmchan,"[CIC:%d]Rx CRG\n", sngss7_info->circuit->cic);
		break;

	case (TRFFCHGE):
		SS7_INFO_CHAN(ftdmchan,"[CIC:%d]Rx CRG-TARIFF\n", sngss7_info->circuit->cic);
		break;

	case (CHARGEACK):
		SS7_INFO_CHAN(ftdmchan,"[CIC:%d]Rx CRG-ACK\n", sngss7_info->circuit->cic);
		break;

	case (CALLOFFMSG):
		SS7_INFO_CHAN(ftdmchan,"[CIC:%d]Rx CALL-OFFER\n", sngss7_info->circuit->cic);
		break;

	case (LOOPPRVNT):
		SS7_INFO_CHAN(ftdmchan,"[CIC:%d]Rx LOP\n", sngss7_info->circuit->cic);
		break;

	case (TECT_TIMEOUT):
		SS7_INFO_CHAN(ftdmchan,"[CIC:%d]Rx ECT-Timeout\n", sngss7_info->circuit->cic);
		break;

	case (RINGSEND):
		SS7_INFO_CHAN(ftdmchan,"[CIC:%d]Rx RINGING-SEND\n", sngss7_info->circuit->cic);
		break;

	case (CALLCLEAR):
		SS7_INFO_CHAN(ftdmchan,"[CIC:%d]Rx CALL-LINE Clear\n", sngss7_info->circuit->cic);
		break;

	case (PRERELEASE):
		SS7_INFO_CHAN(ftdmchan,"[CIC:%d]Rx PRI\n", sngss7_info->circuit->cic);
		break;

	case (APPTRANSPORT):
		SS7_INFO_CHAN(ftdmchan,"[CIC:%d]Rx APM\n", sngss7_info->circuit->cic);
		break;

	case (OPERATOR):
		SS7_INFO_CHAN(ftdmchan,"[CIC:%d]Rx OPERATOR\n", sngss7_info->circuit->cic);
		break;

	case (METPULSE):
		SS7_INFO_CHAN(ftdmchan,"[CIC:%d]Rx METERING-PULSE\n", sngss7_info->circuit->cic);
		break;

	case (CLGPTCLR):
		SS7_INFO_CHAN(ftdmchan,"[CIC:%d]Rx CALLING_PARTY_CLEAR\n", sngss7_info->circuit->cic);
		break;

	case (SUBDIRNUM):
		SS7_INFO_CHAN(ftdmchan,"[CIC:%d]Rx SUB-DIR\n", sngss7_info->circuit->cic);
		break;
#ifdef SANGOMA_SPIROU
	case (CHARGE_ACK):
		SS7_INFO_CHAN(ftdmchan,"[CIC:%d]Rx TXA\n", sngss7_info->circuit->cic);		
		break;
	case (CHARGE_UNIT):
		{			
			uint32_t charging_unit = 0;
			uint32_t msg_num = 0;
			char	val[3];			
			
			SS7_INFO_CHAN(ftdmchan,"[CIC:%d]Rx ITX\n", sngss7_info->circuit->cic);

			memset(val, '\0', sizeof(val));

			if (siCnStEvnt->chargUnitNum.eh.pres == PRSNT_NODEF &&
				siCnStEvnt->chargUnitNum.chargUnitNum.pres == PRSNT_NODEF) {

				charging_unit = siCnStEvnt->chargUnitNum.chargUnitNum.val;
			}

			if (siCnStEvnt->msgNum.eh.pres == PRSNT_NODEF &&
				siCnStEvnt->msgNum.msgNum.pres == PRSNT_NODEF) {

				msg_num = siCnStEvnt->msgNum.msgNum.val;
			}

			ftdm_log_chan(ftdmchan, FTDM_LOG_INFO, "Charging Unit:%d Msg Num:%d\n", charging_unit, msg_num);
			
			sprintf(val, "%d", charging_unit);
			sngss7_add_var(sngss7_info, "ss7_itx_charge_unit", val);
			
			sprintf(val, "%d", msg_num);
			sngss7_add_var(sngss7_info, "ss7_itx_msg_num", val);
			
			if (sngss7_info->circuit->itx_auto_reply) {
				ftdm_log_chan_msg(ftdmchan, FTDM_LOG_INFO, "Auto-reply with TXA msg\n");
				ft_to_sngss7_txa (ftdmchan);
			}
		}
		break;
#endif

	default:
	   	SS7_INFO_CHAN(ftdmchan,"[CIC:%d]Rx Unknown Msg\n", sngss7_info->circuit->cic);
		break;

	}

	ftdm_mutex_unlock(ftdmchan->mutex);
	SS7_FUNC_TRACE_EXIT(__FUNCTION__);
	return FTDM_SUCCESS;
}

/******************************************************************************/
ftdm_status_t handle_con_cfm(uint32_t suInstId, uint32_t spInstId, uint32_t circuit, SiConEvnt *siConEvnt)
{
	SS7_FUNC_TRACE_ENTER(__FUNCTION__);

	sngss7_chan_data_t  *sngss7_info ;
	ftdm_channel_t	  *ftdmchan;
	
	ftdm_running_return(FTDM_FAIL);
	if (extract_chan_data(circuit, &sngss7_info, &ftdmchan)) {
		SS7_ERROR("Failed to extract channel data for circuit = %d!\n", circuit);
		SS7_FUNC_TRACE_EXIT(__FUNCTION__);
		return FTDM_FAIL;
	}
	ftdm_mutex_lock(ftdmchan->mutex);

	/* check whether the ftdm channel is in a state to accept a call */
	switch (ftdmchan->state) {

	case FTDM_CHANNEL_STATE_RINGING:
	case FTDM_CHANNEL_STATE_PROGRESS:
	case FTDM_CHANNEL_STATE_PROGRESS_MEDIA:
		SS7_INFO_CHAN(ftdmchan,"[CIC:%d]Rx ANM\n", sngss7_info->circuit->cic);
		ftdm_set_state(ftdmchan, FTDM_CHANNEL_STATE_UP);
		break;

	case FTDM_CHANNEL_STATE_DIALING:
		SS7_INFO_CHAN(ftdmchan,"[CIC:%d]Rx CON\n", sngss7_info->circuit->cic);
		ftdm_set_state(ftdmchan, FTDM_CHANNEL_STATE_UP);
		break;		

	case FTDM_CHANNEL_STATE_HANGUP_COMPLETE:

		/* already hangup complete, just ignore it */
		/* 
		 * i.e. collision REL & ANM
		 * IAM ->
		 * <- ACM
		 * REL ->	<- ANM  (if REL gets processed first, ANM needs to be ignored)
		 * <- RLC
		 */
		SS7_INFO_CHAN(ftdmchan,"[CIC:%d]Rx ANM/CON Ignoring it because we already hung up\n", sngss7_info->circuit->cic);

		break;

	default:        /* incorrect state...reset the CIC */
		SS7_ERROR_CHAN(ftdmchan, "Got ANM/CON on channel in invalid state(%s)...reset!\n", ftdm_channel_state2str (ftdmchan->state));

		/* throw the TX reset flag */
		if (!sngss7_tx_reset_status_pending(sngss7_info)) {
			sngss7_tx_reset_restart(sngss7_info);
			sngss7_set_ckt_flag (sngss7_info, FLAG_REMOTE_REL);

			/* go to RESTART */
			ftdm_set_state(ftdmchan, FTDM_CHANNEL_STATE_RESTART);
		}
		break;
	}

	ftdm_mutex_unlock(ftdmchan->mutex);
	SS7_FUNC_TRACE_EXIT(__FUNCTION__);
	return FTDM_SUCCESS;
}

/******************************************************************************/
ftdm_status_t handle_rel_ind(uint32_t suInstId, uint32_t spInstId, uint32_t circuit, SiRelEvnt *siRelEvnt)
{
	SS7_FUNC_TRACE_ENTER(__FUNCTION__);

	sngss7_chan_data_t  *sngss7_info ;
	ftdm_channel_t	  *ftdmchan;
	
	ftdm_running_return(FTDM_FAIL);
	if (extract_chan_data(circuit, &sngss7_info, &ftdmchan)) {
		SS7_ERROR("Failed to extract channel data for circuit = %d!\n", circuit);
		SS7_FUNC_TRACE_EXIT(__FUNCTION__);
		return FTDM_FAIL;
	}
	ftdm_mutex_lock(ftdmchan->mutex);

	/* check for Automatic Congestion level */
	ftdm_check_acc(sngss7_info, siRelEvnt, ftdmchan);

	SS7_INFO_CHAN(ftdmchan,"[CIC:%d]Rx REL cause=%d\n",
							sngss7_info->circuit->cic, 
							siRelEvnt->causeDgn.causeVal.val);

	/* check whether the ftdm channel is in a state to release a call */
	switch (ftdmchan->state) {
	case FTDM_CHANNEL_STATE_DIALING:

		/* pass the release code up to FTDM */
		if (siRelEvnt->causeDgn.causeVal.pres) {
			ftdmchan->caller_data.hangup_cause = siRelEvnt->causeDgn.causeVal.val;
		} else {
			SS7_ERROR("REL does not have a cause code!\n");
			ftdmchan->caller_data.hangup_cause = 0;
		}

		sngss7_set_ckt_flag(sngss7_info, FLAG_REMOTE_REL);
		ftdm_channel_command(ftdmchan, FTDM_COMMAND_DISABLE_LOOP, NULL);
		ftdm_set_state(ftdmchan, FTDM_CHANNEL_STATE_TERMINATING);
		break;

	case FTDM_CHANNEL_STATE_RING:
	case FTDM_CHANNEL_STATE_RINGING:
	case FTDM_CHANNEL_STATE_PROGRESS:
	case FTDM_CHANNEL_STATE_PROGRESS_MEDIA:
	case FTDM_CHANNEL_STATE_UP:

		/* pass the release code up to FTDM */
		if (siRelEvnt->causeDgn.causeVal.pres) {
			ftdmchan->caller_data.hangup_cause = siRelEvnt->causeDgn.causeVal.val;
		} else {
			SS7_ERROR("REL does not have a cause ftdm_channel_command(ftdmchan, FTDM_COMMAND_DISABLE_LOOP, NULL);code!\n");
			ftdmchan->caller_data.hangup_cause = 0;
		}

		sngss7_set_ckt_flag(sngss7_info, FLAG_REMOTE_REL);
		ftdm_set_state(ftdmchan, FTDM_CHANNEL_STATE_TERMINATING);
		break;

	case FTDM_CHANNEL_STATE_HANGUP_COMPLETE:
		/* ITU Q.764 2.3.1 e)
		 * Collision of release messages
		 *
		 * ITU Q.784 Test Number 3.8
		 * Collision of REL messages
		 */
		SS7_DEBUG_CHAN(ftdmchan, "Collision of REL messages. Rx REL while waiting for RLC.\n", " ");
		if (sngss7_test_ckt_flag(sngss7_info, FLAG_LOCAL_REL) && 
			!sngss7_test_ckt_flag (sngss7_info, FLAG_REMOTE_REL)) {
			/* locally requested hangup completed, wait for remote RLC */
			/* need to perform remote release */

			/* this is also a remote hangup request */
			sngss7_set_ckt_flag(sngss7_info, FLAG_REMOTE_REL);
		}
		ft_to_sngss7_rlc (ftdmchan);
		break;

	case FTDM_CHANNEL_STATE_IN_LOOP:
		/* inform the core to unloop the channel*/
		ftdm_channel_command(ftdmchan, FTDM_COMMAND_DISABLE_LOOP, NULL);

		/* since we need to acknowledge the hang up set the flag for remote release */
		sngss7_set_ckt_flag(sngss7_info, FLAG_REMOTE_REL);

		/* go to hangup complete to send the RLC */
		ftdm_set_state(ftdmchan, FTDM_CHANNEL_STATE_HANGUP_COMPLETE);

		/* save the call info for the RLC */
		sngss7_info->suInstId = get_unique_id();
		sngss7_info->spInstId = spInstId;
		break;

	case FTDM_CHANNEL_STATE_DOWN:
		/* according to q.764 2.9.5.1-a) send RLC back if circuit is idle to eliminate ambiguities */
		ft_to_sngss7_rlc (ftdmchan);
		break;
	default:
		SS7_ERROR_CHAN(ftdmchan, "Got REL on channel in invalid state(%s)...reset!\n", ftdm_channel_state2str (ftdmchan->state));
		/* throw the TX reset flag */
		if (!sngss7_tx_reset_status_pending(sngss7_info)) {
			sngss7_set_ckt_flag (sngss7_info, FLAG_REMOTE_REL);
			sngss7_tx_reset_restart(sngss7_info);

			/* go to RESTART */
			ftdm_set_state(ftdmchan, FTDM_CHANNEL_STATE_RESTART);
		}
		break;
	}

	ftdm_mutex_unlock(ftdmchan->mutex);
	SS7_FUNC_TRACE_EXIT(__FUNCTION__);
	return FTDM_SUCCESS;
}

/******************************************************************************/
ftdm_status_t handle_peer_rel_ind(uint32_t suInstId, uint32_t spInstId, uint32_t circuit, SiRelEvnt *siRelEvnt)
{
	SS7_FUNC_TRACE_ENTER(__FUNCTION__);

	sngss7_chan_data_t  *sngss7_info ;
	ftdm_channel_t	  *ftdmchan;

	ftdm_running_return(FTDM_FAIL);
	if (extract_chan_data(circuit, &sngss7_info, &ftdmchan)) {
		SS7_ERROR("Failed to extract channel data for circuit = %d!\n", circuit);
		SS7_FUNC_TRACE_EXIT(__FUNCTION__);
		return FTDM_FAIL;
	}
	ftdm_mutex_lock(ftdmchan->mutex);

	/* check for Automatic Congestion level */
	ftdm_check_acc(sngss7_info, siRelEvnt, ftdmchan);

	SS7_INFO_CHAN(ftdmchan,"[CIC:%d]Tx REL cause=%d\n",
							sngss7_info->circuit->cic,
							siRelEvnt->causeDgn.causeVal.val);

	ftdm_mutex_unlock(ftdmchan->mutex);
	SS7_FUNC_TRACE_EXIT(__FUNCTION__);
	return FTDM_SUCCESS;
}

/******************************************************************************/
ftdm_status_t handle_rel_cfm(uint32_t suInstId, uint32_t spInstId, uint32_t circuit, SiRelEvnt *siRelEvnt)
{
	SS7_FUNC_TRACE_ENTER(__FUNCTION__);
	
	sngss7_chan_data_t  *sngss7_info ;
	ftdm_channel_t	  *ftdmchan;
	
	ftdm_running_return(FTDM_FAIL);
	if (extract_chan_data(circuit, &sngss7_info, &ftdmchan)) {
		SS7_ERROR("Failed to extract channel data for circuit = %d!\n", circuit);
		SS7_FUNC_TRACE_EXIT(__FUNCTION__);
		return FTDM_FAIL;
	}
	ftdm_mutex_lock(ftdmchan->mutex);

	SS7_INFO_CHAN(ftdmchan,"[CIC:%d]Rx RLC\n", sngss7_info->circuit->cic);

	switch (ftdmchan->state) {
	case FTDM_CHANNEL_STATE_HANGUP_COMPLETE:
		ftdm_set_state(ftdmchan, FTDM_CHANNEL_STATE_DOWN);
		break;

	case FTDM_CHANNEL_STATE_DOWN:
		/* according to q.764 2.9.5.1-b) disgard REL CFM message on DOWN state */
		break;
	default:	
		SS7_WARN_CHAN(ftdmchan, "Got REL CFM on channel in invalid state(%s).Ignore the received RLC message. \n", ftdm_channel_state2str (ftdmchan->state));
		/* KONRAD: should just stop the call...but a reset is easier for now (since it does hangup the call) */

		/* go to RESTART */
		ftdm_set_state(ftdmchan, FTDM_CHANNEL_STATE_RESTART);
		break;
	}

	ftdm_mutex_unlock(ftdmchan->mutex);
	SS7_FUNC_TRACE_EXIT(__FUNCTION__);
	return FTDM_SUCCESS;
}

/******************************************************************************/
ftdm_status_t handle_dat_ind(uint32_t suInstId, uint32_t spInstId, uint32_t circuit, SiInfoEvnt *siInfoEvnt)
{
	SS7_FUNC_TRACE_ENTER(__FUNCTION__);
	
	sngss7_chan_data_t  *sngss7_info ;
	ftdm_channel_t	  *ftdmchan;
	
	ftdm_running_return(FTDM_FAIL);
	if (extract_chan_data(circuit, &sngss7_info, &ftdmchan)) {
		SS7_ERROR("Failed to extract channel data for circuit = %d!\n", circuit);
		SS7_FUNC_TRACE_EXIT(__FUNCTION__);
		return FTDM_FAIL;
	}
	ftdm_mutex_lock(ftdmchan->mutex);

	SS7_INFO_CHAN(ftdmchan,"[CIC:%d]Rx DATA IND\n", sngss7_info->circuit->cic);
	ftdm_mutex_unlock(ftdmchan->mutex);

	SS7_FUNC_TRACE_EXIT(__FUNCTION__);
	return FTDM_SUCCESS;
}

/******************************************************************************/
ftdm_status_t handle_fac_ind(uint32_t suInstId, uint32_t spInstId, uint32_t circuit, uint8_t evntType, SiFacEvnt *siFacEvnt)
{
	SS7_FUNC_TRACE_ENTER(__FUNCTION__);
	
	sngss7_chan_data_t  *sngss7_info ;
	ftdm_channel_t	  *ftdmchan;
	
	ftdm_running_return(FTDM_FAIL);
	if (extract_chan_data(circuit, &sngss7_info, &ftdmchan)) {
		SS7_ERROR("Failed to extract channel data for circuit = %d!\n", circuit);
		SS7_FUNC_TRACE_EXIT(__FUNCTION__);
		return FTDM_FAIL;
	}
	ftdm_mutex_lock(ftdmchan->mutex);
	SS7_INFO_CHAN(ftdmchan,"[CIC:%d]Rx FAC\n", sngss7_info->circuit->cic);
	ftdm_mutex_unlock(ftdmchan->mutex);
	SS7_FUNC_TRACE_EXIT(__FUNCTION__);
	return FTDM_SUCCESS;
}

/******************************************************************************/
ftdm_status_t handle_fac_cfm(uint32_t suInstId, uint32_t spInstId, uint32_t circuit, uint8_t evntType, SiFacEvnt *siFacEvnt)
{
	SS7_FUNC_TRACE_ENTER(__FUNCTION__);
	
	sngss7_chan_data_t  *sngss7_info ;
	ftdm_channel_t	  *ftdmchan;
	
	ftdm_running_return(FTDM_FAIL);
	if (extract_chan_data(circuit, &sngss7_info, &ftdmchan)) {
		SS7_ERROR("Failed to extract channel data for circuit = %d!\n", circuit);
		SS7_FUNC_TRACE_EXIT(__FUNCTION__);
		return FTDM_FAIL;
	}
	ftdm_mutex_lock(ftdmchan->mutex);
	SS7_INFO_CHAN(ftdmchan,"[CIC:%d]Rx FAC-CON\n", sngss7_info->circuit->cic);
	ftdm_mutex_unlock(ftdmchan->mutex);
	SS7_FUNC_TRACE_EXIT(__FUNCTION__);
	return FTDM_SUCCESS;
}

/******************************************************************************/
ftdm_status_t handle_umsg_ind(uint32_t suInstId, uint32_t spInstId, uint32_t circuit)
{
	SS7_FUNC_TRACE_ENTER(__FUNCTION__);
	
	sngss7_chan_data_t  *sngss7_info ;
	ftdm_channel_t	  *ftdmchan;
	
	ftdm_running_return(FTDM_FAIL);
	if (extract_chan_data(circuit, &sngss7_info, &ftdmchan)) {
		SS7_ERROR("Failed to extract channel data for circuit = %d!\n", circuit);
		SS7_FUNC_TRACE_EXIT(__FUNCTION__);
		return FTDM_FAIL;
	}
	ftdm_mutex_lock(ftdmchan->mutex);
	SS7_INFO_CHAN(ftdmchan,"[CIC:%d]Rx USER-USER msg\n", sngss7_info->circuit->cic);
	ftdm_mutex_unlock(ftdmchan->mutex);
	SS7_FUNC_TRACE_EXIT(__FUNCTION__);
	return FTDM_SUCCESS;
}

/******************************************************************************/
ftdm_status_t handle_susp_ind(uint32_t suInstId, uint32_t spInstId, uint32_t circuit, SiSuspEvnt *siSuspEvnt)
{
	SS7_FUNC_TRACE_ENTER(__FUNCTION__);
	
	sngss7_chan_data_t  *sngss7_info ;
	ftdm_channel_t	  *ftdmchan;
	
	ftdm_running_return(FTDM_FAIL);
	if (extract_chan_data(circuit, &sngss7_info, &ftdmchan)) {
		SS7_ERROR("Failed to extract channel data for circuit = %d!\n", circuit);
		SS7_FUNC_TRACE_EXIT(__FUNCTION__);
		return FTDM_FAIL;
	}

	ftdm_mutex_lock(ftdmchan->mutex);
	SS7_INFO_CHAN(ftdmchan,"[CIC:%d]Rx Call-Suspend msg\n", sngss7_info->circuit->cic);
	ftdm_mutex_unlock(ftdmchan->mutex);
	SS7_FUNC_TRACE_EXIT(__FUNCTION__);
	return FTDM_SUCCESS;
}

/******************************************************************************/
ftdm_status_t handle_resm_ind(uint32_t suInstId, uint32_t spInstId, uint32_t circuit, SiResmEvnt *siResmEvnt)
{
	SS7_FUNC_TRACE_ENTER(__FUNCTION__);
	
	sngss7_chan_data_t  *sngss7_info ;
	ftdm_channel_t	  *ftdmchan;
	
	ftdm_running_return(FTDM_FAIL);
	if (extract_chan_data(circuit, &sngss7_info, &ftdmchan)) {
		SS7_ERROR("Failed to extract channel data for circuit = %d!\n", circuit);
		SS7_FUNC_TRACE_EXIT(__FUNCTION__);
		return FTDM_FAIL;
	}
	ftdm_mutex_lock(ftdmchan->mutex);
	SS7_INFO_CHAN(ftdmchan,"[CIC:%d]Rx Call-Resume msg\n", sngss7_info->circuit->cic);
	ftdm_mutex_unlock(ftdmchan->mutex);
	SS7_FUNC_TRACE_EXIT(__FUNCTION__);
	return FTDM_SUCCESS;
}

/******************************************************************************/
ftdm_status_t handle_sta_ind(uint32_t suInstId, uint32_t spInstId, uint32_t circuit, uint8_t globalFlg, uint8_t evntType, SiStaEvnt *siStaEvnt)
{
	SS7_FUNC_TRACE_ENTER(__FUNCTION__);
	
	ftdm_running_return(FTDM_FAIL);
	if (!sngss7_test_flag(&g_ftdm_sngss7_data.cfg.isupCkt[circuit], SNGSS7_ACTIVE)) {
		SS7_ERROR("[CIC:%d]Rx %s but circuit is not active yet, skipping!\n",
					g_ftdm_sngss7_data.cfg.isupCkt[circuit].cic,
					DECODE_LCC_EVENT(evntType));
		return FTDM_FAIL;
	}

	switch (evntType) {
	case SIT_STA_REATTEMPT:		 /* reattempt indication */
		handle_reattempt(suInstId, spInstId, circuit, globalFlg, evntType, siStaEvnt);
		break;

	case SIT_STA_ERRORIND:		  /* error indication */
		SS7_WARN(" %s indication not currently supported\n", DECODE_LCC_EVENT(evntType));
		break;

	case SIT_STA_CONTCHK:		   /* continuity check */
		handle_cot_start(suInstId, spInstId, circuit, globalFlg, evntType, siStaEvnt);
		break;

	case SIT_STA_CONTREP:		   /* continuity report */
		handle_cot(suInstId, spInstId, circuit, globalFlg, evntType, siStaEvnt);
		break;

	case SIT_STA_STPCONTIN:		 /* stop continuity */
		handle_cot_stop(suInstId, spInstId, circuit, globalFlg, evntType, siStaEvnt);
		break;

	case SIT_STA_CGQRYRSP:		  /* circuit grp query response from far end forwarded to upper layer by ISUP */
		SS7_WARN(" %s indication not currently supported\n", DECODE_LCC_EVENT(evntType));
		break;

	case SIT_STA_CONFUSION:		 /* confusion */
		SS7_WARN(" %s indication not currently supported\n", DECODE_LCC_EVENT(evntType));
		break;

	case SIT_STA_LOOPBACKACK:	   /* loop-back acknowledge */
		SS7_WARN(" %s indication not currently supported\n", DECODE_LCC_EVENT(evntType));
		break;

	case SIT_STA_CIRRSRVREQ:		/* circuit reservation request */
		SS7_WARN(" %s indication not currently supported\n", DECODE_LCC_EVENT(evntType));
		break;

	case SIT_STA_CIRRSRVACK:		/* circuit reservation acknowledgement */
		SS7_WARN(" %s indication not currently supported\n", DECODE_LCC_EVENT(evntType));
		break;

	case SIT_STA_CIRBLOREQ:		 /* circuit blocking request */
		handle_blo_req(suInstId, spInstId, circuit, globalFlg, evntType, siStaEvnt);
		break;

	case SIT_STA_CIRBLORSP:		 /* circuit blocking response   */
		handle_blo_rsp(suInstId, spInstId, circuit, globalFlg, evntType, siStaEvnt);
		break;

	case SIT_STA_CIRUBLREQ:		 /* circuit unblocking request */
		handle_ubl_req(suInstId, spInstId, circuit, globalFlg, evntType, siStaEvnt);
		break;

	case SIT_STA_CIRUBLRSP:		 /* circuit unblocking response */
		handle_ubl_rsp(suInstId, spInstId, circuit, globalFlg, evntType, siStaEvnt);
		break;

	case SIT_STA_CIRRESREQ:		 /* circuit reset request - RSC */
		handle_rsc_req(suInstId, spInstId, circuit, globalFlg, evntType, siStaEvnt);
		break;

	case SIT_STA_CIRLOCRES:		 /* reset initiated locally by the software */
		handle_local_rsc_req(suInstId, spInstId, circuit, globalFlg, evntType, siStaEvnt);
		break;

	case SIT_STA_CIRRESRSP:		 /* circuit reset response */
		handle_rsc_rsp(suInstId, spInstId, circuit, globalFlg, evntType, siStaEvnt);
		break;

	case SIT_STA_CGBREQ:			/* CGB request */
		handle_cgb_req(suInstId, spInstId, circuit, globalFlg, evntType, siStaEvnt);
		break;

	case SIT_STA_CGUREQ:			/* CGU request */
		handle_cgu_req(suInstId, spInstId, circuit, globalFlg, evntType, siStaEvnt);
		break;

	case SIT_STA_CGQRYREQ:		  /* circuit group query request */
		SS7_WARN(" %s indication not currently supported\n", DECODE_LCC_EVENT(evntType));
		break;

	case SIT_STA_CGBRSP:			/* mntc. oriented CGB response */
		SS7_INFO(" Rx CGBA \n");
		break;

	case SIT_STA_CGURSP:			/* mntc. oriented CGU response */
		/*SS7_WARN(" %s indication not currently supported\n", DECODE_LCC_EVENT(evntType));*/
		SS7_INFO(" Rx CGUA \n");
		break;

	case SIT_STA_GRSREQ:			/* circuit group reset request */
		handle_grs_req(suInstId, spInstId, circuit, globalFlg, evntType, siStaEvnt);
		break;

	case SIT_STA_CIRUNEQPD:		 /* circuit unequipped indication */
		handle_ucic(suInstId, spInstId, circuit, globalFlg, evntType, siStaEvnt);
		break;

	case SIT_STA_GRSRSP:			/* circuit group reset response */
		handle_grs_rsp(suInstId, spInstId, circuit, globalFlg, evntType, siStaEvnt);
		break;

	case SIT_STA_PAUSEIND:		  /* pause indication */
		handle_pause(suInstId, spInstId, circuit, globalFlg, evntType, siStaEvnt);
		break;

	case SIT_STA_RESUMEIND:		 /* resume indication */
		handle_resume(suInstId, spInstId, circuit, globalFlg, evntType, siStaEvnt);
		break;

	case SIT_STA_USRPARTA:		  /* user part available */
		SS7_WARN(" %s indication not currently supported\n", DECODE_LCC_EVENT(evntType));
		break;

	case SIT_STA_RMTUSRUNAV:		/* remote user not available */
		SS7_WARN(" %s indication not currently supported\n", DECODE_LCC_EVENT(evntType));
		break;

	case SIT_STA_MTPCONG0:		  /* congestion indication level 0 */
		SS7_WARN(" %s level 1 received. Setting circuit = %d, globalFlg = %d\n", DECODE_LCC_EVENT(evntType), circuit, globalFlg);
		break;

	case SIT_STA_MTPCONG1:		  /* congestion indication level 1 */
		SS7_WARN(" %s indication not currently supported. circuit = %d, globalFlg = %d\n", DECODE_LCC_EVENT(evntType), circuit, globalFlg);
		break;

	case SIT_STA_MTPCONG2:		  /* congestion indication level 2 */
		SS7_WARN(" %s indication not currently supported. circuit = %d, globalFlg = %d\n", DECODE_LCC_EVENT(evntType), circuit, globalFlg);
		break;

	case SIT_STA_MTPCONG3:		  /* congestion indication level 3 */
		SS7_WARN(" %s indication not currently supported. circuit = %d, globalFlg = %d\n", DECODE_LCC_EVENT(evntType), circuit, globalFlg);
		break;

	case SIT_STA_MTPSTPCONG:		/* stop congestion indication level 0 */
		SS7_WARN(" %s indication not currently supported. circuit = %d, globalFlg = %d\n", DECODE_LCC_EVENT(evntType), circuit, globalFlg);
		break; 

	case SIT_STA_CIRLOCALBLOIND:	/* Mngmt local blocking */
		handle_local_blk(suInstId, spInstId, circuit, globalFlg, evntType, siStaEvnt);
		break;

	case SIT_STA_CIRLOCALUBLIND:	/* Mngmt local unblocking */
		handle_local_ubl(suInstId, spInstId, circuit, globalFlg, evntType, siStaEvnt);
		break;

	case SIT_STA_OVERLOAD:		  /* Overload */
		handle_olm_msg(suInstId, spInstId, circuit, globalFlg, evntType, siStaEvnt);
		break;

	case SIT_STA_LMCGBREQ:		  /* when LM requests ckt grp blocking */
		SS7_WARN(" %s indication not currently supported\n", DECODE_LCC_EVENT(evntType));
		break;

	case SIT_STA_LMCGUREQ:		  /* when LM requests ckt grp unblocking */
		SS7_WARN(" %s indication not currently supported\n", DECODE_LCC_EVENT(evntType));
		break;

	case SIT_STA_LMGRSREQ:		  /* when LM requests ckt grp reset */
		SS7_WARN(" %s indication not currently supported\n", DECODE_LCC_EVENT(evntType));
		break;

	case SIT_STA_CGBINFOIND:		/* circuit grp blking ind , no resp req */
/*		handle_cgb_req(suInstId, spInstId, circuit, globalFlg, evntType, siStaEvnt);*/
		break;

	case SIT_STA_LMCQMINFOREQ:	  /* when LM requests ckt grp query */
// 		SS7_WARN(" %s indication not currently supported\n", DECODE_LCC_EVENT(evntType));
		break;

	case SIT_STA_CIRLOCGRS:		 /* group reset initiated locally by the software */
		SS7_WARN(" %s indication not currently supported\n", DECODE_LCC_EVENT(evntType));
		break;

	default:
		SS7_INFO("[SNG-CC] Received Unknown indication %d\n", evntType);
		break;
	}

	SS7_FUNC_TRACE_EXIT(__FUNCTION__);
	return FTDM_SUCCESS;

}

/******************************************************************************/
ftdm_status_t handle_reattempt(uint32_t suInstId, uint32_t spInstId, uint32_t circuit, uint8_t globalFlg, uint8_t evntType, SiStaEvnt *siStaEvnt)
{
	SS7_FUNC_TRACE_ENTER(__FUNCTION__);

	sngss7_chan_data_t  *sngss7_info = NULL;
	ftdm_channel_t	  *ftdmchan = NULL;
	
	ftdm_running_return(FTDM_FAIL);
	if (g_ftdm_sngss7_data.cfg.isupCkt[circuit].type != SNG_CKT_VOICE) {
		SS7_ERROR("[CIC:%d]Rx %s on non-voice CIC\n", g_ftdm_sngss7_data.cfg.isupCkt[circuit].cic, DECODE_LCC_EVENT(evntType));
		SS7_FUNC_TRACE_EXIT(__FUNCTION__);
		return FTDM_FAIL;
	}

	if (extract_chan_data(circuit, &sngss7_info, &ftdmchan)) {
		SS7_ERROR("Failed to extract channel data for ISUP circuit = %d!\n", circuit);
		SS7_FUNC_TRACE_EXIT(__FUNCTION__);
		return FTDM_FAIL;
	}

	SS7_INFO_CHAN(ftdmchan, "[CIC:%d]Rx %s\n", g_ftdm_sngss7_data.cfg.isupCkt[circuit].cic, DECODE_LCC_EVENT(evntType));
	ftdm_mutex_lock(ftdmchan->mutex);

	if (g_ftdm_sngss7_data.cfg.sng_acc) {
		/* Reject the call if self exchange is congested */
		if (siStaEvnt->causeDgn.causeVal.val == SIT_CCSWTCHCONG) {
			/* hangup the call if the circuit is in congested state */
			/*ftdmchan->caller_data.hangup_cause = FTDM_CAUSE_SWITCH_CONGESTION;*/
			ftdmchan->caller_data.hangup_cause = FTDM_CAUSE_NORMAL_CIRCUIT_CONGESTION;
			/* set flag to indicate this hangup is started due to congestion */
			sngss7_set_call_flag (sngss7_info, FLAG_CONG_REL);
			if (ftdm_queue_enqueue(sngss7_reject_queue.sngss7_call_rej_queue, ftdmchan)) {
				SS7_DEBUG_CHAN(ftdmchan, "Hanging up call due to Local Congestion! and Call reject queue is full!%s\n", "");
				ftdm_set_state(ftdmchan, FTDM_CHANNEL_STATE_HANGUP);
			}
		}
	} else if (sngss7_test_ckt_flag(sngss7_info, FLAG_GLARE)) {
		/* the glare flag is already up so it was caught ... do nothing */
		SS7_DEBUG_CHAN(ftdmchan, "Glare flag is already up...nothing to do!%s\n", " ");
	} else {
		int bHangup = 0;
		SS7_DEBUG_CHAN(ftdmchan, "Glare flag is not up yet...indicating glare from reattempt!%s\n", " ");
		/* glare, throw the flag */
		sngss7_set_ckt_flag(sngss7_info, FLAG_GLARE);

		/* clear any existing glare data from the channel */
		memset(&sngss7_info->glare, 0x0, sizeof(sngss7_glare_data_t));

		if (g_ftdm_sngss7_data.cfg.glareResolution == SNGSS7_GLARE_DOWN) {
			/* If I'm in DOWN mode, I will always hangup my call. */
			bHangup = 1;
		} else if (g_ftdm_sngss7_data.cfg.glareResolution == SNGSS7_GLARE_PC) {
			/* I'm in PointCode mode. 
				Case 1: My point code is higher than the other side. 
						If the CIC number is even, I'm trying to control. 
						If the CIC number is odd, I'll hangup my call and back off.
				Case 2: My point code is lower than the other side. 
						If the CIC number is odd, I'm trying to control. 
						If the CIC number is even, I'll hangup my call and back off.
			*/
			if( g_ftdm_sngss7_data.cfg.isupIntf[sngss7_info->circuit->infId].spc > g_ftdm_sngss7_data.cfg.isupIntf[sngss7_info->circuit->infId].dpc ) 
			{
				if ((sngss7_info->circuit->cic % 2) == 1 ) {
					bHangup = 1;
				}
			} else {
				if( (sngss7_info->circuit->cic % 2) == 0 ) {
					bHangup = 1;
				}
			}
		} else {	
			/* If I'm in CONTROL mode, I will not hangup my call. */
			bHangup = 0;
		}

		if (bHangup) {
			/* setup the hangup cause */
			ftdmchan->caller_data.hangup_cause = 34;	/* SIT_CCNOCIRCUIT - no circuit/channel available */

			/* move the state of the channel to Terminating to end the call 
			     in TERMINATING state, the release cause is set to REMOTE_REL 
			     in any means. So we don't have to set the release reason here.
			*/
			ftdm_set_state(ftdmchan, FTDM_CHANNEL_STATE_TERMINATING);
		}
	}

	ftdm_mutex_unlock(ftdmchan->mutex);
	SS7_FUNC_TRACE_EXIT(__FUNCTION__);
	return FTDM_SUCCESS;
}

/******************************************************************************/
ftdm_status_t handle_pause(uint32_t suInstId, uint32_t spInstId, uint32_t circuit, uint8_t globalFlg, uint8_t evntType, SiStaEvnt *siStaEvnt)
{
	SS7_FUNC_TRACE_ENTER(__FUNCTION__);
	
	sngss7_chan_data_t	*sngss7_info = NULL;
	ftdm_channel_t		*ftdmchan = NULL;
	int					infId;
	int					i;
	int					idx = 0;
	
	ftdm_running_return(FTDM_FAIL);
	infId = g_ftdm_sngss7_data.cfg.isupCkt[circuit].infId;

	/* set the interface to paused */
	sngss7_set_flag(&g_ftdm_sngss7_data.cfg.isupIntf[infId], SNGSS7_PAUSED);
	
	/* go through all the circuits now and find any other circuits on this infId */
	i = ftmod_ss7_get_circuit_start_range(g_ftdm_sngss7_data.cfg.procId);

	for (idx = 1; idx < MAX_ISUP_INFS; idx++) {
		if (g_ftdm_sngss7_data.cfg.isupCc[idx].span_id) {
			i = g_ftdm_sngss7_data.cfg.isupCc[idx].ckt_start_val;
		} else {
			continue;
		}

		while ((g_ftdm_sngss7_data.cfg.isupCkt[i].id != 0) &&
			(g_ftdm_sngss7_data.cfg.isupCc[idx].span_id == g_ftdm_sngss7_data.cfg.isupCkt[i].span))  {

			/* check that the infId matches and that this is not a siglink */
			if ((g_ftdm_sngss7_data.cfg.isupCkt[i].infId == infId) &&
				(g_ftdm_sngss7_data.cfg.isupCkt[i].type == SNG_CKT_VOICE)) {

				/* confirm that the circuit is active on our side otherwise move to the next circuit */
				if (!sngss7_test_flag(&g_ftdm_sngss7_data.cfg.isupCkt[i], SNGSS7_ACTIVE)) {
					SS7_ERROR("[CIC:%d]Circuit is not active yet, skipping!\n",g_ftdm_sngss7_data.cfg.isupCkt[i].cic);
					i++;
					continue;
				}

				/* get the ftdmchan and ss7_chan_data from the circuit */
				if (extract_chan_data(i, &sngss7_info, &ftdmchan)) {
					SS7_ERROR("Failed to extract channel data for circuit = %d!\n", circuit);
					i++;
					continue;
				}

#if 0
				/* Temp fix did for BT to answer sip client as soon as ss7 link went down */
#ifdef SS7_UK
				/* If recieved PAUSE indication for channel on which it call is in progress then change channel state to UP */
				if ((FTDM_CHANNEL_STATE_RINGING == ftdmchan->state ) ||
						(ftdmchan->state == FTDM_CHANNEL_STATE_PROGRESS_MEDIA)) {
					ftdm_set_state(ftdmchan, FTDM_CHANNEL_STATE_UP);
					SS7_DEBUG("Changing span[%d] channel[%d] state to UP as call is in progress\n", ftdmchan->span_id, ftdmchan->chan_id);
				}
#endif
#endif

				/* lock the channel */
				ftdm_mutex_lock(ftdmchan->mutex);

				/* check if the circuit is fully started */
				if (ftdm_test_flag(ftdmchan->span, FTDM_SPAN_IN_THREAD)) {
					SS7_DEBUG_CHAN(ftdmchan, "Rx PAUSE%s\n", "");
					/* set the pause flag on the channel */
					sngss7_set_ckt_flag(sngss7_info, FLAG_INFID_PAUSED);

					/* clear the resume flag on the channel */
					sngss7_clear_ckt_flag(sngss7_info, FLAG_INFID_RESUME);
				}

				/* unlock the channel again before we exit */
				ftdm_mutex_unlock(ftdmchan->mutex);

			}

			i++;
		}
	}

	SS7_FUNC_TRACE_EXIT(__FUNCTION__);
	return FTDM_SUCCESS;
}

/******************************************************************************/
ftdm_status_t handle_resume(uint32_t suInstId, uint32_t spInstId, uint32_t circuit, uint8_t globalFlg, uint8_t evntType, SiStaEvnt *siStaEvnt)
{
	SS7_FUNC_TRACE_ENTER(__FUNCTION__);

	sngss7_chan_data_t	*sngss7_info = NULL;
	ftdm_channel_t		*ftdmchan = NULL;
	int					infId;
	int					i;
	int					idx = 0;
	
	ftdm_running_return(FTDM_FAIL);

	/* extract the affect infId from the circuit structure */
	infId = g_ftdm_sngss7_data.cfg.isupCkt[circuit].infId;

	/* set the interface to resumed */
	sngss7_clear_flag(&g_ftdm_sngss7_data.cfg.isupIntf[infId], SNGSS7_PAUSED);

	/* go through all the circuits now and find any other circuits on this infId */
	i = ftmod_ss7_get_circuit_start_range(g_ftdm_sngss7_data.cfg.procId);

	for (idx = 1; idx < MAX_ISUP_INFS; idx++) {
		if (g_ftdm_sngss7_data.cfg.isupCc[idx].span_id) {
			i = g_ftdm_sngss7_data.cfg.isupCc[idx].ckt_start_val;
		} else {
			continue;
		}

		while ((g_ftdm_sngss7_data.cfg.isupCkt[i].id != 0) &&
		       (g_ftdm_sngss7_data.cfg.isupCc[idx].span_id == g_ftdm_sngss7_data.cfg.isupCkt[i].span))  {

			/* check that the infId matches and that this is not a siglink */
			if ((g_ftdm_sngss7_data.cfg.isupCkt[i].infId == infId) &&
				(g_ftdm_sngss7_data.cfg.isupCkt[i].type == SNG_CKT_VOICE)) {

				/* confirm that the circuit is active on our side otherwise move to the next circuit */
				if (!sngss7_test_flag(&g_ftdm_sngss7_data.cfg.isupCkt[i], SNGSS7_ACTIVE)) {
					ftdm_log(FTDM_LOG_DEBUG, "[CIC:%d]Circuit is not active yet, skipping!\n",g_ftdm_sngss7_data.cfg.isupCkt[i].cic);
					i++;
					continue;
				}

				/* get the ftdmchan and ss7_chan_data from the circuit */
				if (extract_chan_data(i, &sngss7_info, &ftdmchan)) {
					SS7_ERROR("Failed to extract channel data for circuit = %d!\n", circuit);
					i++;
					continue;
				}

				/* lock the channel */
				ftdm_mutex_lock(ftdmchan->mutex);

				/* only resume if we are paused */
				if (sngss7_test_ckt_flag(sngss7_info, FLAG_INFID_PAUSED)) {
					SS7_DEBUG_CHAN(ftdmchan, "Rx RESUME%s\n", "");

					/* set the resume flag on the channel */
					sngss7_set_ckt_flag(sngss7_info, FLAG_INFID_RESUME);

					/* clear the paused flag */
					sngss7_clear_ckt_flag(sngss7_info, FLAG_INFID_PAUSED);
				}

				ftdm_mutex_unlock(ftdmchan->mutex);
			}
			i++;
		}
	}

	SS7_FUNC_TRACE_EXIT(__FUNCTION__);
	return FTDM_SUCCESS;
}

/******************************************************************************/
ftdm_status_t handle_cot_start(uint32_t suInstId, uint32_t spInstId, uint32_t circuit, uint8_t globalFlg, uint8_t evntType, SiStaEvnt *siStaEvnt)
{
	SS7_FUNC_TRACE_ENTER(__FUNCTION__);

	sngss7_chan_data_t  *sngss7_info = NULL;
	ftdm_channel_t	  *ftdmchan = NULL;
	
	ftdm_running_return(FTDM_FAIL);
	if (g_ftdm_sngss7_data.cfg.isupCkt[circuit].type != SNG_CKT_VOICE) {
		SS7_ERROR("[CIC:%d]Rx %s on non-voice CIC\n",
					g_ftdm_sngss7_data.cfg.isupCkt[circuit].cic,
					DECODE_LCC_EVENT(evntType));

		SS7_FUNC_TRACE_EXIT(__FUNCTION__);
		return FTDM_FAIL;
	} 

	if (extract_chan_data(circuit, &sngss7_info, &ftdmchan)) {
		SS7_ERROR("Failed to extract channel data for ISUP circuit = %d!\n", circuit);
		SS7_FUNC_TRACE_EXIT(__FUNCTION__);
		return FTDM_FAIL;
	}
	SS7_INFO_CHAN(ftdmchan, "[CIC:%d]Rx %s\n", g_ftdm_sngss7_data.cfg.isupCkt[circuit].cic, DECODE_LCC_EVENT(evntType));
	ftdm_mutex_lock(ftdmchan->mutex);

	/* open the channel if it is not open */
	if (!ftdm_test_flag(ftdmchan, FTDM_CHANNEL_OPEN)) {
		if (ftdm_channel_open_chan(ftdmchan) != FTDM_SUCCESS) {
			SS7_ERROR("Failed to open CIC %d for CCR test!\n", sngss7_info->circuit->cic);
			SS7_FUNC_TRACE_EXIT(__FUNCTION__);
			return FTDM_FAIL;
		}
	}
	/* tell the core to loop the channel */
	ftdm_channel_command(ftdmchan, FTDM_COMMAND_ENABLE_LOOP, NULL);

	/* switch to the IN_LOOP state */
	ftdm_set_state(ftdmchan, FTDM_CHANNEL_STATE_IN_LOOP);

	ftdm_mutex_unlock(ftdmchan->mutex);
	SS7_FUNC_TRACE_EXIT(__FUNCTION__);
	return FTDM_SUCCESS;
}

/******************************************************************************/
ftdm_status_t handle_cot_stop(uint32_t suInstId, uint32_t spInstId, uint32_t circuit, uint8_t globalFlg, uint8_t evntType, SiStaEvnt *siStaEvnt)
{
	SS7_FUNC_TRACE_ENTER(__FUNCTION__);

	sngss7_chan_data_t  *sngss7_info = NULL;
	ftdm_channel_t	  *ftdmchan = NULL;
	
	ftdm_running_return(FTDM_FAIL);
	if (g_ftdm_sngss7_data.cfg.isupCkt[circuit].type != SNG_CKT_VOICE) {
		SS7_ERROR("[CIC:%d]Rx %s on non-voice CIC\n",
					g_ftdm_sngss7_data.cfg.isupCkt[circuit].cic,
					DECODE_LCC_EVENT(evntType));

		SS7_FUNC_TRACE_EXIT(__FUNCTION__);
		return FTDM_FAIL;
	}
	if (extract_chan_data(circuit, &sngss7_info, &ftdmchan)) {
		SS7_ERROR("Failed to extract channel data for ISUP circuit = %d!\n", circuit);
		SS7_FUNC_TRACE_EXIT(__FUNCTION__);
		return FTDM_FAIL;
	}

	SS7_INFO_CHAN(ftdmchan, "[CIC:%d]Rx %s\n", g_ftdm_sngss7_data.cfg.isupCkt[circuit].cic, DECODE_LCC_EVENT(evntType));


	ftdm_mutex_lock(ftdmchan->mutex);
	
	/* tell the core to stop looping the channel */
	ftdm_channel_command(ftdmchan, FTDM_COMMAND_DISABLE_LOOP, NULL);

	/* exit out of the LOOP state to the last state */
	ftdm_set_state(ftdmchan, ftdmchan->last_state);

	ftdm_mutex_unlock(ftdmchan->mutex);
	SS7_FUNC_TRACE_EXIT(__FUNCTION__);
	return FTDM_SUCCESS;
}

/******************************************************************************/
ftdm_status_t handle_cot(uint32_t suInstId, uint32_t spInstId, uint32_t circuit, uint8_t globalFlg, uint8_t evntType, SiStaEvnt *siStaEvnt)
{
	SS7_FUNC_TRACE_ENTER(__FUNCTION__);

	sngss7_chan_data_t  *sngss7_info = NULL;
	ftdm_channel_t	  *ftdmchan = NULL;
	
	ftdm_running_return(FTDM_FAIL);

	/* confirm that the circuit is voice channel */
	if (g_ftdm_sngss7_data.cfg.isupCkt[circuit].type != SNG_CKT_VOICE) {
		SS7_ERROR("[CIC:%d]Rx %s on non-voice CIC\n",
					g_ftdm_sngss7_data.cfg.isupCkt[circuit].cic,
					DECODE_LCC_EVENT(evntType));

		SS7_FUNC_TRACE_EXIT(__FUNCTION__);
		return FTDM_FAIL;
	} 

	if (extract_chan_data(circuit, &sngss7_info, &ftdmchan)) {
		SS7_ERROR("Failed to extract channel data for ISUP circuit = %d!\n", circuit);
		SS7_FUNC_TRACE_EXIT(__FUNCTION__);
		return FTDM_FAIL;
	}

	SS7_INFO_CHAN(ftdmchan, "[CIC:%d]Rx %s\n", g_ftdm_sngss7_data.cfg.isupCkt[circuit].cic, DECODE_LCC_EVENT(evntType));
	ftdm_mutex_lock(ftdmchan->mutex);

	switch (ftdmchan->state) {
	case (FTDM_CHANNEL_STATE_IN_LOOP):
		/* tell the core to stop looping the channel */
		ftdm_channel_command(ftdmchan, FTDM_COMMAND_DISABLE_LOOP, NULL);
	
		/* exit out of the LOOP state and go to collect */
		ftdm_set_state(ftdmchan, FTDM_CHANNEL_STATE_COLLECT);
		break;

	default:
		/* exit out of the LOOP state to the last state */
		ftdm_set_state(ftdmchan, ftdmchan->last_state);

		break;

	}

	if ( (siStaEvnt->contInd.eh.pres > 0) && (siStaEvnt->contInd.contInd.pres > 0)) {
		SS7_INFO("Continuity Test result for CIC = %d (span %d, chan %d) is: \"%s\"\n",
					g_ftdm_sngss7_data.cfg.isupCkt[circuit].cic,
					g_ftdm_sngss7_data.cfg.isupCkt[circuit].span,
					g_ftdm_sngss7_data.cfg.isupCkt[circuit].chan,
					(siStaEvnt->contInd.contInd.val) ? "PASS" : "FAIL");
	} else {
		SS7_ERROR("Recieved Continuity report containing no results!\n");
	}


	ftdm_mutex_unlock(ftdmchan->mutex);
	SS7_FUNC_TRACE_EXIT(__FUNCTION__);
	return FTDM_SUCCESS;
}

/******************************************************************************/
ftdm_status_t handle_blo_req(uint32_t suInstId, uint32_t spInstId, uint32_t circuit, uint8_t globalFlg, uint8_t evntType, SiStaEvnt *siStaEvnt)
{
	SS7_FUNC_TRACE_ENTER(__FUNCTION__);

	sngss7_chan_data_t  *sngss7_info = NULL;
	ftdm_channel_t	  *ftdmchan = NULL;
	
	ftdm_running_return(FTDM_FAIL);
	if (g_ftdm_sngss7_data.cfg.isupCkt[circuit].type != SNG_CKT_VOICE) {
		SS7_ERROR("[CIC:%d]Rx %s on non-voice CIC\n",
					g_ftdm_sngss7_data.cfg.isupCkt[circuit].cic,
					DECODE_LCC_EVENT(evntType));

		SS7_FUNC_TRACE_EXIT(__FUNCTION__);
		return FTDM_FAIL;
	}

	if (extract_chan_data(circuit, &sngss7_info, &ftdmchan)) {
		SS7_ERROR("Failed to extract channel data for ISUP circuit = %d!\n", circuit);
		SS7_FUNC_TRACE_EXIT(__FUNCTION__);
		return FTDM_FAIL;
	}

	SS7_INFO_CHAN(ftdmchan, "[CIC:%d]Rx %s\n", g_ftdm_sngss7_data.cfg.isupCkt[circuit].cic, DECODE_LCC_EVENT(evntType));

	ftdm_mutex_lock(ftdmchan->mutex);
	if (sngss7_test_ckt_blk_flag(sngss7_info, FLAG_CKT_MN_BLOCK_RX)) {
		SS7_WARN("Received BLO on circuit that is already blocked!\n");
	}

	sngss7_set_ckt_blk_flag(sngss7_info, FLAG_CKT_MN_BLOCK_RX);
	sngss7_clear_ckt_blk_flag(sngss7_info, FLAG_CKT_MN_BLOCK_RX_DN);
	ftdm_set_state(ftdmchan, FTDM_CHANNEL_STATE_SUSPENDED);

	ftdm_mutex_unlock(ftdmchan->mutex);
	SS7_FUNC_TRACE_EXIT(__FUNCTION__);
	return FTDM_SUCCESS;
}

/******************************************************************************/
ftdm_status_t handle_blo_rsp(uint32_t suInstId, uint32_t spInstId, uint32_t circuit, uint8_t globalFlg, uint8_t evntType, SiStaEvnt *siStaEvnt)
{
	SS7_FUNC_TRACE_ENTER(__FUNCTION__);

	sngss7_chan_data_t  *sngss7_info = NULL;
	ftdm_channel_t	  *ftdmchan = NULL;
	
	ftdm_running_return(FTDM_FAIL);
	if (g_ftdm_sngss7_data.cfg.isupCkt[circuit].type != SNG_CKT_VOICE) {
		SS7_ERROR("[CIC:%d]Rx %s on non-voice CIC\n", g_ftdm_sngss7_data.cfg.isupCkt[circuit].cic, 	DECODE_LCC_EVENT(evntType));
		SS7_FUNC_TRACE_EXIT(__FUNCTION__);
		return FTDM_FAIL;
	} 

	if (extract_chan_data(circuit, &sngss7_info, &ftdmchan)) {
		SS7_ERROR("Failed to extract channel data for ISUP circuit = %d!\n", circuit);
		SS7_FUNC_TRACE_EXIT(__FUNCTION__);
		return FTDM_FAIL;
	}
	
	sngss7_clear_cmd_pending_flag(sngss7_info, FLAG_CMD_PENDING_WAIT_FOR_RX_BLA);
	SS7_INFO_CHAN(ftdmchan, "[CIC:%d]Rx %s\n", g_ftdm_sngss7_data.cfg.isupCkt[circuit].cic, DECODE_LCC_EVENT(evntType));
	
	if (sngss7_test_cmd_pending_flag(sngss7_info, FLAG_CMD_PENDING_WAIT_FOR_TX_UBL) ) {
		if (ftdm_sched_timer (sngss7_info->t_tx_ubl_on_rx_bla.sched,
						     "t_tx_ubl_on_rx_bla",
						     sngss7_info->t_tx_ubl_on_rx_bla.beat,
						     sngss7_info->t_tx_ubl_on_rx_bla.callback,
						     &sngss7_info->t_tx_ubl_on_rx_bla,
						     &sngss7_info->t_tx_ubl_on_rx_bla.hb_timer_id)) 
		{
			SS7_ERROR ("Unable to schedule timer of sending UBL after receiving BLA. \n");
		}
		
		SS7_DEBUG_CHAN(ftdmchan, "[CIC:%d]Trigger pending UBL request.\n",	g_ftdm_sngss7_data.cfg.isupCkt[circuit].cic);
		sngss7_clear_cmd_pending_flag(sngss7_info, FLAG_CMD_PENDING_WAIT_FOR_TX_UBL);
	}

	if (sngss7_info->t_waiting_bla.hb_timer_id) {
		ftdm_sched_cancel_timer (sngss7_info->t_waiting_bla.sched, sngss7_info->t_waiting_bla.hb_timer_id);
		SS7_DEBUG_CHAN(ftdmchan, "[CIC:%d]Cancel waiting BLA timer.\n",	g_ftdm_sngss7_data.cfg.isupCkt[circuit].cic);
	}

	SS7_FUNC_TRACE_EXIT(__FUNCTION__);
	return FTDM_SUCCESS;
}

/******************************************************************************/
ftdm_status_t handle_ubl_req(uint32_t suInstId, uint32_t spInstId, uint32_t circuit, uint8_t globalFlg, uint8_t evntType, SiStaEvnt *siStaEvnt)
{
	SS7_FUNC_TRACE_ENTER(__FUNCTION__);

	sngss7_chan_data_t  *sngss7_info = NULL;
	ftdm_channel_t	  *ftdmchan = NULL;
	
	ftdm_running_return(FTDM_FAIL);
	if (g_ftdm_sngss7_data.cfg.isupCkt[circuit].type != SNG_CKT_VOICE) {
		SS7_ERROR("[CIC:%d]Rx %s on non-voice CIC\n",
					g_ftdm_sngss7_data.cfg.isupCkt[circuit].cic,
					DECODE_LCC_EVENT(evntType));

		SS7_FUNC_TRACE_EXIT(__FUNCTION__);
		return FTDM_FAIL;
	} 
	
	if (extract_chan_data(circuit, &sngss7_info, &ftdmchan)) {
		SS7_ERROR("Failed to extract channel data for ISUP circuit = %d!\n", circuit);
		SS7_FUNC_TRACE_EXIT(__FUNCTION__);
		return FTDM_FAIL;
	}

	SS7_INFO_CHAN(ftdmchan, "[CIC:%d]Rx %s\n", g_ftdm_sngss7_data.cfg.isupCkt[circuit].cic, DECODE_LCC_EVENT(evntType));
	
	ftdm_mutex_lock(ftdmchan->mutex);

	/* check if the channel is blocked */
	if (!(sngss7_test_ckt_blk_flag(sngss7_info, FLAG_CKT_MN_BLOCK_RX)) && !sngss7_test_ckt_blk_flag(sngss7_info, FLAG_GRP_MN_BLOCK_RX)) {
		SS7_WARN("Received UBL on circuit that is not blocked! span= %d, chan= %d , flag = %x \n", g_ftdm_sngss7_data.cfg.isupCkt[circuit].span, g_ftdm_sngss7_data.cfg.isupCkt[circuit].chan,sngss7_info->blk_flags  );
	}


	sngss7_set_ckt_blk_flag(sngss7_info, FLAG_CKT_MN_UNBLK_RX);
	sngss7_clear_ckt_blk_flag(sngss7_info, FLAG_CKT_MN_BLOCK_RX);
	sngss7_clear_ckt_blk_flag(sngss7_info, FLAG_GRP_MN_BLOCK_RX);
	sngss7_clear_ckt_blk_flag(sngss7_info, FLAG_GRP_MN_BLOCK_RX_DN);

	ftdm_set_state(ftdmchan, FTDM_CHANNEL_STATE_SUSPENDED);

	ftdm_mutex_unlock(ftdmchan->mutex);
	SS7_FUNC_TRACE_EXIT(__FUNCTION__);
	return FTDM_SUCCESS;
}

/******************************************************************************/
ftdm_status_t handle_ubl_rsp(uint32_t suInstId, uint32_t spInstId, uint32_t circuit, uint8_t globalFlg, uint8_t evntType, SiStaEvnt *siStaEvnt)
{
	SS7_FUNC_TRACE_ENTER(__FUNCTION__);

	sngss7_chan_data_t  *sngss7_info = NULL;
	ftdm_channel_t	  *ftdmchan = NULL;

	ftdm_running_return(FTDM_FAIL);
	if (g_ftdm_sngss7_data.cfg.isupCkt[circuit].type != SNG_CKT_VOICE) {
		SS7_ERROR("[CIC:%d]Rx %s on non-voice CIC\n", g_ftdm_sngss7_data.cfg.isupCkt[circuit].cic, DECODE_LCC_EVENT(evntType));
		SS7_FUNC_TRACE_EXIT(__FUNCTION__);
		return FTDM_FAIL;
	} 
	
	if (extract_chan_data(circuit, &sngss7_info, &ftdmchan)) {
		SS7_ERROR("Failed to extract channel data for ISUP circuit = %d!\n", circuit);
		SS7_FUNC_TRACE_EXIT(__FUNCTION__);
		return FTDM_FAIL;
	}

	SS7_INFO_CHAN(ftdmchan, "[CIC:%d]Rx %s\n", g_ftdm_sngss7_data.cfg.isupCkt[circuit].cic, DECODE_LCC_EVENT(evntType));
	
	if (sngss7_info->t_waiting_uba.hb_timer_id) {
		ftdm_sched_cancel_timer (sngss7_info->t_waiting_uba.sched, sngss7_info->t_waiting_uba.hb_timer_id);
		SS7_DEBUG_CHAN(ftdmchan, "[CIC:%d]Cancel waiting UBA timer.\n",	g_ftdm_sngss7_data.cfg.isupCkt[circuit].cic);
	}
	
	SS7_FUNC_TRACE_EXIT(__FUNCTION__);
	return FTDM_SUCCESS;
}

/******************************************************************************/
ftdm_status_t handle_rsc_req(uint32_t suInstId, uint32_t spInstId, uint32_t circuit, uint8_t globalFlg, uint8_t evntType, SiStaEvnt *siStaEvnt)
{
	SS7_FUNC_TRACE_ENTER(__FUNCTION__);

	sngss7_chan_data_t  *sngss7_info = NULL;
	ftdm_channel_t	  *ftdmchan = NULL;
	
	ftdm_running_return(FTDM_FAIL);
	if (g_ftdm_sngss7_data.cfg.isupCkt[circuit].type != SNG_CKT_VOICE) {
		SS7_ERROR("[CIC:%d]Rx %s on non-voice CIC\n", g_ftdm_sngss7_data.cfg.isupCkt[circuit].cic, DECODE_LCC_EVENT(evntType));
		SS7_FUNC_TRACE_EXIT(__FUNCTION__);
		return FTDM_FAIL;
	} 

	if (extract_chan_data(circuit, &sngss7_info, &ftdmchan)) {
		SS7_ERROR("Failed to extract channel data for ISUP circuit = %d!\n", circuit);
		SS7_FUNC_TRACE_EXIT(__FUNCTION__);
		return FTDM_FAIL;
	}
	SS7_INFO_CHAN(ftdmchan, "[CIC:%d]Rx %s\n", g_ftdm_sngss7_data.cfg.isupCkt[circuit].cic, DECODE_LCC_EVENT(evntType));
	ftdm_mutex_lock(ftdmchan->mutex);

	sngss7_set_ckt_flag(sngss7_info, FLAG_RESET_RX);
	switch (ftdmchan->state) {
	case FTDM_CHANNEL_STATE_RESTART:
		/* go to idle so that we can redo the restart state*/
		ftdm_set_state(ftdmchan, FTDM_CHANNEL_STATE_IDLE);
		break;

	/* If call is active (or in-progress) then ignore RSC 
	 * as it could possible that during the ringing/active call 
	 * state SS7 link might have gone down or come up again..
	 * so ignore RSC as we need to keep call active */
	case FTDM_CHANNEL_STATE_RINGING:
	case FTDM_CHANNEL_STATE_UP:
	case FTDM_CHANNEL_STATE_PROGRESS_MEDIA:
		if (FTDM_FAIL == ftdm_ss7_release_calls()) {
			SS7_INFO_CHAN(ftdmchan, "[CIC:%d]Rx %s when call is up..ignoring..\n", g_ftdm_sngss7_data.cfg.isupCkt[circuit].cic, DECODE_LCC_EVENT(evntType));
			break;
		}
		/* fall down to release the calls */

	default:
		/* set the state of the channel to restart...the rest is done by the chan monitor */
		sngss7_set_ckt_flag(sngss7_info, FLAG_REMOTE_REL);
		ftdm_set_state(ftdmchan, FTDM_CHANNEL_STATE_RESTART);
		break;
	}

	ftdm_mutex_unlock(ftdmchan->mutex);
	SS7_FUNC_TRACE_EXIT(__FUNCTION__);
	return FTDM_SUCCESS;
}

/******************************************************************************/
ftdm_status_t handle_local_rsc_req(uint32_t suInstId, uint32_t spInstId, uint32_t circuit, uint8_t globalFlg, uint8_t evntType, SiStaEvnt *siStaEvnt)
{
	SS7_FUNC_TRACE_ENTER(__FUNCTION__);

	sngss7_chan_data_t  *sngss7_info = NULL;
	ftdm_channel_t	  *ftdmchan = NULL;
	
	ftdm_running_return(FTDM_FAIL);
	if (g_ftdm_sngss7_data.cfg.isupCkt[circuit].type != SNG_CKT_VOICE) {
		SS7_ERROR("[CIC:%d]Rx %s on non-voice CIC\n", g_ftdm_sngss7_data.cfg.isupCkt[circuit].cic, DECODE_LCC_EVENT(evntType));
		SS7_FUNC_TRACE_EXIT(__FUNCTION__);
		return FTDM_FAIL;
	}
	
	if (extract_chan_data(circuit, &sngss7_info, &ftdmchan)) {
		SS7_ERROR("Failed to extract channel data for ISUP circuit = %d!\n", circuit);
		SS7_FUNC_TRACE_EXIT(__FUNCTION__);
		return FTDM_FAIL;
	}

	SS7_INFO_CHAN(ftdmchan, "[CIC:%d]Rx %s\n", g_ftdm_sngss7_data.cfg.isupCkt[circuit].cic, DECODE_LCC_EVENT(evntType));
	ftdm_mutex_lock(ftdmchan->mutex);


	sngss7_set_ckt_flag(sngss7_info, FLAG_RESET_RX);
	switch (ftdmchan->state) {
	case FTDM_CHANNEL_STATE_RESTART:
		/* go to idle so that we can redo the restart state*/
		ftdm_set_state(ftdmchan, FTDM_CHANNEL_STATE_IDLE);
		break;

	default:
		/* set the state of the channel to restart...the rest is done by the chan monitor */
		ftdm_set_state(ftdmchan, FTDM_CHANNEL_STATE_RESTART);
		break;
	}

	ftdm_mutex_unlock(ftdmchan->mutex);
	SS7_FUNC_TRACE_EXIT(__FUNCTION__);
	return FTDM_SUCCESS;
}

/******************************************************************************/
ftdm_status_t handle_rsc_rsp(uint32_t suInstId, uint32_t spInstId, uint32_t circuit, uint8_t globalFlg, uint8_t evntType, SiStaEvnt *siStaEvnt)
{
	SS7_FUNC_TRACE_ENTER(__FUNCTION__);

	sngss7_chan_data_t  *sngss7_info = NULL;
	ftdm_channel_t	  *ftdmchan = NULL;
	
	ftdm_running_return(FTDM_FAIL);
	if (g_ftdm_sngss7_data.cfg.isupCkt[circuit].type != SNG_CKT_VOICE) {
 		SS7_ERROR("[CIC:%d]Rx %s on non-voice CIC\n", g_ftdm_sngss7_data.cfg.isupCkt[circuit].cic, DECODE_LCC_EVENT(evntType));
		SS7_FUNC_TRACE_EXIT(__FUNCTION__);
		return FTDM_FAIL;
	}
	
	if (extract_chan_data(circuit, &sngss7_info, &ftdmchan)) {
		SS7_ERROR("Failed to extract channel data for ISUP circuit = %d!\n", circuit);
		SS7_FUNC_TRACE_EXIT(__FUNCTION__);
		return FTDM_FAIL;
	}

	SS7_INFO_CHAN(ftdmchan, "[CIC:%d]Rx %s\n", g_ftdm_sngss7_data.cfg.isupCkt[circuit].cic, DECODE_LCC_EVENT(evntType));
	
	if (sngss7_info->t_waiting_rsca.hb_timer_id) {
		if (ftdm_sched_cancel_timer (sngss7_info->t_waiting_rsca.sched, sngss7_info->t_waiting_rsca.hb_timer_id)) {
			SS7_ERROR_CHAN(ftdmchan, "[CIC:%d]Unable to Cancel waiting RSCA timer %d!\n",
					g_ftdm_sngss7_data.cfg.isupCkt[circuit].cic, (int)sngss7_info->t_waiting_rsca.hb_timer_id);
		} else {
			SS7_DEBUG_CHAN(ftdmchan, "[CIC:%d]Cancel waiting RSCA timer %d\n",
					g_ftdm_sngss7_data.cfg.isupCkt[circuit].cic, (int)sngss7_info->t_waiting_rsca.hb_timer_id);
			sngss7_info->t_waiting_rsca.hb_timer_id = 0;
		}
	}
	
	ftdm_mutex_lock(ftdmchan->mutex);
	switch (ftdmchan->state) {
	case FTDM_CHANNEL_STATE_RESTART:
		if ( sngss7_test_ckt_flag(sngss7_info, FLAG_RESET_TX) ) {
			/* throw the FLAG_RESET_TX_RSP to indicate we have acknowledgement from the remote side */
			sngss7_set_ckt_flag(sngss7_info, FLAG_RESET_TX_RSP);
			/* go to DOWN */
			ftdm_set_state(ftdmchan, FTDM_CHANNEL_STATE_DOWN);
		} else {
			SS7_ERROR("Received RSC-RLC but we're not waiting on a RSC-RLC on CIC #%d, dropping\n", sngss7_info->circuit->cic);
		}

		break;

	case FTDM_CHANNEL_STATE_DOWN:
		SS7_DEBUG("Receveived RSC-RLC in down state on CIC # %d, dropping\n", sngss7_info->circuit->cic);
		
		break;

	case FTDM_CHANNEL_STATE_TERMINATING:
	case FTDM_CHANNEL_STATE_HANGUP:
	case FTDM_CHANNEL_STATE_HANGUP_COMPLETE:
		/* throw the FLAG_RESET_TX_RSP to indicate we have acknowledgement from the remote side */
		sngss7_set_ckt_flag(sngss7_info, FLAG_RESET_TX_RSP);

		/* go to DOWN */
		ftdm_set_state(ftdmchan, FTDM_CHANNEL_STATE_RESTART);

		break;

	default:
		/* ITU Q764-2.9.5.1.c -> release the circuit */
		if ((siStaEvnt != NULL) &&
			(siStaEvnt->causeDgn.eh.pres ==PRSNT_NODEF) &&
			(siStaEvnt->causeDgn.causeVal.pres == PRSNT_NODEF)) {
			ftdmchan->caller_data.hangup_cause = siStaEvnt->causeDgn.causeVal.val;
		} else {
			ftdmchan->caller_data.hangup_cause = 98;	/* SIT_NOMSGTYPE - Message not compatiable with call state or msg type not existent or not implemented */
		}

		ftdm_set_state(ftdmchan, FTDM_CHANNEL_STATE_TERMINATING);
		break;
	}


	ftdm_mutex_unlock(ftdmchan->mutex);
	SS7_FUNC_TRACE_EXIT(__FUNCTION__);
	return FTDM_SUCCESS;
}
/******************************************************************************/
ftdm_status_t handle_grs_req(uint32_t suInstId, uint32_t spInstId, uint32_t circuit, uint8_t globalFlg, uint8_t evntType, SiStaEvnt *siStaEvnt)
{
	SS7_FUNC_TRACE_ENTER(__FUNCTION__);

	sngss7_chan_data_t *sngss7_info = NULL;
	ftdm_channel_t *ftdmchan = NULL;
	sngss7_span_data_t *sngss7_span = NULL;
	int range = 0;
	
	ftdm_running_return(FTDM_FAIL);
	if (g_ftdm_sngss7_data.cfg.isupCkt[circuit].type != SNG_CKT_VOICE) {
		SS7_ERROR("[CIC:%d]Rx %s on non-voice CIC\n", g_ftdm_sngss7_data.cfg.isupCkt[circuit].cic, DECODE_LCC_EVENT(evntType));
		SS7_FUNC_TRACE_EXIT(__FUNCTION__);
		return FTDM_FAIL;
	}
	
	if (extract_chan_data(circuit, &sngss7_info, &ftdmchan)) {
		SS7_ERROR("Failed to extract channel data for ISUP circuit = %d!\n", circuit);
		SS7_FUNC_TRACE_EXIT(__FUNCTION__);
		return FTDM_FAIL;
	}
	SS7_INFO_CHAN(ftdmchan, "[CIC:%d]Rx %s\n", g_ftdm_sngss7_data.cfg.isupCkt[circuit].cic, DECODE_LCC_EVENT(evntType));

	/* extract the range value from the event structure */
	if ((siStaEvnt->rangStat.eh.pres == PRSNT_NODEF) && (siStaEvnt->rangStat.range.pres == PRSNT_NODEF)) {
		range = siStaEvnt->rangStat.range.val;
	} else {
		SS7_ERROR("Received GRS with no range value on CIC = %d\n", sngss7_info->circuit->cic);
		SS7_FUNC_TRACE_EXIT(__FUNCTION__);
		return FTDM_FAIL;
	}

	/* fill in the span structure for this circuit */
	sngss7_span = ftdmchan->span->signal_data;
	if (sngss7_info->rx_grs.range) {
		SS7_CRITICAL("Cannot handle another GRS on CIC = %d\n", sngss7_info->circuit->cic);
		SS7_FUNC_TRACE_EXIT(__FUNCTION__);
		return FTDM_FAIL;
	}
	sngss7_info->rx_grs.circuit = circuit; 
	sngss7_info->rx_grs.range = range;

	ftdm_set_flag(sngss7_span, SNGSS7_RX_GRS_PENDING);

	SS7_FUNC_TRACE_EXIT(__FUNCTION__);
	return FTDM_SUCCESS;
}

/******************************************************************************/
ftdm_status_t handle_grs_rsp(uint32_t suInstId, uint32_t spInstId, uint32_t circuit, uint8_t globalFlg, uint8_t evntType, SiStaEvnt *siStaEvnt)
{
	SS7_FUNC_TRACE_ENTER(__FUNCTION__);

	sngss7_chan_data_t *sngss7_info = NULL;
	ftdm_channel_t *ftdmchan = NULL;
	sngss7_span_data_t *sngss7_span = NULL; 
	int range = 0;
	
	ftdm_running_return(FTDM_FAIL);
	if (g_ftdm_sngss7_data.cfg.isupCkt[circuit].type != SNG_CKT_VOICE) {
		SS7_ERROR("[CIC:%d]Rx %s on non-voice CIC\n", g_ftdm_sngss7_data.cfg.isupCkt[circuit].cic, DECODE_LCC_EVENT(evntType));
		SS7_FUNC_TRACE_EXIT(__FUNCTION__);
		return FTDM_FAIL;
	}
	
	if (extract_chan_data(circuit, &sngss7_info, &ftdmchan)) {
		SS7_ERROR("Failed to extract channel data for ISUP circuit = %d!\n", circuit);
		SS7_FUNC_TRACE_EXIT(__FUNCTION__);
		return FTDM_FAIL;
	}

	SS7_INFO_CHAN(ftdmchan, "[CIC:%d]Rx %s\n", g_ftdm_sngss7_data.cfg.isupCkt[circuit].cic, DECODE_LCC_EVENT(evntType));

	/* extract the range value from the event structure */
	if ((siStaEvnt->rangStat.eh.pres == PRSNT_NODEF) && (siStaEvnt->rangStat.range.pres == PRSNT_NODEF)) {
		range = siStaEvnt->rangStat.range.val;
	} else {
		SS7_ERROR("Received GRA with no range value on CIC = %d\n", sngss7_info->circuit->cic);
		SS7_FUNC_TRACE_EXIT(__FUNCTION__);
		return FTDM_FAIL;
	}

	/* fill in the span structure for this circuit */
	sngss7_span = ftdmchan->span->signal_data;
	if (sngss7_info->rx_gra.range) {
		SS7_ERROR("Cannot handle another GRA on CIC = %d\n", sngss7_info->circuit->cic);
		SS7_FUNC_TRACE_EXIT(__FUNCTION__);
		return FTDM_FAIL;
	}
	sngss7_info->rx_gra.circuit = circuit; 
	sngss7_info->rx_gra.range = range;

	/* check if there is a cause value in the GRA */
	if ((siStaEvnt != NULL) &&
		(siStaEvnt->causeDgn.eh.pres == PRSNT_NODEF) &&
		(siStaEvnt->causeDgn.causeVal.pres == PRSNT_NODEF)) {

		sngss7_info->rx_gra.cause = siStaEvnt->causeDgn.causeVal.val;
	}

	ftdm_set_flag(sngss7_span, SNGSS7_RX_GRA_PENDING);

	SS7_FUNC_TRACE_EXIT(__FUNCTION__);
	return FTDM_SUCCESS;
}

/******************************************************************************/
ftdm_status_t handle_local_blk(uint32_t suInstId, uint32_t spInstId, uint32_t circuit, uint8_t globalFlg, uint8_t evntType, SiStaEvnt *siStaEvnt)
{
	SS7_FUNC_TRACE_ENTER(__FUNCTION__);

	sngss7_chan_data_t  *sngss7_info = NULL;
	ftdm_channel_t	  *ftdmchan = NULL;
	
	ftdm_running_return(FTDM_FAIL);

	/* confirm that the circuit is voice channel */
	if (g_ftdm_sngss7_data.cfg.isupCkt[circuit].type != SNG_CKT_VOICE) {
		SS7_ERROR("[CIC:%d]Rx %s on non-voice CIC\n",
					g_ftdm_sngss7_data.cfg.isupCkt[circuit].cic,
					DECODE_LCC_EVENT(evntType));

		SS7_FUNC_TRACE_EXIT(__FUNCTION__);
		return FTDM_FAIL;
	} else {
		/* get the ftdmchan and ss7_chan_data from the circuit */
		if (extract_chan_data(circuit, &sngss7_info, &ftdmchan)) {
			SS7_ERROR("Failed to extract channel data for ISUP circuit = %d!\n", circuit);
			SS7_FUNC_TRACE_EXIT(__FUNCTION__);
			return FTDM_FAIL;
		}

		SS7_INFO_CHAN(ftdmchan, "[CIC:%d]Rx %s\n",
			g_ftdm_sngss7_data.cfg.isupCkt[circuit].cic,
			DECODE_LCC_EVENT(evntType));
	}

	/* lock the channel */
	ftdm_mutex_lock(ftdmchan->mutex);

	/* check if the circuit is already blocked or not */
	if (sngss7_test_ckt_blk_flag(sngss7_info, FLAG_CKT_LC_BLOCK_RX)) {
		SS7_WARN("Received local BLO on circuit that is already blocked!\n");
	}

	/* throw the ckt block flag */
	sngss7_set_ckt_blk_flag(sngss7_info, FLAG_CKT_LC_BLOCK_RX);

	/* set the channel to suspended state */
	ftdm_set_state(ftdmchan, FTDM_CHANNEL_STATE_SUSPENDED);

	/* unlock the channel again before we exit */
	ftdm_mutex_unlock(ftdmchan->mutex);

	SS7_FUNC_TRACE_EXIT(__FUNCTION__);
	return FTDM_SUCCESS;
}

/******************************************************************************/
ftdm_status_t handle_local_ubl(uint32_t suInstId, uint32_t spInstId, uint32_t circuit, uint8_t globalFlg, uint8_t evntType, SiStaEvnt *siStaEvnt)
{
	SS7_FUNC_TRACE_ENTER(__FUNCTION__);

	sngss7_chan_data_t  *sngss7_info = NULL;
	ftdm_channel_t	  *ftdmchan = NULL;
	
	ftdm_running_return(FTDM_FAIL);

	/* confirm that the circuit is voice channel */
	if (g_ftdm_sngss7_data.cfg.isupCkt[circuit].type != SNG_CKT_VOICE) {
		SS7_ERROR("[CIC:%d]Rx %s on non-voice CIC\n",
					g_ftdm_sngss7_data.cfg.isupCkt[circuit].cic,
					DECODE_LCC_EVENT(evntType));

		SS7_FUNC_TRACE_EXIT(__FUNCTION__);
		return FTDM_FAIL;
	} else {
		/* get the ftdmchan and ss7_chan_data from the circuit */
		if (extract_chan_data(circuit, &sngss7_info, &ftdmchan)) {
			SS7_ERROR("Failed to extract channel data for ISUP circuit = %d!\n", circuit);
			SS7_FUNC_TRACE_EXIT(__FUNCTION__);
			return FTDM_FAIL;
		}

		SS7_INFO_CHAN(ftdmchan, "[CIC:%d]Rx %s\n",
			g_ftdm_sngss7_data.cfg.isupCkt[circuit].cic,
			DECODE_LCC_EVENT(evntType));
	}

	/* lock the channel */
	ftdm_mutex_lock(ftdmchan->mutex);

	/* check if the circuit is blocked or not */
	if (!sngss7_test_ckt_blk_flag(sngss7_info, FLAG_CKT_LC_BLOCK_RX)) {
		SS7_WARN("Received local UBL on circuit that is not blocked!\n");
	}

	/* throw the ckt unblock flag */
	sngss7_set_ckt_blk_flag(sngss7_info, FLAG_CKT_LC_UNBLK_RX);

	/* set the channel to suspended state */
	ftdm_set_state(ftdmchan, FTDM_CHANNEL_STATE_SUSPENDED);

	/* unlock the channel again before we exit */
	ftdm_mutex_unlock(ftdmchan->mutex);

	SS7_FUNC_TRACE_EXIT(__FUNCTION__);
	return FTDM_SUCCESS;
}

/******************************************************************************/
ftdm_status_t handle_ucic(uint32_t suInstId, uint32_t spInstId, uint32_t circuit, uint8_t globalFlg, uint8_t evntType, SiStaEvnt *siStaEvnt)
{
	SS7_FUNC_TRACE_ENTER(__FUNCTION__);

	ftdm_iterator_t *iter = NULL;
	ftdm_iterator_t *curr = NULL;
	sngss7_chan_data_t *sngss7_info = NULL;
	sngss7_chan_data_t *cinfo = NULL;
	sngss7_span_data_t *sngss7_span = NULL;
	ftdm_channel_t *ftdmchan = NULL;

	ftdm_running_return(FTDM_FAIL);

	/* confirm that the circuit is voice channel */
	if (g_ftdm_sngss7_data.cfg.isupCkt[circuit].type != SNG_CKT_VOICE) {
		SS7_ERROR("[CIC:%d]Rx %s on non-voice CIC\n",
					g_ftdm_sngss7_data.cfg.isupCkt[circuit].cic,
					DECODE_LCC_EVENT(evntType));

		SS7_FUNC_TRACE_EXIT(__FUNCTION__);
		return FTDM_FAIL;
	} else {
		/* get the ftdmchan and ss7_chan_data from the circuit */
		if (extract_chan_data(circuit, &sngss7_info, &ftdmchan)) {
			SS7_ERROR("Failed to extract channel data for ISUP circuit = %d!\n", circuit);
			SS7_FUNC_TRACE_EXIT(__FUNCTION__);
			return FTDM_FAIL;
		}

		SS7_INFO_CHAN(ftdmchan, "[CIC:%d]Rx %s\n",
			g_ftdm_sngss7_data.cfg.isupCkt[circuit].cic,
			DECODE_LCC_EVENT(evntType));
	}

	/* find out if the cic belongs to one of our GRS requests, if so, 
	 * all circuits in the request must be blocked */
	sngss7_span = ftdmchan->span->signal_data;
	iter = ftdm_span_get_chan_iterator(ftdmchan->span, NULL);
	curr = iter;
	for (curr = iter; curr; curr = ftdm_iterator_next(curr)) {
		ftdm_channel_t *fchan = ftdm_iterator_current(curr);

		if (ftdm_test_flag(fchan, FTDM_CHANNEL_OPEN)) {
			continue;
		}

		ftdm_channel_lock(fchan);

		cinfo = fchan->call_data;
		if (circuit == cinfo->tx_grs.circuit) {
			cinfo->ucic.circuit = cinfo->tx_grs.circuit;
			cinfo->ucic.range = cinfo->tx_grs.range;
			ftdm_set_flag(sngss7_span, SNGSS7_UCIC_PENDING);

			SS7_WARN("Set span SNGSS7_UCIC_PENDING for ISUP circuit = %d!\n", circuit);

			ftdm_channel_unlock(fchan);

			goto done;
		}

		ftdm_channel_unlock(fchan);
	}

	/* lock the channel */
	ftdm_mutex_lock(ftdmchan->mutex);

	/* throw the ckt block flag */
	SS7_DEBUG("Set FLAG_CKT_UCIC_BLOCK for ISUP circuit = %d!\n", circuit);
	sngss7_set_ckt_blk_flag(sngss7_info, FLAG_CKT_UCIC_BLOCK);

	/* set the channel to suspended state */
	ftdm_set_state(ftdmchan, FTDM_CHANNEL_STATE_SUSPENDED);

	/* unlock the channel again before we exit */
	ftdm_mutex_unlock(ftdmchan->mutex);
done:
	if (iter) {
		ftdm_iterator_free(iter);
	}

	SS7_FUNC_TRACE_EXIT(__FUNCTION__);
	return FTDM_SUCCESS;
}

/******************************************************************************/
ftdm_status_t handle_cgb_req(uint32_t suInstId, uint32_t spInstId, uint32_t circuit, uint8_t globalFlg, uint8_t evntType, SiStaEvnt *siStaEvnt)
{
	SS7_FUNC_TRACE_ENTER(__FUNCTION__);

	sngss7_chan_data_t	*sngss7_info = NULL;
	sngss7_span_data_t	*sngss7_span = NULL;
	ftdm_channel_t		*ftdmchan = NULL;
	int					range;
	uint8_t				status[255];
	int					blockType = 0;
	int					byte = 0;
	int					bit = 0;
	int 					x;
	int					loop_range=0;

	ftdm_running_return(FTDM_FAIL);

	memset(&status[0], '\0', sizeof(status));

	/* confirm that the circuit is voice channel */
	if (g_ftdm_sngss7_data.cfg.isupCkt[circuit].type != SNG_CKT_VOICE) {
		SS7_ERROR("[CIC:%d]Rx %s on non-voice CIC\n",
					g_ftdm_sngss7_data.cfg.isupCkt[circuit].cic,
					DECODE_LCC_EVENT(evntType));

		SS7_FUNC_TRACE_EXIT(__FUNCTION__);
		return FTDM_FAIL;
	} else {
		/* get the ftdmchan and ss7_chan_data from the circuit */
		if (extract_chan_data(circuit, &sngss7_info, &ftdmchan)) {
			SS7_ERROR("Failed to extract channel data for ISUP circuit = %d!\n", circuit);
			SS7_FUNC_TRACE_EXIT(__FUNCTION__);
			return FTDM_FAIL;
		}

		SS7_INFO_CHAN(ftdmchan, "[CIC:%d]Rx %s\n",
			g_ftdm_sngss7_data.cfg.isupCkt[circuit].cic,
			DECODE_LCC_EVENT(evntType));
	}
	/* grab the span info */
	sngss7_span = ftdmchan->span->signal_data;

	/* figure out what type of block needs to be applied */
	if ((siStaEvnt->cgsmti.eh.pres == PRSNT_NODEF) && (siStaEvnt->cgsmti.typeInd.pres == PRSNT_NODEF)) {
		blockType = siStaEvnt->cgsmti.typeInd.val;
	} else {
		SS7_ERROR("Received CGB with no circuit group supervision value on CIC = %d\n", sngss7_info->circuit->cic);
		SS7_FUNC_TRACE_EXIT(__FUNCTION__);
		return FTDM_FAIL;
	}	

	/* pull out the range value */
	if ((siStaEvnt->rangStat.eh.pres == PRSNT_NODEF) && (siStaEvnt->rangStat.range.pres == PRSNT_NODEF)) {
		range = siStaEvnt->rangStat.range.val;
	} else {
		SS7_ERROR("Received CGB with no range value on CIC = %d\n", sngss7_info->circuit->cic);
		SS7_FUNC_TRACE_EXIT(__FUNCTION__);
		return FTDM_FAIL;
	}

	/* pull out the status field */
	if ((siStaEvnt->rangStat.eh.pres == PRSNT_NODEF) && (siStaEvnt->rangStat.status.pres == PRSNT_NODEF)) {
		for (x = 0; x < siStaEvnt->rangStat.status.len; x++) {
			status[x] = siStaEvnt->rangStat.status.val[x];
		}
	} else {
		SS7_ERROR("Received CGB with no status value on CIC = %d\n", sngss7_info->circuit->cic);
		SS7_FUNC_TRACE_EXIT(__FUNCTION__);
		return FTDM_FAIL;
	}

	/* save the circuit, range and status */
	sngss7_span->rx_cgb.circuit = circuit;
	sngss7_span->rx_cgb.range = range;
	sngss7_span->rx_cgb.type = blockType;
	for (x = 0; x < siStaEvnt->rangStat.status.len; x++) {
		sngss7_span->rx_cgb.status[x] = status[x];
	}

	/* loop over the cics starting from circuit until range+1 */
	loop_range = circuit + range + 1;
	x = circuit;
	while( x < loop_range ) {
		if (g_ftdm_sngss7_data.cfg.isupCkt[x].type != SNG_CKT_VOICE)  {
			loop_range++;
		}
		else {
			if (extract_chan_data(x, &sngss7_info, &ftdmchan)) {
				SS7_ERROR("Failed to extract channel data for circuit = %d!\n", x);
			} else {
				ftdm_mutex_lock(ftdmchan->mutex);
				if (status[byte] & (1 << bit)) {
					switch (blockType) {
					case 0:	/* maintenance oriented */
						sngss7_set_ckt_blk_flag(sngss7_info, FLAG_GRP_MN_BLOCK_RX);
						break;

					case 1: /* hardware failure oriented */
						sngss7_set_ckt_blk_flag(sngss7_info, FLAG_GRP_HW_BLOCK_RX);
						break;

					case 2: /* reserved for national use */
						break;

					default:
						break;
					}
				}

				/* bring the sig status down */
				sngss7_set_sig_status(sngss7_info, FTDM_SIG_STATE_DOWN, 0);
				ftdm_set_state(ftdmchan, FTDM_CHANNEL_STATE_SUSPENDED);

				ftdm_mutex_unlock(ftdmchan->mutex);
				/* update the bit and byte counter*/
				bit ++;
				if (bit == 8) {
					byte++;
					bit = 0;
				}
			}
		}
		x++;
	}


	/* get the ftdmchan and ss7_chan_data from the circuit */
	if (extract_chan_data(circuit, &sngss7_info, &ftdmchan)) {
		SS7_ERROR("Failed to extract channel data for circuit = %d!\n", circuit);
		SS7_FUNC_TRACE_EXIT(__FUNCTION__);
		return FTDM_FAIL;
	}

	ft_to_sngss7_cgba(ftdmchan);

	return FTDM_SUCCESS;
}

/******************************************************************************/
ftdm_status_t handle_cgu_req(uint32_t suInstId, uint32_t spInstId, uint32_t circuit, uint8_t globalFlg, uint8_t evntType, SiStaEvnt *siStaEvnt)
{
	SS7_FUNC_TRACE_ENTER(__FUNCTION__);

	sngss7_chan_data_t	*sngss7_info = NULL;
	sngss7_span_data_t	*sngss7_span = NULL;
	ftdm_channel_t		*ftdmchan = NULL;
	int					range;
	uint8_t				status[255];
	int					blockType = 0;
	int					byte = 0;
	int					bit = 0;
	int 					x;
	int					loop_range=0;
	ftdm_sigmsg_t 		sigev;
	
	ftdm_running_return(FTDM_FAIL);

	memset(&sigev, 0, sizeof (sigev));
	memset(&status[0], '\0', sizeof(status));

	/* confirm that the circuit is voice channel */
	if (g_ftdm_sngss7_data.cfg.isupCkt[circuit].type != SNG_CKT_VOICE) {
		SS7_ERROR("[CIC:%d]Rx %s on non-voice CIC\n",
					g_ftdm_sngss7_data.cfg.isupCkt[circuit].cic,
					DECODE_LCC_EVENT(evntType));

		SS7_FUNC_TRACE_EXIT(__FUNCTION__);
		return FTDM_FAIL;
	} else {
		/* get the ftdmchan and ss7_chan_data from the circuit */
		if (extract_chan_data(circuit, &sngss7_info, &ftdmchan)) {
			SS7_ERROR("Failed to extract channel data for ISUP circuit = %d!\n", circuit);
			SS7_FUNC_TRACE_EXIT(__FUNCTION__);
			return FTDM_FAIL;
		}

		SS7_INFO_CHAN(ftdmchan, "[CIC:%d]Rx %s\n",
			g_ftdm_sngss7_data.cfg.isupCkt[circuit].cic,
			DECODE_LCC_EVENT(evntType));
	}

	/* grab the span info */
	sngss7_span = ftdmchan->span->signal_data;

	/* figure out what type of block needs to be applied */
	if ((siStaEvnt->cgsmti.eh.pres == PRSNT_NODEF) && (siStaEvnt->cgsmti.typeInd.pres == PRSNT_NODEF)) {
		blockType = siStaEvnt->cgsmti.typeInd.val;
	} else {
		SS7_ERROR("Received CGU with no circuit group supervision value on CIC = %d\n", sngss7_info->circuit->cic);
		SS7_FUNC_TRACE_EXIT(__FUNCTION__);
		return FTDM_FAIL;
	}	

	/* pull out the range value */
	if ((siStaEvnt->rangStat.eh.pres == PRSNT_NODEF) && (siStaEvnt->rangStat.range.pres == PRSNT_NODEF)) {
		range = siStaEvnt->rangStat.range.val;
	} else {
		SS7_ERROR("Received CGU with no range value on CIC = %d\n", sngss7_info->circuit->cic);
		SS7_FUNC_TRACE_EXIT(__FUNCTION__);
		return FTDM_FAIL;
	}

	/* pull out the status field */
	if ((siStaEvnt->rangStat.eh.pres == PRSNT_NODEF) && (siStaEvnt->rangStat.status.pres == PRSNT_NODEF)) {
		for (x = 0; x < siStaEvnt->rangStat.status.len; x++) {
			status[x] = siStaEvnt->rangStat.status.val[x];
		}
	} else {
		SS7_ERROR("Received CGU with no status value on CIC = %d\n", sngss7_info->circuit->cic);
		SS7_FUNC_TRACE_EXIT(__FUNCTION__);
		return FTDM_FAIL;
	}

	/* save the circuit, range and status */
	sngss7_span->rx_cgu.circuit = circuit;
	sngss7_span->rx_cgu.range = range;
	sngss7_span->rx_cgu.type = blockType;
	for (x = 0; x < siStaEvnt->rangStat.status.len; x++) {
		sngss7_span->rx_cgu.status[x] = status[x];
	}

	/* loop over the cics starting from circuit until range+1 */
	loop_range = circuit + range + 1;
	x = circuit;
	while( x < loop_range ) {
		if (g_ftdm_sngss7_data.cfg.isupCkt[x].type != SNG_CKT_VOICE)  {
			loop_range++;
		} else {
			if (extract_chan_data(x, &sngss7_info, &ftdmchan)) {
				SS7_ERROR("Failed to extract channel data for circuit = %d!\n", x);
			}
			else {
				ftdm_mutex_lock(ftdmchan->mutex);

				if (status[byte] & (1 << bit)) {
					switch (blockType) {
					case 0:	/* maintenance oriented */
						sngss7_clear_ckt_blk_flag(sngss7_info, FLAG_GRP_MN_BLOCK_RX);
						sngss7_clear_ckt_blk_flag(sngss7_info, FLAG_CKT_MN_BLOCK_RX);
						sngss7_clear_ckt_blk_flag(sngss7_info, FLAG_CKT_MN_BLOCK_RX_DN);
						break;

					case 1: /* hardware failure oriented */
						sngss7_clear_ckt_blk_flag(sngss7_info, FLAG_GRP_HW_BLOCK_RX);
						break;

					case 2: /* reserved for national use */
						break;

					default:
						break;

					}
				}

				sigev.chan_id = ftdmchan->chan_id;
				sigev.span_id = ftdmchan->span_id;
				sigev.channel = ftdmchan;

				/* bring the sig status down */
				if (sngss7_channel_status_clear(sngss7_info)) {
					sngss7_set_sig_status(sngss7_info, FTDM_SIG_STATE_UP, 0);
				}
				
				ftdm_set_state(ftdmchan, FTDM_CHANNEL_STATE_SUSPENDED);
				ftdm_mutex_unlock(ftdmchan->mutex);

				/* update the bit and byte counter*/
				bit ++;
				if (bit == 8) {
					byte++;
					bit = 0;
				}
			}
		}
		x++;
	}

	/* get the ftdmchan and ss7_chan_data from the circuit */
	if (extract_chan_data(circuit, &sngss7_info, &ftdmchan)) {
		SS7_ERROR("Failed to extract channel data for circuit = %d!\n", circuit);
		SS7_FUNC_TRACE_EXIT(__FUNCTION__);
		return FTDM_FAIL;
	}

	ft_to_sngss7_cgua(ftdmchan);

	return FTDM_SUCCESS;
}

/******************************************************************************/
ftdm_status_t handle_olm_msg(uint32_t suInstId, uint32_t spInstId, uint32_t circuit, uint8_t globalFlg, uint8_t evntType, SiStaEvnt *siStaEvnt)
{
	SS7_FUNC_TRACE_ENTER(__FUNCTION__);

	sngss7_chan_data_t	*sngss7_info = NULL;
	ftdm_channel_t		*ftdmchan = NULL;
	
	ftdm_running_return(FTDM_FAIL);

	/* confirm that the circuit is voice channel */
	if (g_ftdm_sngss7_data.cfg.isupCkt[circuit].type != SNG_CKT_VOICE) {
		SS7_ERROR("[CIC:%d]Rx %s on non-voice CIC\n",
					g_ftdm_sngss7_data.cfg.isupCkt[circuit].cic,
					DECODE_LCC_EVENT(evntType));

		SS7_FUNC_TRACE_EXIT(__FUNCTION__);
		return FTDM_FAIL;
	} else {
		/* get the ftdmchan and ss7_chan_data from the circuit */
		if (extract_chan_data(circuit, &sngss7_info, &ftdmchan)) {
			SS7_ERROR("Failed to extract channel data for ISUP circuit = %d!\n", circuit);
			SS7_FUNC_TRACE_EXIT(__FUNCTION__);
			return FTDM_FAIL;
		}

		SS7_INFO_CHAN(ftdmchan, "[CIC:%d]Rx %s\n",
			g_ftdm_sngss7_data.cfg.isupCkt[circuit].cic,
			DECODE_LCC_EVENT(evntType));
	}

	/* handle overload */
	SS7_ERROR_CHAN(ftdmchan,"[CIC:%d]Rx Overload\n", sngss7_info->circuit->cic);

	sng_isup_reg_info_show();

	SS7_FUNC_TRACE_EXIT(__FUNCTION__);
	return FTDM_SUCCESS;
}

/******************************************************************************/
/* For Emacs:
 * Local Variables:
 * mode:c
 * indent-tabs-mode:t
 * tab-width:4
 * c-basic-offset:4
 * End:
 * For VIM:
 * vim:set softtabstop=4 shiftwidth=4 tabstop=4:
 */
/******************************************************************************/
