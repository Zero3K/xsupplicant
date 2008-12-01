/**
 * Plugin interface for providing alternate SIM card behavior.
 * 
 * \file sim_reader_plugin_hook.c
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \author chris@open1x.org
 *
 **/

#ifdef WINDOWS
#include <windows.h>
#endif

#include <winscard.h>

#include "sim_reader_plugin_hook.h"

/**
 * \brief Determine if we have a plug-in that provides the services for a SIM card reader.
 *
 * \retval TRUE if a plugin is available
 * \retval FALSE if a plugin is NOT available.
 **/
int sim_reader_plugin_hook_available()
{
	return FALSE;
}

/**
 * \brief Allow our plugin to modify the SIM card reader list to add anything it feels it 
 *		needs to.
 *
 * @param[in/out] readername   A string in the format returned from the PC/SC call SCardListReaders()
 **/
void sim_reader_plugin_update_reader_list(char **readername)
{
}

/**
 * \brief Determine the which types of cards this plugin supports.
 *
 * \retval int containing the flags defined by SUPPORT_xG_SIM in sim_reader_plugin_hook.h.
 **/
int sim_reader_plugin_gs_supported()
{
	return 0;
}

/**
 * \brief Allow the plugin to return the 2G IMSI information.
 *
 * @param[in] card_hdl   An SCARDHANDLE as defined in PC/SC.
 * @param[in] reader_mode   0 for T=0, 1 for T=1
 * @param[in] pin   The ASCII representation of the PIN provided by the user.
 * @param[out] imsi   The IMSI from the card.
 *
 * \retval 0 on success, or an SM_ERROR_* (from sm_handler.h) on error.
 **/
int sim_reader_plugin_hook_get_2g_imsi(SCARDHANDLE *card_hdl, char reader_mode, char *pin, char **imsi)
{
	return -1;
}

/**
 * \brief Allow the plugin to return the 3G IMSI information.
 *
 * @param[in] card_hdl   An SCARDHANDLE as defined in PC/SC.
 * @param[in] reader_mode   0 for T=0, 1 for T=1
 * @param[in] pin   The ASCII representation of the PIN provided by the user.
 * @param[out] imsi   The IMSI from the card.
 *
 * \retval 0 on success, or an SM_ERROR_* (from sm_handler.h) on error.
 **/
int sim_reader_plugin_hook_get_3g_imsi(SCARDHANDLE *card_hdl, char reader_mode, char *pin, char **imsi)
{
	return -1;
}

/**
 * \brief Given a reader name see if it is the one we provided.
 *
 * @param[in] readername   The name of the reader to check on.
 *
 * \retval FALSE if it isn't our reader
 * \retval TRUE if it is our reader
 **/
int sim_reader_plugin_is_my_reader(char *readername)
{
	return -1;
}

/**
 * \brief Return if a PIN is needed when operating in 3G mode.
 * 
 * @param[in] card_hdl   A pointer to an SCARDHANDLE (useful for using PC/SC type interfaces)
 * @param[in] reader_mode   0 for T=0, 1 for T=1
 *
 * \retval TRUE if a PIN is needed
 * \retval FALSE if a PIN is not needed
 **/
int sim_reader_plugin_hook_3g_pin_needed(SCARDHANDLE *card_hdl, char reader_mode)
{
	return -1;
}

/**
 * \brief Establish a connection to the card reader.
 *
 * @param[in] card_ctx   A pointer to a PC/SC card context.
 * @param[in] card_hdl   A pointer to a PC/SC card handle.
 * @param[in] cardreader   The card reader that we want to connect to.
 *
 * \retval SCARD_S_SUCCESS on success, anything else is an error.
 **/
long sim_reader_plugin_hook_card_connect(SCARDCONTEXT *card_ctx, SCARDHANDLE *card_hdl, char *cardreader)
{
	return -1;
}

/**
 * \brief Break the connection to the card reader.
 *
 * @param[in] card_hdl   The card handle we want to terminate.
 *
 * \retval SCARD_S_SUCCESS on success, anything else is an error.
 **/
int sim_reader_plugin_hook_card_disconnect(SCARDHANDLE *card_hdl)
{
	return -1;
}

// return -2 on sync failure. -1 for all other errors.
int sim_reader_plugin_do_3g_auth(SCARDHANDLE *card_hdl, char reader_mode, 
			  unsigned char *Rand, unsigned char *autn, 
			  unsigned char *c_auts, char *res_len, 
			  unsigned char *c_sres, unsigned char *c_ck, 
			  unsigned char *c_ik, unsigned char *c_kc)
{
	return -1;
}


int sim_reader_plugin_hook_do_2g_auth(SCARDHANDLE *card_hdl, char reader_mode, 
			  unsigned char *challenge, unsigned char *response, 
			  unsigned char *ckey)
{
	return -1;
}

