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

#include "../../lib/libxsupconfig/xsupconfig.h"
#include "../../lib/libxsupconfig/xsupconfig_structs.h"
#include "libxsupplugins/xsupplugin_types.h"

#include "sim_reader_plugin_hook.h"

/**
 * \brief Determine if we have a plug-in that provides the services for a SIM card reader.
 *
 * \retval TRUE if a plugin is available
 * \retval FALSE if a plugin is NOT available.
 **/
int sim_reader_plugin_hook_available()
{
	struct config_plugins *cur = NULL;

	cur = config_get_plugins();
	
	while (cur != NULL)
	{
		if (cur->plugin_type & PLUGIN_TYPE_SIM_INTERFACE) break;
		cur = cur->next;
	}

	if (cur == NULL) return FALSE;

	return TRUE;
}

/**
 * \brief Allow our plugin to modify the SIM card reader list to add anything it feels it 
 *		needs to.
 *
 * @param[in/out] readername   A string in the format returned from the PC/SC call SCardListReaders()
 **/
void sim_reader_plugin_update_reader_list(char **readername)
{
	struct config_plugins *cur = NULL;
	void (*hook)(char **readerlist);

	cur = config_get_plugins();
	
	while (cur != NULL)
	{
		if((cur->handle != NULL) && ((cur->plugin_type & PLUGIN_TYPE_SIM_INTERFACE) == PLUGIN_TYPE_SIM_INTERFACE))
	    {
	      hook = (void *)platform_plugin_entrypoint(cur, "sim_hook_update_reader_list");
	      
          if(hook != NULL)
		    (*hook)(readername);
	    }

		cur = cur->next;
	}
}

/**
 * \brief Determine the which types of cards this plugin supports.
 *
 * \retval int containing the flags defined by SUPPORT_xG_SIM in sim_reader_plugin_hook.h.
 **/
int sim_reader_plugin_gs_supported(SCARDHANDLE *card_hdl)
{
	struct config_plugins *cur = NULL;
	int (*hook)(void *card_hdl);
	int support = 0;

	cur = config_get_plugins();
	
	while (cur != NULL)
	{
		if((cur->handle != NULL) && ((cur->plugin_type & PLUGIN_TYPE_SIM_INTERFACE) == PLUGIN_TYPE_SIM_INTERFACE))
	    {
	      hook = (void *)platform_plugin_entrypoint(cur, "sim_hook_reader_gs_supported");
	      
          if(hook != NULL)
		  {
		    support = (*hook)(card_hdl);
			if (support > 0) return support;
		  }
	    }

		cur = cur->next;
	}

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
	struct config_plugins *cur = NULL;
	int (*hook)(void *cardhdl, char reader_mode, char *pin, char **imsi);
	int result = 0;

	cur = config_get_plugins();
	
	while (cur != NULL)
	{
		if((cur->handle != NULL) && ((cur->plugin_type & PLUGIN_TYPE_SIM_INTERFACE) == PLUGIN_TYPE_SIM_INTERFACE))
	    {
	      hook = (void *)platform_plugin_entrypoint(cur, "sim_hook_get_2g_imsi");
	      
          if(hook != NULL)
		  {
		    result = (*hook)(card_hdl, reader_mode, pin, imsi);
			if (result >= 0) return 0;
		  }
	    }

		cur = cur->next;
	}

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
	struct config_plugins *cur = NULL;
	int (*hook)(void *cardhdl, char reader_mode, char *pin, char **imsi);
	int result = 0;

	cur = config_get_plugins();
	
	while (cur != NULL)
	{
		if((cur->handle != NULL) && ((cur->plugin_type & PLUGIN_TYPE_SIM_INTERFACE) == PLUGIN_TYPE_SIM_INTERFACE))
	    {
	      hook = (void *)platform_plugin_entrypoint(cur, "sim_hook_get_3g_imsi");
	      
          if(hook != NULL)
		  {
		    result = (*hook)(card_hdl, reader_mode, pin, imsi);
			if (result >= 0) return 0;
		  }
	    }

		cur = cur->next;
	}

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
	struct config_plugins *cur = NULL;
	int (*hook)(void *cardhdl, char reader_mode);
	int result = 0;

	cur = config_get_plugins();
	
	while (cur != NULL)
	{
		if((cur->handle != NULL) && ((cur->plugin_type & PLUGIN_TYPE_SIM_INTERFACE) == PLUGIN_TYPE_SIM_INTERFACE))
	    {
	      hook = (void *)platform_plugin_entrypoint(cur, "sim_hook_3g_pin_needed");
	      
          if(hook != NULL)
		  {
		    result = (*hook)(card_hdl, reader_mode);
			if (result >= 0) return result;
		  }
	    }

		cur = cur->next;
	}

	return -1;
}

/**
 * \brief Return if a PIN is needed when operating in 2G mode.
 * 
 * @param[in] card_hdl   A pointer to an SCARDHANDLE (useful for using PC/SC type interfaces)
 * @param[in] reader_mode   0 for T=0, 1 for T=1
 *
 * \retval TRUE if a PIN is needed
 * \retval FALSE if a PIN is not needed
 **/
int sim_reader_plugin_hook_2g_pin_needed(SCARDHANDLE *card_hdl, char reader_mode)
{
	struct config_plugins *cur = NULL;
	int (*hook)(void *cardhdl, char reader_mode);
	int result = 0;

	cur = config_get_plugins();
	
	while (cur != NULL)
	{
		if((cur->handle != NULL) && ((cur->plugin_type & PLUGIN_TYPE_SIM_INTERFACE) == PLUGIN_TYPE_SIM_INTERFACE))
	    {
	      hook = (void *)platform_plugin_entrypoint(cur, "sim_hook_2g_pin_needed");
	      
          if(hook != NULL)
		  {
		    result = (*hook)(card_hdl, reader_mode);
			if (result >= 0) return result;
		  }
	    }

		cur = cur->next;
	}

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
	struct config_plugins *cur = NULL;
	int (*hook)(void *card_ctx, void *cardhdl, char *cardreader);
	int result = 0;

	cur = config_get_plugins();
	
	while (cur != NULL)
	{
		if((cur->handle != NULL) && ((cur->plugin_type & PLUGIN_TYPE_SIM_INTERFACE) == PLUGIN_TYPE_SIM_INTERFACE))
	    {
	      hook = (void *)platform_plugin_entrypoint(cur, "sim_hook_card_connect");
	      
          if(hook != NULL)
		  {
		    result = (*hook)(card_ctx, card_hdl, cardreader);
			if (result >= 0) 
			{
				sim_reader_plugin_init_ctx(card_ctx);		// Do this here, so that we clean up the old context and aquire one for the plugin.
				return result;
			}
		  }
	    }

		cur = cur->next;
	}

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
	struct config_plugins *cur = NULL;
	int (*hook)(void *card_hdl);
	int result = 0;

	cur = config_get_plugins();
	
	while (cur != NULL)
	{
		if((cur->handle != NULL) && ((cur->plugin_type & PLUGIN_TYPE_SIM_INTERFACE) == PLUGIN_TYPE_SIM_INTERFACE))
	    {
	      hook = (void *)platform_plugin_entrypoint(cur, "sim_hook_card_disconnect");
	      
          if(hook != NULL)
		  {
		    result = (*hook)(card_hdl);
			if (result >= 0) return result;
		  }
	    }

		cur = cur->next;
	}

	return -1;
}

// return -2 on sync failure. -1 for all other errors.
int sim_reader_plugin_hook_do_3g_auth(SCARDHANDLE *card_hdl, char reader_mode, 
			  unsigned char *Rand, unsigned char *autn, 
			  unsigned char *c_auts, char *res_len, 
			  unsigned char *c_sres, unsigned char *c_ck, 
			  unsigned char *c_ik, unsigned char *c_kc)
{
	struct config_plugins *cur = NULL;
	int (*hook)(void *card_hdl, char reader_mode, unsigned char *Rand, unsigned char *autn,
		unsigned char *c_auts, char *res_len, unsigned char *c_sres, unsigned char *c_ck,
		unsigned char *c_ik, unsigned char *c_kc);
	int result = 0;

	cur = config_get_plugins();
	
	while (cur != NULL)
	{
		if((cur->handle != NULL) && ((cur->plugin_type & PLUGIN_TYPE_SIM_INTERFACE) == PLUGIN_TYPE_SIM_INTERFACE))
	    {
	      hook = (void *)platform_plugin_entrypoint(cur, "sim_hook_do_3g_auth");
	      
          if(hook != NULL)
		  {
		    result = (*hook)(card_hdl, reader_mode, Rand, autn, c_auts, res_len, c_sres, c_ck, c_ik, c_kc);
			if (result != -3) return result;
		  }
	    }

		cur = cur->next;
	}

	return -1;
}


int sim_reader_plugin_hook_do_2g_auth(SCARDHANDLE *card_hdl, char reader_mode, 
			  unsigned char *challenge, unsigned char *response, 
			  unsigned char *ckey)
{
	struct config_plugins *cur = NULL;
	int (*hook)(void *card_hdl, char reader_mode, unsigned char *challenge, unsigned char *response,
		unsigned char *ckey);
	int result = 0;

	cur = config_get_plugins();
	
	while (cur != NULL)
	{
		if((cur->handle != NULL) && ((cur->plugin_type & PLUGIN_TYPE_SIM_INTERFACE) == PLUGIN_TYPE_SIM_INTERFACE))
	    {
	      hook = (void *)platform_plugin_entrypoint(cur, "sim_hook_do_2g_auth");
	      
          if(hook != NULL)
		  {
		    result = (*hook)(card_hdl, reader_mode, challenge, response, ckey);
			if (result >= 0) return result;
		  }
	    }

		cur = cur->next;
	}

	return -1;
}

/**
 * \brief Called to initialize the context for a card reader.  
 **/
int sim_reader_plugin_init_ctx(SCARDCONTEXT *card_ctx)
{
	printf("%s()\n", __FUNCTION__);

	// Release our old context if we have one.
	SCardReleaseContext(*card_ctx);

	//In PC/SC SCARDCONTEXT is defined as "typedef ULONG_PTR SCARDCONTEXT", we will set it
	// to -1 to identify that we are using a plugin.
	/*
	(*card_ctx) = malloc(sizeof(unsigned long));
	if ((*card_ctx) == NULL) return -1;

	(*card_ctx) = -1;  // Will set this to all 0xffs.
	*/
	(*card_ctx) = -1;
	return 0;
}

int sim_reader_plugin_deinit_ctx(SCARDHANDLE *card_hdl, SCARDCONTEXT *card_ctx)
{
//	free((*card_ctx));
	(*card_ctx) = 0;

	return sim_reader_plugin_hook_card_disconnect(card_hdl);
}

int sim_reader_plugin_ctx_is_plugin(void **card_ctx)
{
	if (card_ctx == NULL) return FALSE;
	if ((*card_ctx) == -1) return TRUE;

	return FALSE;
}

int sim_reader_plugin_hook_wait_card_ready(SCARDHANDLE *card_hdl, int waittime)
{
	struct config_plugins *cur = NULL;
	int (*hook)(void *card_hdl, int waittime);
	int result = 0;

	cur = config_get_plugins();
	
	while (cur != NULL)
	{
		if((cur->handle != NULL) && ((cur->plugin_type & PLUGIN_TYPE_SIM_INTERFACE) == PLUGIN_TYPE_SIM_INTERFACE))
	    {
	      hook = (void *)platform_plugin_entrypoint(cur, "sim_hook_wait_card_ready");
	      
          if(hook != NULL)
		  {
		    result = (*hook)(card_hdl, waittime);
			if (result >= 0) return result;
		  }
	    }

		cur = cur->next;
	}

	return -1;
}
