/**
 * Validate the profile section of a configuration block.
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file xsupconfcheck_profile.c
 *
 * \authors chris@open1x.org
 *
 **/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libxsupconfig/xsupconfig.h"
#include "libxsupconfig/xsupconfig_structs.h"
#include "src/context.h"
#include "src/error_prequeue.h"
#include "src/interfaces.h"
#include "xsupconfcheck.h"
#include "xsupconfcheck_profile.h"

/**
 * \brief Check to see if we have a password configured.
 *
 * @param[in] mypwd   The structure that contains data for "password only" EAP types.
 *
 * \retval 0 on success
 * \retval -1 on failure
 **/
int xsupconfcheck_profile_pwd_only(struct config_pwd_only *mypwd, config_profiles *prof, int log)
{
	if (mypwd == NULL)
	{
		if (log == TRUE) error_prequeue_add("There is no password configured.");
		return PROFILE_NEED_UPW;
	}

	if ((mypwd->password == NULL) && (prof->temp_password == NULL))
	{
		if (log == TRUE) error_prequeue_add("There is no password configured.");
		return PROFILE_NEED_UPW;
	}

	return 0;
}

/**
 * \brief Check to see if we have EAP-TLS configured correctly.
 *
 * @param[in] tls   The structure that contains data for the EAP-TLS authentication type.
 *
 * \retval 0 on success
 * \retval -1 on failure
 **/
int xsupconfcheck_profile_eap_tls(struct config_eap_tls *tls, config_profiles *prof, int log)
{
	int retval = 0;

	if (tls == NULL)
	{
		if (log == TRUE) error_prequeue_add("You must configure EAP-TLS first.");
		retval = -1;
	}

	if (tls->trusted_server == NULL)
	{
		if (log == TRUE) error_prequeue_add("You must define a trusted server to use EAP-TLS.");
		retval = -1;
	}

	if (tls->store_type == NULL)
	{
		if (log == TRUE) error_prequeue_add("A store type for your certificate must be specified to use EAP-TLS.");
		retval = -1;
	}

	if (tls->user_cert == NULL)
	{
		if (log == TRUE) error_prequeue_add("A user certificate file must be specified to use EAP-TLS.");
		retval = -1;
	}

#ifndef WINDOWS
	if (tls->user_key == NULL)
	{
		if (log == TRUE) error_prequeue_add("A user key file must be specified to use EAP-TLS.");
		retval = -1;
	}

	if ((tls->user_key_pass == NULL) && (prof->temp_password == NULL))
	{
		if (log == TRUE) error_prequeue_add("A user key password must be specified to use EAP-TLS.");
		retval = PROFILE_NEED_UPW;
	}
#endif

	return retval;
}

/**
 * \brief Check to see if we have EAP-SIM configured correctly.
 *
 * @param[in] sim   The structure that contains data for the EAP-SIM authentication type.
 *
 * \retval 0 on success
 * \retval -1 on failure
 **/
int xsupconfcheck_profile_eap_sim(struct config_eap_sim *sim, config_profiles *prof, int log)
{
	int retval = 0;

	if (sim == NULL)
	{
		if (log == TRUE) error_prequeue_add("You must configure EAP-SIM before using it.");
		return -1;
	}

	if (sim->reader == NULL)
	{
		if (log == TRUE) error_prequeue_add("You must have a SIM card reader configured before attempting to use EAP-SIM.");
		retval = -1;
	}

	if ((sim->password == NULL) && (prof->temp_password == NULL))
	{
		retval = PROFILE_NEED_PIN;
	}

	return retval;
}

/**
 * \brief Check to see if we have EAP-AKA configured correctly.
 *
 * @param[in] aka   The structure that contains data for the EAP-AKA authentication type.
 *
 * \retval 0 on success
 * \retval -1 on failure
 **/
int xsupconfcheck_profile_eap_aka(struct config_eap_aka *aka, config_profiles *prof, int log)
{
	int retval = 0;

	if (aka == NULL)
	{
		if (log == TRUE) error_prequeue_add("You must configure EAP-AKA before using it.");
		retval = -1;
	}

	if ((aka->password == NULL) && (prof->temp_password == NULL))
	{
		retval = PROFILE_NEED_PIN;
	}

	return retval;
}

/**
 * \brief Check to see if we have EAP-TTLS configured correctly.
 *
 * @param[in] ttls   The structure that contains data for the EAP-TTLS authentication type.
 *
 * \retval 0 on success
 * \retval -1 on failure
 **/
int xsupconfcheck_profile_eap_ttls(struct config_eap_ttls *ttls, config_profiles *prof, int log)
{
	int retval = 0;

	if (ttls == NULL)
	{
		if (log == TRUE) error_prequeue_add("There is no TTLS configuration defined for this profile.");
		return -1;
	}

	if ((ttls->validate_cert == TRUE) && (ttls->trusted_server == NULL))
	{
		if (log == TRUE) error_prequeue_add("There is no trusted server defined even though you want to validate the server certificate.");
		retval = -1;
	}
	else
	{
		if (ttls->validate_cert == TRUE)
		{
			if (xsupconfcheck_trusted_server(ttls->trusted_server, log) != 0)
			{
				// No need to do anything else here.  The above call will have handled it.
				retval = -1;
			}
		}
	}

	if ((ttls->user_cert != NULL) && (ttls->user_key == NULL))
	{
		if (log == TRUE) error_prequeue_add("The profile is configured to use a user certificate with TTLS, but there is no user key file defined.");
		retval = -1;
	}

	if ((ttls->user_key != NULL) && (ttls->user_key_pass == NULL))
	{
		if (log == TRUE) error_prequeue_add("The profile is configured to use a user certificate with TTLS, but there is no password for the private key.");
		retval = PROFILE_NEED_UPW;
	}

	if ((ttls->phase2_data == NULL) && (prof->temp_password == NULL))
	{
		return PROFILE_NEED_UPW;
	}


	switch (ttls->phase2_type)
	{
	case TTLS_PHASE2_PAP:
	case TTLS_PHASE2_CHAP:
	case TTLS_PHASE2_MSCHAP:
	case TTLS_PHASE2_MSCHAPV2:
		if (((ttls->phase2_data == NULL) || (((struct config_pwd_only *)ttls->phase2_data)->password == NULL)) && (prof->temp_password == NULL))
		{
			if (log == TRUE) error_prequeue_add("There is no password defined for the TTLS phase 2 method.");
			retval = PROFILE_NEED_UPW;
		}
		break;

	case TTLS_PHASE2_EAP:
		switch (xsupconfcheck_profile_check_eap_method(ttls->phase2_data, prof, log))
		{
		case PROFILE_NEED_UPW:
			retval = PROFILE_NEED_UPW;
			break;
			
		case 0:
			break;

		default:
			retval = -1;
			break;
		}
		break;

	default:
		if (log == TRUE) error_prequeue_add("The TTLS phase 2 method defined is unknown.");
		retval = -1;
		break;
	}

	return retval;
}

/**
 * \brief Check to see if we have EAP-PEAP configured correctly.
 *
 * @param[in] peap   The structure that contains data for the EAP-PEAP authentication type.
 *
 * \retval 0 on success
 * \retval -1 on failure
 **/
int xsupconfcheck_profile_eap_peap(struct config_eap_peap *peap, config_profiles *prof, int log)
{
	int retval = 0;

	if (peap == NULL)
	{
		if (log == TRUE) error_prequeue_add("There is no configuration for EAP-PEAP.");
		return -1;
	}

	if ((peap->trusted_server == NULL) && (peap->validate_cert == TRUE))
	{
		if (log == TRUE) error_prequeue_add("There is no trusted server defined, but the profile is configured to validate the certificate.");
		retval = -1;
	}
	else
	{
		if (peap->validate_cert == TRUE)
		{
			if (xsupconfcheck_trusted_server(peap->trusted_server, log) != 0)
			{
				// No need to do anything else here.  The above call will have handled it.
				retval = -1;
			}
		}
	}

	if ((peap->user_cert != NULL) && (peap->user_key == NULL))
	{
		if (log == TRUE) error_prequeue_add("The profile is configured to use a user certificate with PEAP, but there is no user key file defined.");
		retval = -1;
	}

	if ((peap->user_key != NULL) && (peap->user_key_pass == NULL))
	{
		if (log == TRUE) error_prequeue_add("The profile is configured to use a user certificate with PEAP, but there is no password for the private key.");
		retval = -1;
	}

	switch (xsupconfcheck_profile_check_eap_method(peap->phase2, prof, log))
	{
	case PROFILE_NEED_UPW:
		retval = PROFILE_NEED_UPW;
		break;
		
	case 0:
		break;
		
	default:
		retval = -1;
		break;
	}

	return retval;
}

/**
 * \brief Check to see if we have EAP-MSCHAPv2 configured correctly.
 *
 * @param[in] mscv2   The structure that contains data for the EAP-MSCHAPv2 authentication type.
 *
 * \retval 0 on success
 * \retval -1 on failure
 **/
int xsupconfcheck_profile_eap_mschapv2(struct config_eap_mschapv2 *mscv2, config_profiles *prof, int log)
{
	int retval = 0;

	if (mscv2 == NULL)
	{
		if (log == TRUE) error_prequeue_add("There is no configuration for EAP-MSCHAPv2.");
		return -1;
	}

	if ((mscv2->nthash == NULL) && (mscv2->password == NULL) && (prof->temp_password == NULL) && (!TEST_FLAG(mscv2->flags, FLAGS_EAP_MSCHAPV2_MACHINE_AUTH)))
	{
		retval = PROFILE_NEED_UPW;
	}

	return retval;
}

/**
 * \brief Check to see if we have EAP-FAST configured correctly.
 *
 * @param[in] fast   The structure that contains data for the EAP-FAST authentication type.
 *
 * \retval 0 on success
 * \retval -1 on failure
 **/
int xsupconfcheck_profile_eap_fast(struct config_eap_fast *fast, config_profiles *prof, int log)
{
	int retval = 0;

	if (fast == NULL)
	{
		if (log == TRUE) error_prequeue_add("There is no configuration set for EAP-FAST.");
		return -1;
	}

	if (fast->phase2 == NULL)
	{
		if (log == TRUE) error_prequeue_add("There is no phase 2 configuration defined for EAP-FAST.");
		retval = -1;
	}

	if (fast->phase2->method_num == EAP_TYPE_GTC)
	{
		// Because EAP-FAST pretty much breaks EAP-GTC, we won't let it prompt for a password during the authentication.
		// We prompt for it at connection time just like any other inner EAP method.
		if (prof->temp_password == NULL) retval = PROFILE_NEED_UPW;
	}
	else
	{
		switch (xsupconfcheck_profile_check_eap_method(fast->phase2, prof, log))
		{
		case PROFILE_NEED_UPW:
			retval = PROFILE_NEED_UPW;
			break;
		
		case 0:
			break;
		
		default:
			retval = -1;
			break;
		}
	}

	return retval;
}

/**
 * \brief Check the EAP method structure, and check the related EAP methods.
 *
 * @param[in] myeap   The EAP method structure that contains information about which EAP method
 *                    we need to validate.
 *
 * \retval 0 on success
 * \retval -1 on failure
 **/
int xsupconfcheck_profile_check_eap_method(config_eap_method *myeap, config_profiles *prof, int log)
{
	int retval = 0;

	if (myeap == NULL) return -1;

	if (myeap->method_data == NULL)
	{
		if (log == TRUE) error_prequeue_add("No method data is configured for the EAP method.");
		return -1;
	}

	switch (myeap->method_num)
	{
	case EAP_TYPE_OTP:
	case EAP_TYPE_GTC:
		// Nothing to check.
		break;

	case EAP_TYPE_MD5:
	case EAP_TYPE_LEAP:
	case EAP_TYPE_PSK:
		switch (xsupconfcheck_profile_pwd_only(myeap->method_data, prof, log))
		{
		case PROFILE_NEED_UPW:
			retval = PROFILE_NEED_UPW;
			break;

		case 0:
			break;

		default:
			retval = -1;
			break;
		}
		break;

	case EAP_TYPE_TLS:
		switch (xsupconfcheck_profile_eap_tls(myeap->method_data, prof, log))
		{
		case PROFILE_NEED_UPW:
			retval = PROFILE_NEED_UPW;
			break;

		case 0:
			break;

		default:
			retval = -1;
			break;
		}
		break;

	case EAP_TYPE_AKA:
		switch (xsupconfcheck_profile_eap_aka(myeap->method_data, prof, log))
		{
		case PROFILE_NEED_PIN:
			retval = PROFILE_NEED_PIN;
			break;

		case 0:
			break;
			
		default:
			// No need to do anything here, the previous call did it all.
			retval = -1;
			break;
		}
		break;

	case EAP_TYPE_SIM:
		switch (xsupconfcheck_profile_eap_sim(myeap->method_data, prof, log))
		{
		case PROFILE_NEED_PIN:
			retval = PROFILE_NEED_PIN;
			break;
			
		case 0:
			break;
			
		default:
			// No need to do anything here, the previous call did it all.
			retval = -1;
			break;
		}
		break;

	case EAP_TYPE_TTLS:
		switch (xsupconfcheck_profile_eap_ttls(myeap->method_data, prof, log))
		{
		case PROFILE_NEED_UPW:
			retval = PROFILE_NEED_UPW;
			break;
			
		case 0:
			break;
			
		default:
			// No need to do anything here, the previous call did it all.
			retval = -1;
			break;
		}
		break;

	case EAP_TYPE_PEAP:
		switch (xsupconfcheck_profile_eap_peap(myeap->method_data, prof, log))
		{
		case PROFILE_NEED_UPW:
			retval = PROFILE_NEED_UPW;
			break;
			
		case 0:
			break;
			
		default:
			// No need to do anything here, the previous call did it all.
			retval = -1;
			break;
		}
		break;

	case EAP_TYPE_MSCHAPV2:
		switch (xsupconfcheck_profile_eap_mschapv2(myeap->method_data, prof, log))
		{
		case PROFILE_NEED_UPW:
			retval = PROFILE_NEED_UPW;
			break;

		case 0:
			break;

		default:
			// No need to do anything here, the previous call did it all.
			retval = -1;
			break;
		}
		break;

	case EAP_TYPE_FAST:
		switch (xsupconfcheck_profile_eap_fast(myeap->method_data, prof, log))
		{
		case PROFILE_NEED_UPW:
			retval = PROFILE_NEED_UPW;
			break;

		case 0:
			break;

		default:
			// No need to do anything here, the previous call did it all.
			retval = -1;
			break;
		}
		break;

	default:
		if (log == TRUE) error_prequeue_add("Unknown EAP type configured.  Please update xsupconfcheck_profile_check_eap_method().");
		retval = -1;
		break;
	}

	return retval;
}

/**
 * \brief Check a profile to make sure it is valid.
 *
 * @param[in] myprof   The profile structure that contains the data we want to check.
 *
 * \retval 0 on success
 * \retval -1 on failure
 **/
int xsupconfcheck_profile_check(struct config_profiles *myprof, int log)
{
	int retval = 0;
	struct config_eap_peap *peapdata = NULL;

	// Verify that we have a valid identity set.
	if ((myprof->identity == NULL) && (myprof->temp_username == NULL))
	{
		if ((myprof->method->method_num != EAP_TYPE_SIM) && (myprof->method->method_num != EAP_TYPE_AKA))
		{
			if (myprof->method->method_num == EAP_TYPE_PEAP)
			{
				peapdata = (struct config_eap_peap *)myprof->method->method_data;
				if (!TEST_FLAG(peapdata->flags, FLAGS_PEAP_MACHINE_AUTH))
				{
					if (log == TRUE) error_prequeue_add("Profile is missing a valid username.");
					retval = PROFILE_NEED_UPW;
				}
			}
			else
			{
				// XXX If we are doing TLS here and are on Windows, we need to know the username, but not the password.
				if (log == TRUE) error_prequeue_add("Profile is missing a valid username.");
				retval = PROFILE_NEED_UPW;
			}
		}
	}

	// Verify that the other data is valid.
	switch (xsupconfcheck_profile_check_eap_method(myprof->method, myprof, log))
	{
	case PROFILE_NEED_PIN:
		retval = PROFILE_NEED_PIN;
		break;

	case PROFILE_NEED_UPW:
		retval = PROFILE_NEED_UPW;
		break;

	case 0:
		break;

	default:
		retval = -1;
		break;
	}

	return retval;
}

