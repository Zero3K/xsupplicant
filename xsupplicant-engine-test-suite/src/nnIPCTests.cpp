#include <iostream>

#include "Util.h"
#include "nnIPCTests.h"
    nnIPCTests::nnIPCTests() 
{
} nnIPCTests::~nnIPCTests() 
{
} bool nnIPCTests::executeTest() 
{
	runInnerTest("doPing()", doPing());
	runInnerTest("enumLiveInts()", enumLiveInts());
	runInnerTest("enumEAPmethods()", enumEAPmethods());
	runInnerTest("checkVersionString()", checkVersionString());
	runInnerTest("checkCertificates()", checkCertificates());
	runInnerTest("checkUserCertificates()", checkUserCertificates());
	runInnerTest("checkCreateTT()", checkCreateTT());
	runInnerTest("enumSmartCardReaders()", enumSmartCardReaders());
	return true;
}

bool nnIPCTests::doPing() 
{
	if (xsupgui_request_ping() != REQUEST_SUCCESS)
		 {
		innerError("Unable to ping the engine!\n");
		return false;
		}
	return true;
}

bool nnIPCTests::enumLiveInts() 
{
	int_enum * retints = NULL;
	int i = 0;
	int intPull = 0;
	char *desc = NULL;
	char *mac = NULL;
	int iswireless = 0;
	int capabilities = 0;
	int state = 0;
	int result = 0;
	if (xsupgui_request_enum_live_ints(&retints) != REQUEST_SUCCESS)
		 {
		innerError("Unable to enumerate live interfaces!\n");
		return false;
		}
	for (i = 0; (retints[i].name != NULL); i++) ;
	intPull = (rand() % i);
	if (xsupgui_request_get_os_specific_int_data
	      (retints[intPull].name, &desc, &mac,
	       &iswireless) != REQUEST_SUCCESS)
		 {
		innerError("Unable to get OS specific interface data.\n");
		return false;
		}
	
	    // Make sure the OS data we got matches the enumeration data we got.
	    if (strcmp(retints[intPull].desc, desc) != 0)
		 {
		innerError
		    ("Description from the enumeration and OS data didn't match!\n");
		return false;
		}
	if (iswireless != retints[intPull].is_wireless)
		 {
		innerError
		    ("Enumeration and direct call disagree on the wirelessness of the interface.\n");
		return false;
		}
	free(desc);
	free(mac);
	for (i = 0;
	       ((retints[i].name != NULL) && (retints[i].is_wireless == 0));
	       i++) ;
	if (retints[i].is_wireless == 1)
		 {
		
		    // There is a wireless interface in the machine, ask about its capabilities.
		    if (xsupgui_request_get_interface_capabilities
			(retints[i].name, &capabilities) != REQUEST_SUCCESS)
			 {
			innerError
			    ("Couldn't get wireless interface capabilities!\n");
			return false;
			}
		}
	
	else
		 {
		innerError
		    ("No wireless interface found in the machine.  This part of the enumLiveInts() test will be skipped.\n");
		}
	if (xsupgui_request_free_int_enum(&retints) != 0)
		 {
		innerError("Unable to free live interface enumeration!\n");
		return false;
		}
	return true;
}

bool nnIPCTests::enumSmartCardReaders() 
{
	char **readers;
	int result = 0;
	if ((result =
	       xsupgui_request_enum_smartcard_readers(&readers)) !=
	      REQUEST_SUCCESS)
		 {
		if (result == IPC_ERROR_NOT_SUPPORTED)
			 {
			innerError
			    ("Either this machine has no smart card readers, or this build isn't smart card enabled.\n");
			return true;
			}
		
		else
			 {
			innerError
			    ("Unable to enumerate smart card readers! (Error : "
			     + Util::itos(result) + ")\n");
			return false;
			}
		}
	if (xsupgui_request_free_enum_smartcard_readers(&readers) != 0)
		 {
		innerError
		    ("Unable to free the memory used by the smart card enumeration.\n");
		return false;
		}
	return true;
}

bool nnIPCTests::checkVersionString() 
{
	char *verString = NULL;
	if (xsupgui_request_version_string(&verString) != REQUEST_SUCCESS)
		 {
		innerError("Unable to determine the version string!\n");
		return false;
		}
	if (strstr(verString, "XSupplicant") == NULL)
		 {
		innerError
		    ("Invalid string returned for the supplicant version string!\n");
		free(verString);
		return false;
		}
	free(verString);
	return true;
}

bool nnIPCTests::checkUserCertificates() 
{
	cert_enum * certEnum = NULL;
	int i = 0;
	if (xsupgui_request_enum_user_certs(&certEnum) != REQUEST_SUCCESS)
		 {
		innerError("Unable to enumerate certificates.\n");
		if (certEnum != NULL)
			 {
			innerError
			    ("AND the resulting enumeration pointer wasn't NULL!\n");
			}
		return false;
		}
	xsupgui_request_free_cert_enum(&certEnum);
	return true;
}

bool nnIPCTests::checkCertificates() 
{
	cert_enum * certEnum = NULL;
	cert_info * certInfo = NULL;
	int i = 0;
	int certpull = 0;
	if (xsupgui_request_enum_root_ca_certs(&certEnum) != REQUEST_SUCCESS)
		 {
		innerError("Unable to enumerate certificates.\n");
		if (certEnum != NULL)
			 {
			innerError
			    ("AND the resulting enumeration pointer wasn't NULL!\n");
			}
		return false;
		}
	for (i = 0; (certEnum[i].certname != NULL); i++) ;
	certpull = (rand() % i);
	if (xsupgui_request_ca_certificate_info
	      (certEnum[certpull].storetype, certEnum[certpull].location,
	       &certInfo) != REQUEST_SUCCESS)
		 {
		innerError("Unable to get certificate specific data!\n");
		if (certInfo != NULL)
			 {
			innerError
			    ("AND the certificate info pointer wasn't NULL!\n");
			}
		return false;
		}
	xsupgui_request_free_cert_info(&certInfo);
	
	    // Now, try to read something that is invalid.
	    if (xsupgui_request_ca_certificate_info
		(certEnum[certpull].storetype, "sdlkhjtjrhgkrjthsr",
		 &certInfo) == REQUEST_SUCCESS)
		 {
		innerError("Invalid certificate request succeeded?!\n");
		return false;
		}
	if (certInfo != NULL)
		 {
		innerError
		    ("Invalid certificate request returned a non-NULL pointer.\n");
		return false;
		}
	xsupgui_request_free_cert_enum(&certEnum);
	return true;
}

bool nnIPCTests::enumEAPmethods() 
{
	eap_enum * eaptypes = NULL;
	int i = 0;
	if (xsupgui_request_enum_eap_methods(&eaptypes) != REQUEST_SUCCESS)
		 {
		innerError("Unable to enumerate EAP methods!\n");
		return false;
		}
	for (i = 0; (eaptypes[i].name != NULL); i++)
		 {
		switch (eaptypes[i].num)
			 {
		case EAP_TYPE_MD5:
		case EAP_TYPE_OTP:
		case EAP_TYPE_GTC:
		case EAP_TYPE_TLS:
		case EAP_TYPE_LEAP:
		case EAP_TYPE_SIM:
		case EAP_TYPE_TTLS:
		case EAP_TYPE_AKA:
		case EAP_TYPE_PEAP:
		case EAP_TYPE_MSCHAPV2:
		case EAP_TYPE_TNC:
		case EAP_TYPE_FAST:
		case EAP_TYPE_PSK:
			break;	// Do nothing here.  This is the successful case.
		default:
			innerError("Unknown EAP method " +
				    Util::itos(eaptypes[i].num) + "!\n");
			return false;
			}
		}
	return true;
}

bool nnIPCTests::checkCreateTT() 
{
	int result = 0;
	FILE * tfile = NULL;
	if ((result =
	       xsupgui_request_create_trouble_ticket_file("TTtest.zip", "\\",
							  1)) !=
	      REQUEST_SUCCESS)
		 {
		innerError("Unable to create a trouble ticket!\n");
		return false;
		}
	
	    // XXX We should check the completion here, but we don't have the event channel hooked up.
	    return true;
}
