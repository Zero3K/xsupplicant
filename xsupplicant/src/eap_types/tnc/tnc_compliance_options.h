/**
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \author chris@open1x.org
 *
 * $Id: tnc_compliance_options.h,v 1.4 2008/01/23 23:45:10 galimorerpg Exp $
 * $Date: 2008/01/23 23:45:10 $
 **/

#ifndef __TNC_COMPLIANCE_OPTIONS_H__
#define __TNC_COMPLIANCE_OPTIONS_H__

/** NOTE: Just because these settings are here doesn't mean the supplicant can actually
 *        do any of this stuff.   It is all defined so that compliance modules can use 
 *        these values to do the right thing when asked to do so.  In order for any of these
 *        to do anything, you will need a third party module.
 */
#define TNC_COMPLIANCE_ENABLE              0x00000001   ///< Should compliance checking be enabled?  (If not, then other flags should be ignored.)
#define TNC_COMPLIANCE_PERSONALITY_CHECK   0x00000002   ///< Should we check for the "personality" of the machine?  (OS, supplicant, etc.)
#define TNC_COMPLIANCE_FIREWALL_CHECK      0x00000004   ///< Should we check if a firewall is enabled?
#define TNC_COMPLIANCE_ANTI_SPYWARE_CHECK  0x00000008   ///< Should we check if anti-spyware software is enabled?
#define TNC_COMPLIANCE_ANTI_VIRUS_CHECK    0x00000010   ///< Should we check if anti-virus software is enabled?
#define TNC_COMPLIANCE_ANTI_PHISHING_CHECK 0x00000020   ///< Should we check if anti-phishing software is enabled?
#define TNC_COMPLIANCE_ALLOW_FULL_SCAN     0x00000040   ///< Should we allow any of the above to perform a full system scan, if requested?
#define TNC_COMPLIANCE_ALLOW_AUTO_UPDATE   0x00000080   ///< Should we allow an auto update of any pieces found not to be in compliance?  (If unset, we will ask the user.)
// TODO: Remove TNC_COMPLIANCE_ALLOW_FULL_SCAN and TNC_COMPLIANCE_ALLOW_AUTO_UPDATE and replace with TNC_COMPLIANCE_ALLOW_AUTOMATIC_REMEDIATION or the like.  This has already been done in the UI.

enum BatchTypes {
	BATCH_REMEDIATION,
	BATCH_REMEDIATION_IN_PROGRESS,
    BATCH_REMEDIATION_STATUS_UPDATE,
	BATCH_REMEDIATED,
    BATCH_REMEDIATION_FAILURE,
	BATCH_OUT_OF_COMPLIANCE,
	BATCH_RECONNECT_REQUEST,
    BATCH_TNC_STATE_CHANGE,
};

#endif // __TNC_COMPLIANCE_OPTIONS_H__
