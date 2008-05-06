/*******************************************************************
 * Error codes used in various parts of the program.
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file xsup_err.h
 *
 * \author chris@open1x.org
 *
 *******************************************************************/

#ifndef __XSUP_ERR_H__
#define __XSUP_ERR_H__
/* Error codes that we can get for various pieces of xsupplicant. */

// If we return >=0 then there wasn't an error.
#define XDATACHANGED       9    // We updated config data, instead of adding new data.
#define XPROMPT            2    // We asked the GUI to prompt for something.
#define XDATA              1    // There is data to return.
#define XNEWESSID          3    // We have a new ESSID.
#define XENONE             0

// Error numbers -1 to -10 are socket related errors.
#define XENOSOCK          -1
#define XESOCKOP          -2
#define XENOTINT          -3
#define XENOWIRELESS      -4
#define XENOFRAMES        -5
#define XEIGNOREDFRAME    -6
#define XGOODKEYFRAME      6
#define XEBADKEY          -7
#define XNOMOREINTS        2
#define XINVALIDINT        3  // This isn't an error.  It is for situations
                              // where an interface index of 0 is invalid.
#define XECANTPASSIVE     -8  ///< Can't do a passive scan.

// Error numbers -11 through -20 are for misc. errors.
#define XECONFIGFILEFAIL  -11
#define XECONFIGPARSEFAIL -12 
#define XENOTHING_TO_DO   -13
#define XEBADCONFIG       -14
#define XEBADPACKETSIZE   -15
#define XEINVALIDEAP      -16
#define XEGENERROR        -17
#define XENOTSUPPORTED    -18
#define XECONFIGALREADYLOADED -19
#define XEINNERDONE       -20

// Error numbers -21 through -30 are memory related errors.
#define XEMALLOC          -21   // Malloc error.
#define XENOBUFFER        -22   // There was a buffer that was empty when it
                                // shouldn't have been!
#define XENOUSERDATA      -23   // Our userdata structure was NULL!
#define XECACHEMISS       -24   // We had a PMK cache miss.

// Error numbers -31 through -40 are additional general errors.
#define XECANTFINDSERVER   -31

// Error numbers -41 through -50 are key generation errors.
#define XENOKEYSUPPORT    -41

// Error numbers -100 through -200 are EAP specific errors.
// Error messages for EAP-MD5
#define XEMD5LEN         -100

// Error messages for EAP-TLS
#define XETLSINIT        -105
#define XETLSSTARTFAIL   -106
#define XETLSBADFLAGS    -107
#define XETLSCERTLOAD    -108
#define XETLSNOCTX       -109
#define XTLSNEEDDATA      105

// Error message for TLS based methods other than EAP-TLS.
#define XEBADCN          -130
#define XETLSCRYPTFAIL   -131
#define XEPHASE2FAILURE  -132

// Error messages for MS-CHAPv2
#define XEMSCHAPV2LEN     -110

// Error messages for EAP-SIM
#define XESIMNOATMAC      -115
#define XESIMBADLEN       -116
#define XESIMBADTYPE      -117
#define XESIMBADMAC       -118
#define XESIMBADCMD       -119
#define XESIMBADMODE      -120
#define XESIMGENERR       -121
#define XEAKASYNCFAIL     -122

// Error message for EAP-TNC
#define XEINVALIDFLAGSVER -130
#define XETNCLIBFAILURE   -131

// Error message for LEAP
#define XELEAP            -140

// Special type for Windows to know the timer expired.
#define XEWINTIMEREXPIRED -254


#endif // __XSUP_ERR_H__
