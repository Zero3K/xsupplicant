/**
 * Handle MIC routines.
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file mic.h
 *
 * \author chris@open1x.org
 *
 **/

#ifndef _MIC_H_
#define _MIC_H_

/* How long should we wait when we enable countermeasures. */
#define MIC_COUNTERMEASURE_TIMEOUT   60

void mic_process(char *, int, char *, int, int, char *);
int mic_wpa_validate(char *, int, char *, int);
void mic_wpa_populate(char *, int, char *, int);
void mic_disable_countermeasures(context *);

#endif
