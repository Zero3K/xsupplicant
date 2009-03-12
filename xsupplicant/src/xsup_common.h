/**
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file xsup_common.h
 *
 * \author Carsten Grohmann and chris@open1x.org
 *
 **/
#ifndef XSUP_COMMON_H_
#define XSUP_COMMON_H_

#ifdef WINDOWS
#include "stdintwin.h"

#include "version.h"
#else
#define _strdup  strdup
#define _unlink  unlink
#endif

// Define some things to make the code more readable.
#define TRUE  1
#define FALSE 0

// Defines that are used for config parsing.
#define PARAM_CONFIG	 1
#define PARAM_INTERFACE  2
#define PARAM_DEBUG		 3
#define PARAM_FOREGROUND 4
#define PARAM_DRIVER	 5
#define PARAM_ZKEYS		 6
#define PARAM_NOTEMP	 7
#define PARAM_TERMINATE  8
#define PARAM_ALTERNATE  9
#define PARAM_CLEAR_CTRL 10
#define PARAM_HELP		 12
#define PARAM_CONNECTION 13

/** Secure strncpy() replacement
 *
 *  Sets the last position of the buffer to 0. All times.
 *  All parameters are equal to strncpy().
 */
char Strncpy(char *dest, unsigned int, const char *src, size_t n);

/** Secure free() replacement
 *
 * Check the pointer before freeing and set it to NULL after the memory
 * has been freed 
 */
#define FREE(p) if (p != NULL) {free(p); p=NULL;}

/** Comfortable malloc() replacement
 *
 *  This function combines malloc() and memset(). It returns NULL in case of
 *  an error on allocating memory. It should used like malloc().
 */
void *Malloc(size_t size);

/**
 * Determine if a value is TRUE or FALSE, and return a text string that can be displayed
 * to a user.
 **/
char *xsup_common_is_tf(uint8_t);

/**
 * Set a bit based on it's bit number.
 **/
#define BIT(x)  (1 << x)

/**
 * A safer string copy.
 **/
char xsup_common_strcpy(char *, unsigned int, char *);

/**
 * A safer string concatenation.
 **/
int Strcat(char *, unsigned int, char *);

/**
 * Are we in the startup phase of the supplicant?
 **/
int xsup_common_in_startup();

/**
 * Change the status to indicate that we are now in "normal" operating mode.
 **/
void xsup_common_startup_complete();

void xsup_common_upcase(char *);
#endif
