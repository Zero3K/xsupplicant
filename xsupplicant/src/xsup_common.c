/**
 * General routines
 *
 * Licensed under the dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file xsup_common.c
 *
 * \author Carsten Grohmann and chris@open1x.org
 *
 **/

#include <string.h>
#include <stdlib.h>

#ifndef WINDOWS
#include <stdint.h>
#include <ctype.h>
#endif

#include "xsup_common.h"
#include "libxsupconfig/xsupconfig_structs.h"
#include "libxsupconfig/xsupconfig.h"
#include "context.h"
#include "xsup_debug.h"

#ifdef USE_EFENCE
#include <efence.h>
#endif

int in_startup = TRUE;

/**
 * \brief A safer version of strncpy.
 *
 * \param[out] dest     A destination buffer large enough to hold the source string.
 * \param[in] destsize  The size of the destination buffer.
 * \param[in] src       A source string to copy.
 * \param[in] n         The number of characters to copy.
 *
 * \retval 0 on success
 * \retval -1 on failure
 **/
char Strncpy(char *dest, unsigned int destsize, const char *src, size_t n)
{
	if (dest == NULL)
		return -1;
	if (src == NULL)
		return -1;

	if (n > destsize) {
		debug_printf(DEBUG_NORMAL,
			     "Attempt to overflow the destination buffer!\n");

		return -1;
	}
#ifdef WINDOWS
	if (strncpy_s(dest, destsize, src, n) != 0)
		return -1;
#else
	strncpy(dest, src, n);
#endif

	dest[n - 1] = 0x00;
	return 0;
}

/**
 * \brief Allocate memory, and set the allocate memory to all 0s.
 *
 * \param[in] size   The amount of memory to allocate.
 *
 * \retval NULL on error
 * \retval ptr to the allocated memory on success
 **/
void *Malloc(size_t size)
{
	void *ptr = NULL;

	ptr = malloc(size);
	if (ptr != NULL) {
		memset(ptr, 0x00, size);
	}

	return ptr;
}

/**
 * \brief Convert a 1 or 0 to a string of "TRUE" or "FALSE.
 *
 * \param[in] tf   A 1 or a 0 that identifies a value as either true, or
 *                 false.
 *
 * \retval ptr  A pointer to a string that is either TRUE or FALSE depending on
 *              the value of \em tf.
 *
 * \note You have to \em free() the string memory yourself.
 **/
char *xsup_common_is_tf(uint8_t tf)
{
	char *retval = NULL;

	if (tf == FALSE) {
		retval = _strdup("FALSE");
	}

	if (tf == TRUE) {
		retval = _strdup("TRUE");
	}

	return retval;
}

/**
 * \brief A safer string copy function that attempts to avoid writing beyond the
 *        end of the buffer.
 *
 * \param[in] srcstr   The string to copy from.
 * \param[out] deststr   The buffer to copy the string to.
 * \param[out] deststr_len   The length of the buffer to copy to.
 *
 * \retval 0 on success
 * \retval -1 on failure
 **/
char xsup_common_strcpy(char *deststr, unsigned int deststr_len, char *srcstr)
{
	if (strlen(srcstr) + 1 > deststr_len)
	{
		debug_printf(DEBUG_NORMAL, "Attempted to overflow the destination buffer!\n");
		return -1;
	}

	memset(deststr, 0x00, deststr_len);

#ifdef WINDOWS
	// Use the safer string copy for Windows.
	return strcpy_s(deststr, deststr_len, srcstr);
#else
	if (strcpy(deststr, srcstr) == NULL)
		return -1;

	return 0;
#endif
}

/**
 * \brief A safer string concatenation function that attempts to avoid writing
 *        beyond the end of the buffer.
 *
 * \param[in] append   A pointer to the string to append.
 * \param[out] result   A pointer to the string that we want to apped 'append'
 *                      to.
 * \param[in] ressize   An integer value that identifies the size of the buffer
 *                      that result points to.
 *
 * \retval 0 on success
 * \retval -1 on failure
 **/
int Strcat(char *result, unsigned int ressize, char *append)
{
	if (result == NULL)
		return -1;
	if (append == NULL)
		return 0;	// We appended NULL. ;)

	if (ressize == 0)
		return -1;	// Gotta have some kind of buffer.

	if (strlen(append) + 1 > (ressize - strlen(result))) {
		debug_printf(DEBUG_NORMAL, "Would overflow the string!\n");
		return -1;
	}
#ifdef WINDOWS
	strncat_s(result, ressize, append, ressize - strlen(result) - 1);
#else
	strncat(result, append, ressize - strlen(result) - 1);
#endif

	return 0;
}

/**
 * \brief Determine if the supplicant is in "start-up" mode.
 *
 * \retval TRUE if it is
 * \retval FALSE if it isn't
 **/
int xsup_common_in_startup()
{
	return in_startup;
}

/**
 * \brief Change state from startup to normal.
 **/
void xsup_common_startup_complete()
{
	in_startup = FALSE;
}

/**
 * \brief Convert a string in to the uppercase version of the string.
 *
 * @param[in,out] strtoconvert   The mixed case string that will be converted to
 *                               all uppercase.
 **/
void xsup_common_upcase(char *strtoconvert)
{
	int i;

	if (strtoconvert == NULL)
		return;		// If there is nothing to convert, then don't convert it! ;)

	for (i = 0; i < strlen(strtoconvert); i++) {
		strtoconvert[i] = toupper(strtoconvert[i]);
	}
}

/**
 * \brief A modified version of strlen() that returns 0 on NULL.
 *
 * @param[in] str   The string to get the length of.
 *
 * \retval strlen   The length of the string passed in.
 **/
size_t Strlen(const char *str)
{
	if (str == NULL)
		return 0;

	return strlen(str);
}
