/**
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file pmksa.h
 *
 * \author chris@open1x.org
 */

#ifndef __PMKSA_H__
#define __PMKSA_H__

typedef struct {
	pmksa_cache_element *cache_element;
	struct found_ssids *ssid_element;
} pmksa_list;

void pmksa_cache_init(context *ctx);
void pmksa_cache_deinit(context *ctx);
int pmksa_add(context *ctx, uint8_t *aMac);
void pmksa_cache_update(context *ctx);
void pmksa_init_cache_update(context *ctx);
void pmksa_delete(context *ctx, pmksa_cache_element *toDelete);
int pmksa_populate_keydata(context *ctx, uint8_t *pmkid);
void pmksa_generate_okc_data(context *ctx);

#endif  // __PMKSA_H__