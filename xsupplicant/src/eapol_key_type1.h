/**
 * Handle keying for type 1 (RC4, non-TKIP) EAPOL Keys
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file eapol_key_type1.h
 *
 * \author chris@open1x.org
 *
 **/

#ifndef _EAPOL_KEY_TYPE1_H_
#define _EAPOL_KEY_TYPE1_H_

#define UNICAST_KEY     0x80
#define KEY_INDEX       0x7f

/**
 * When a key is set, it isn't unusual for a card to reset itself, and
 * cause a reauthentication.  This value specifies how long we should wait
 * between attempts to rekey before we warn the user that there may be a 
 * keying issue with their card.
 */
#define REKEY_PROB_TIMEOUT  30

struct key_packet {
  uint8_t key_descr;          /**< Key Descriptor Type (802.1x - 7.6.1) */
  uint8_t key_length[2];      /**< Key Length (802.1x - 7.6.2)          */
  uint8_t replay_counter[8];  /**< Replay Counter (802.1x - 7.6.3)      */
  uint8_t key_iv[16];         /**< Key IV (802.1x - 7.6.4)              */
  uint8_t key_index;          /**< Key Index (802.1x - 7.6.5)           */
  uint8_t key_signature[16];  /**< Key Signature (802.1x - 7.6.6)       */
};

void eapol_key_type1_process(context *);

#endif
