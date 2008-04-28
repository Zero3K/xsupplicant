/*******************************************************************
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file timer.h
 *
 * \author chris@open1x.org
 *
 *******************************************************************/

#ifndef _TIMER_H_
#define _TIMER_H_

// Different types of timers that we will use.
#define NUM_TIMER_IDS   12

// BE SURE THAT IF YOU ADD A TIMER HERE, THAT YOU ADD IT'S DEF. IN timer.c!
#define COUNTERMEASURE_TIMER   1
#define REKEY_PROB_TIMER       2
#define ASSOCIATION_TIMER      3
#define STALE_KEY_WARN_TIMER   4
#define PASSIVE_SCAN_TIMER     5
#define RESCAN_TIMER           6
#define SCANCHECK_TIMER        7
#define INT_HELD_TIMER         8
#define SIG_STRENGTH           9
#define PSK_DEATH_TIMER        10
#define PMKSA_CACHE_MGMT_TIMER 11

struct timer_data
{
  uint16_t seconds_left;     // How many seconds are left before this timer
                             // expires.
  uint16_t timer_id;         // A numeric identifier that indicates what
                             // type of timer this is.  (From above)
  int8_t (*timer_tick)(context *);
  int8_t (*timer_expired)(context *);

  struct timer_data *next;
};

void timer_init(context *);
void timer_add_timer(context *, uint16_t, uint16_t, void *, void *);
void timer_tick(context *);
uint8_t timer_reset_timer_count(context *, uint16_t, uint16_t);
char *timer_get_name_from_id(uint16_t);
uint8_t timer_check_existing(context *, uint16_t);
struct timer_data *timer_get_by_id(context *, uint16_t);
void timer_cancel(context *, uint16_t);
void timer_cleanup(context *);
void timer_clock_start(context *);

#endif
