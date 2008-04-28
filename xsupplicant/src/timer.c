/**
 * \file timer.c
 *
 * Implement a one second timer that will call functions in a linked list.
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \author chris@open1x.org
 *
 **/

#include <stdio.h>
#include <stdlib.h>

#ifndef WINDOWS
#include <stdint.h>
#include <inttypes.h>
#include <unistd.h>
#endif

#include "libxsupconfig/xsupconfig_structs.h"
#include "xsup_common.h"
#include "libxsupconfig/xsupconfig.h"
#include "context.h"
#include "xsup_debug.h"
#include "timer.h"
#include "ipc_events.h"
#include "ipc_events_index.h"

#ifdef USE_EFENCE
#include <efence.h>
#endif

// Uncomment the TIMER_DEBUG below to have Xsupplicant dump the timer counters each time
// through the loop.  (You generally don't want to do this!)
//#define TIMER_DEBUG       1

struct timer_ids_struct {
  uint16_t timer_id;
  char *timer_id_name;
};

struct timer_ids_struct timer_ids[] = {
  {0, "invalid timer"},
  {COUNTERMEASURE_TIMER, "countermeasure timer"},
  {REKEY_PROB_TIMER, "rekey problem timer"},
  {ASSOCIATION_TIMER, "association timer"},
  {STALE_KEY_WARN_TIMER, "stale key warning timer"},
  {PASSIVE_SCAN_TIMER, "passive scan timer"},
  {RESCAN_TIMER, "rescan timer"},
  {SCANCHECK_TIMER, "scan result timer"},
  {INT_HELD_TIMER, "interface held timer"},
  {SIG_STRENGTH, "signal strength indicator"},
  {PSK_DEATH_TIMER, "PSK validation timer"},
  {PMKSA_CACHE_MGMT_TIMER, "PMKSA cache management timer"}
};

/*****************************
 * 
 * Set up the linked list of timers that we will be using, and make sure
 * it is empty.
 *
 *****************************/
void timer_init(context *ctx)
{
  ctx->timers = NULL;
  debug_printf(DEBUG_INIT | DEBUG_TIMERS, "Init timer!\n");
}

/*****************************
 *
 * Locate the timer structure by id number.
 *
 *****************************/
struct timer_data *timer_get_by_id(context *ctx, uint16_t id)
{
  struct timer_data *cur;

  cur = ctx->timers;

  while ((cur != NULL) && (cur->timer_id != id))
    {
      cur = cur->next;
    }

  return cur;
}

/*****************************
 *
 * Reset the "seconds_left" value of a timer.
 *
 *****************************/
uint8_t timer_reset_timer_count(context *ctx, uint16_t timer_id, uint16_t seconds_left)
{
  struct timer_data *timer;
  char *timername;

  timer = timer_get_by_id(ctx, timer_id);

  if (timer == NULL)
    {
      timername = timer_get_name_from_id(timer_id);
      if (timername == NULL)
	{
	  debug_printf(DEBUG_NORMAL, "Couldn't reset timeout for unknown "
		       "timer with id %d!\n", timer_id);
	  return FALSE;
	} else {
	  debug_printf(DEBUG_NORMAL, "Couldn't reset timeout for timer '%s'!"
		       "\n", timername);
	  return FALSE;
	}
    }

  timer->seconds_left = seconds_left;
  return TRUE;
}

/*****************************
 *
 * Given a timer id #, look up the string name of the ID.
 *
 *****************************/
char *timer_get_name_from_id(uint16_t id)
{
  uint16_t i = 0;

  while ((i<NUM_TIMER_IDS) && (!(timer_ids[i].timer_id == id)))
    {
      i++;
    }

  if (timer_ids[i].timer_id == id)
    {
      return timer_ids[i].timer_id_name;
    }

  return NULL;
}

/*****************************
 *
 * Check to see if the timer already exists in the list.  Return FALSE if
 * the timer is not currently in the list, and TRUE if it is.
 *
 *****************************/
uint8_t timer_check_existing(context *ctx, uint16_t timertype)
{
  struct timer_data *cur;

  cur = ctx->timers;

  if (cur == NULL) 
    {
      debug_printf(DEBUG_TIMERS, "No existing timers in the list!\n");
      return FALSE;
    }

  while (cur != NULL)
    {
      if (cur->timer_id == timertype) 
	{
	  debug_printf(DEBUG_TIMERS, "Matched existing timer! (Timer "
		       "was : '%s')\n", timer_get_name_from_id(timertype));
	  return TRUE;
	}

      cur = cur->next;
    }

  return FALSE;
}

/*****************************
 *
 * Add a node to our timer list.
 *
 *****************************/
void timer_add_timer(context *ctx, uint16_t timertype, uint16_t timeout, void *timertick, 
		     void *timerexpired)
{
  struct timer_data *cur = NULL;

  if (!xsup_assert((timeout != 0), "timeout != 0", FALSE)) 
  {
	  debug_printf(DEBUG_NORMAL, "Timer was : %s\n", timer_get_name_from_id(timertype));
	  return;
  }

  if (ctx->timers == NULL)
    {
      ctx->timers = (struct timer_data *)Malloc(sizeof(struct timer_data));
      if (ctx->timers == NULL)
	{
	  debug_printf(DEBUG_NORMAL, "Couldn't allocate memory to add timer "
		       "to our list!  We may have strange results!\n");
	  ipc_events_malloc_failed(ctx);
	  return;
	}

      cur = ctx->timers;
    } else {
      if (timer_check_existing(ctx, timertype) == TRUE)
	{
	  debug_printf(DEBUG_EVENT_CORE, "Attempt to add a timer that already "
		       "exists!  Ignoring!\n");
	  return;
	}

      cur = ctx->timers;

      while (cur->next != NULL)
	{
	  cur = cur->next;
	}

      cur->next = (struct timer_data *)Malloc(sizeof(struct timer_data));
      if (cur->next == NULL)
	{
	  debug_printf(DEBUG_NORMAL, "Couldn't allocate memory for timer "
		       "node!  We may have strange results!\n");
	  return;
	}

      cur = cur->next;
    }

  // At this point, cur should point to a node that was just created.
  cur->next = NULL;
  cur->timer_id = timertype;
  cur->seconds_left = timeout;
  cur->timer_tick = timertick;
  cur->timer_expired = timerexpired;
}

/*******************************************************
 *
 *  Execute a single clock tick on all registered handlers.
 *
 *******************************************************/
void do_tick(struct timer_data *cur, context *ctx)
{
  int retval = 0;

  if (!xsup_assert((cur != NULL), "cur != NULL", FALSE)) return;

  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE)) return;

  cur->seconds_left--;

#ifdef TIMER_DEBUG
  debug_printf(DEBUG_NORMAL, "timer : %s ... %d second(s) remain.\n", timer_get_name_from_id(cur->timer_id), cur->seconds_left);
#endif
  
  if (cur->timer_tick != NULL)
    {
      // If something other than 0 is returned, then the pointer was
      // probably freed out from under us. :-/
      retval = cur->timer_tick(ctx);

      if (retval != 0) return;
    }

  // If something changed bail out.
  if (cur == NULL) return;

  if (cur->seconds_left <= 0)
    {
      if (cur->timer_expired != NULL)
		{
			cur->timer_expired(ctx);
		}
    }
}



/*****************************
 *
 * Called once a second, this function should execute the "on_tick" function
 * in the timer.
 *
 *****************************/
void timer_tick(context *intdata)
{
  struct timer_data *cur, *next;

  if (!xsup_assert((intdata != NULL), "intdata != NULL", FALSE))
    return;

  intdata->tick = FALSE;

  cur = intdata->timers;

  if (cur == NULL)
    {
      // We don't have any timers to tick.
      return;
    }

  // Otherwise, tick all of our timers.
  while (cur != NULL)
    {
      next = cur->next;
      do_tick(cur, intdata);

      cur = next;
    }
}


/*****************************
 *
 * Cancel an existing timer by removing it from the linked list.
 *
 *****************************/
void timer_cancel(context *ctx, uint16_t timertype)
{
  struct timer_data *cur, *prev;
  char *timername;

  // Be sure we have something to work with.
  if (ctx->timers == NULL)
    {
      timername = timer_get_name_from_id(timertype);
      if (timername == NULL)
		{
			debug_printf(DEBUG_NORMAL, "No timers to cancel for unknown timer "
		       "type %d!\n", timertype);
			return;
		} else {
			debug_printf(DEBUG_TIMERS, "No timers to cancel for '%s'!\n",
		       timername);
			timername = NULL;
			return;
		}
    }

  // See if the first node has what we are looking for.
  if (ctx->timers->timer_id == timertype)
    {
      // We found the timer to cancel.
      cur = ctx->timers;
      ctx->timers = ctx->timers->next;

      FREE(cur);

      timername = timer_get_name_from_id(timertype);
      if (timername == NULL)
	{
	  debug_printf(DEBUG_TIMERS, "Canceled timer for unknown timer id %d!\n", timertype);
	} else {
	  debug_printf(DEBUG_TIMERS, "Canceled timer for '%s'!\n",
		       timername);
	}
      return;
    }

  // Now, check the rest.
  cur = ctx->timers->next;
  prev = ctx->timers;

  while ((cur != NULL) && (cur->timer_id != timertype))
    {
      prev = cur;
      cur = cur->next;
    }

  if (cur == NULL)
    {
      debug_printf(DEBUG_TIMERS, "Attempted to cancel timer that doesn't "
		   "exist!  (Timer was : '%s')\n", 
		   timer_get_name_from_id(timertype));
      return;
    }

  if (cur->timer_id == timertype)
    {
      prev->next = cur->next;

      FREE(cur);
  
      timername = timer_get_name_from_id(timertype);
      if (timername == NULL)
	{
	  debug_printf(DEBUG_TIMERS, "Canceled timer for unknown timer id"
		       " %d!\n", timertype);
	} else {
	  debug_printf(DEBUG_TIMERS, "Canceled timer for '%s'!\n",
		       timername);
	}
    } else {
      timername = timer_get_name_from_id(timertype);
      if (timername == NULL)
	{
	  debug_printf(DEBUG_NORMAL, "Request to cancel timer for unknown "
		       "timer id %d, failed because the timer is not in the "
		       "list!\n", timertype);
	} else {
	  debug_printf(DEBUG_NORMAL, "Request to cancel timer '%s' failed "
		       "because the timer is not in the list!\n", timername);
	}
    }
  return;
}

/*****************************
 *
 * Free up the memory being used in the linked list.
 *
 *****************************/
void timer_cleanup(context *ctx)
{
  struct timer_data *cur, *next;

  cur = ctx->timers;

  while (cur != NULL)
    {
      next = cur->next;

      FREE(cur);
      cur = next;
    }

  ctx->timers = NULL;
}

