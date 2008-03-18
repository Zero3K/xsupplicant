/**
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \author chris@open1x.org
 *
 **/

#ifndef _EVENT_CORE_H_
#define _EVENT_CORE_H_

// Priority values for event_core_register();
#define HIGH_PRIORITY    0
#define ANY_PRIORITY     1
#define LOW_PRIORITY     2

// Values for our sleep state machine.
#define PWR_STATE_RUNNING      0
#define PWR_STATE_SLEEPING     1
#define PWR_STATE_SLEEP_CANCEL 2
#define PWR_STATE_WAKING_UP    3
#define PWR_STATE_HELD         4

// Event flags
#define EVENT_IGNORE_INT       BIT(0)
#define EVENT_PRIMARY		   BIT(7)  // This event handler slot does accept frames.
#define EVENT_SECONDARY 	   BIT(6)  // This event handler slot doesn't accept frames, but needs a context anyway.

// Starting maximum number of event handlers we will register.  (This will be dynamically increased as needed.)
#define STARTING_EVENTS       20
#define EVENT_GROW            5    // The number of additional event slots to add when we run out.

void event_core_init();
void event_core_deinit();
void event_core();
context *event_core_get_active_ctx();
void event_core_terminate();
int event_core_register(HANDLE, context *, int(*)(context *, HANDLE), uint8_t, int, char *);
void event_core_deregister(HANDLE, uint8_t);
context *event_core_locate(char *);
LPOVERLAPPED event_core_get_ovr(HANDLE, uint8_t);
int event_core_set_ovr(HANDLE devHandle, uint8_t eventType, LPOVERLAPPED lovr);
context *event_core_locate_by_caption(wchar_t *, int);
context *event_core_locate_by_desc(char *);
context *event_core_locate_by_desc_strstr(char *);
context *event_core_get_next_context();
void event_core_reset_locator();
void event_core_going_to_sleep();
void event_core_cancel_sleep();
void event_core_waking_up();
void event_core_going_to_sleep_thread_ctrl();
void event_core_cancel_sleep_thread_ctrl();
void event_core_waking_up_thread_ctrl();
void event_core_check_state();
void event_core_user_logged_on();
void event_core_user_logged_off();
uint32_t event_core_register_imc_logon_callback(void *callback);
uint32_t event_core_register_ui_connect_callback(void *callback);
int event_core_lock();
int event_core_unlock();

#endif
