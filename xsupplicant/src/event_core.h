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

// Maximum number of event handlers we will register.
#define MAX_EVENTS       20

context *event_core_get_active_ctx();
void event_core_set_active_ctx(context *ctx);
context *event_core_get_next_context();
void event_core_init();
void event_core_deinit();
int event_core_terminate();
void event_core();
int event_core_register(int, context *, int(*)(context *, int), int, char *);
void event_core_deregister(int);
context *event_core_locate(char *);
void event_core_reset_locator();
context *events_core_get_next_context();
context *event_core_locate_by_desc(char *);
void event_core_load_user_config();
void event_core_change_wireless(config_globals *newsettings);

#endif
