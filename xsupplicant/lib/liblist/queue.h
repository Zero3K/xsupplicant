/**
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \author chris@open1x.org
 *
 **/
#ifndef __QUEUE_H__
#define __QUEUE_H__

typedef struct _queue_data {
	uint32_t queuesize;
	uint32_t cur_offset;
	
	uint8_t *queue;
} queue_data;

int queue_create(queue_data **);
int queue_enqueue(queue_data **, uint8_t *, uint32_t);
int queue_dequeue(queue_data **, uint8_t **, uint32_t *);
int queue_destroy(queue_data **);
int queue_get_size(queue_data **, uint32_t *);
int queue_at_head(queue_data **);
int queue_queue_done(queue_data **);

#endif // __QUEUE_H__

