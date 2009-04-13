/**
 * A generic queue library.
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file queue.c
 *
 * \author chris@open1x.org
 **/

#ifdef WINDOWS
#include "src/stdintwin.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef WINDOWS
#include <stdint.h>
#endif

#include "queue.h"

/**
 * \brief Initialize a queue structure.
 *
 * @param[in,out] indata   The queue structure that we want to initialize.
 *
 * \retval 0 on success
 * \retval <0 on failure
 **/
int queue_create(queue_data ** indata)
{
	(*indata) = malloc(sizeof(queue_data));
	if ((*indata) == NULL)
		return -1;

	memset((*indata), 0x00, sizeof(queue_data));

	return 0;
}

/**
 * \brief Enqueue some data in to a flat memory queue.
 *
 * The queuesize member of the queue_data structure should always contain the size of the buffer that
 * we currently have allocated.  So, when we enqueue data, we need to realloc() the buffer, insert the
 * new data in to buffer[queuesize], and then increase the value of queuesize by the size of the newly
 * inserted data.
 *
 * @param[in,out] indata   The structure that contains all of the interesting information about the queue.
 * @param[in] newdata   The new data to add to the queue.
 * @param[in] newsize   The size of the data pointed to by newdata.
 *
 * \retval 0 on success
 * \retval -1 on indata not pointing to a valid structure
 * \retval -2 on (*indata) not pointing to a valid structure
 * \retval -3 on structure is inconsistant and shouldn't be trusted
 * \retval -4 couldn't realloc() enough data!  (i.e. Can't enqueue your new data. ;)
 **/
int queue_enqueue(queue_data ** indata, uint8_t * newdata, uint32_t newsize)
{
	queue_data *queue = NULL;
	void *newmem = NULL;

	// First, check for consistancy in the structure.
	if (indata == NULL)
		return -1;	// It NEVER should be!

	queue = (*indata);

	if (queue == NULL)
		return -2;

	if ((queue->queuesize == 0) && (queue->queue != NULL))
		return -3;

	// We believe the structure should be solid.  So
	newmem = realloc(queue->queue, (queue->queuesize + newsize));
	if (newmem == NULL)	// Uh, oh..  We couldn't get enough memory!!! 
		return -4;

	queue->queue = newmem;	// Otherwise, update our pointer.

	memcpy(&queue->queue[queue->queuesize], newdata, newsize);

	queue->queuesize += newsize;

	return 0;
}

/**
 * \brief Dequeue some amount of data.
 *
 * @param[in,out] queuedata   The structure that contains all of the interesting information about the queue.
 * @param[out] outdata   The data that is being returned.
 * @param[in,out] size   (in) The maximum amount of data wanted back.  (out) The amount of data returned.
 *
 * \retval 0 on success (no additional data will be left to read from the queue)
 * \retval 1 on success (more data left to read from the queue)
 * \retval -1 on queuedata is NULL
 * \retval -2 on (*queuedata) is NULL
 * \retval -3 on outdata is NULL
 * \retval -4 on size is NULL
 * \retval -5 on already past the end of the queue!
 * \retval -6 on already at the end of the queue.
 * \retval -7 on couldn't allocate memory to store resulting fragment.
 **/
int queue_dequeue(queue_data ** queuedata, uint8_t ** outdata, uint32_t * size)
{
	queue_data *queue = NULL;

	// Sanity check our structure
	if (queuedata == NULL)
		return -1;

	if ((*queuedata) == NULL)
		return -2;

	if (outdata == NULL)
		return -3;

	if (size == NULL)
		return -4;

	queue = (*queuedata);

	if (queue->cur_offset > queue->queuesize)
		return -5;

	if (queue->cur_offset == queue->queuesize)
		return -6;

	// If the caller is dumb, and asks us for nothing, give it to them. ;)
	if ((*size) == 0) {
		(*outdata) = NULL;
		if (queue->cur_offset < queue->queuesize)
			return 1;

		return 0;
	}
	// If the caller has asked for more data than we have, adjust the request to
	// cover all of the data that remains.
	if ((*size) > (queue->queuesize - queue->cur_offset)) {
		(*size) = (queue->queuesize - queue->cur_offset);
	}

	(*outdata) = malloc((*size));
	if ((*outdata) == NULL)
		return -7;

	memcpy((*outdata), &queue->queue[queue->cur_offset], (*size));

	queue->cur_offset += (*size);

	if (queue->cur_offset < queue->queuesize)
		return 1;

	return 0;
}

/**
 * \brief Get the size of the data in a queue.
 *
 * @param[in] queuedata   The queue that we want to determine the size of.
 * @param[out] datasize   The size of the data that is in the queue.
 *
 * \retval 0 on success
 * \retval <0 on error
 **/
int queue_get_size(queue_data ** queuedata, uint32_t * datasize)
{
	queue_data *queue = NULL;

	// Verify that the structure seems to be valid.
	if (queuedata == NULL)
		return -1;

	if ((*queuedata) == NULL)
		return -2;

	if (datasize == NULL)
		return -3;

	queue = (*queuedata);

	if ((queue->queuesize > 0) && (queue->queue == NULL))
		return -4;

	// Otherwise, we can be pretty confident that our queue depth value is correct.
	(*datasize) = queue->queuesize;

	return 0;
}

/**
 * \brief Destroy the data in a queue.
 *
 * @param[in,out] queuedata   The structure that contains the data we want to destroy.
 *
 * \retval 0 on success
 * \retval <0 on error
 **/
int queue_destroy(queue_data ** queuedata)
{
	queue_data *queue = NULL;

	if (queuedata == NULL)
		return -1;

	if ((*queuedata) == NULL)
		return -2;

	queue = (*queuedata);

	if (NULL != queue->queue) {
		free(queue->queue);
		queue->queue = NULL;
	}

	queue->cur_offset = 0;
	queue->queuesize = 0;

	free((*queuedata));

	(*queuedata) = NULL;

	return 0;
}

/**
 * \brief Determine if the queue pointer is at the beginning of the queue.
 *
 * @param[in] queuedata   The structure that stores the information about the queue we want
 *                        to get data from.
 * 
 * \retval 1 if it is at the head
 * \retval 0 if it is not at the head
 * \retval <0 on error
 **/
int queue_at_head(queue_data ** queuedata)
{
	queue_data *queue = NULL;

	if (queuedata == NULL)
		return -1;

	if ((*queuedata) == NULL)
		return -2;

	queue = (*queuedata);

	if (queue->cur_offset == 0)
		return 1;

	return 0;
}

/**
 * \brief Determine if we are at the end of a queue.
 *
 * @param[in] queuedata   A pointer to the queue that we want to check to see if we are at the end of.
 *
 * \retval 1 if we are at the end
 * \retval 0 if we are not at the end
 * \retval <0 on error
 **/
int queue_queue_done(queue_data ** queuedata)
{
	queue_data *queue = NULL;

	if (queuedata == NULL)
		return -1;

	if ((*queuedata) == NULL)
		return -2;

	queue = (*queuedata);

	if (queue->cur_offset >= queue->queuesize)
		return 1;

	return 0;
}
