/**
 * A debug log ringbuffer plugin.
 *
 * Licensed under the dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file birddog.c
 *
 * \author galimorerpg@users.sourceforge.net
 *
 **/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifdef WIN32
#include <windows.h>
#include <stdintwin.h>
#ifdef _DLL
#define DLLMAGIC __declspec(dllexport)

//typedef strdup _strdup;

#else
#define DLLMAGIC __declspec(dllimport)
#endif 	// _DLL
#endif // WIN32

#ifndef WIN32  // Non-Windows platforms need a stub
#include <stdint.h>
#define DLLMAGIC 
#endif //WIN32


// 1MB of buffer.
//#define MAX_BUFFER 1048576
// 2MB of buffer.
//#define MAX_BUFFER 2097152
// 3MB of buffer.
//#define MAX_BUFFER 3145728
// 4MB of buffer.
//#define MAX_BUFFER 4194304
// 5MB of buffer.
#define MAX_BUFFER (1024 * 1024 * 5)

#ifdef WIN32
HANDLE growMutex = NULL;
HANDLE trimMutex = NULL;
#endif // WIN32

// A list of commands to run for a given system to gather additional debug data.
char *trouble_ticket_commands[10] =
{
#ifdef WIN32
	"sc queryex state= all",
	"ipconfig /all",
	"netsh firewall show state",
#endif // WIN32
	NULL
};

struct debug_ring 
{
  struct debug_ring *next;
  uint32_t size;
  char *msg;
}debug_ring;

struct debug_ring *head  = NULL;
struct debug_ring *tail  = NULL;
unsigned int buffer_size = 0;
unsigned int log_lines   = 0;

void add_to_buffer(char *msg);
void trim_buffer_to_size(unsigned long bufferSize);

// Supplicant entrypoint
void DLLMAGIC initialize()
{
	// These are already initialized by the defines above.  If you init them here, you
	// will lose the log message indicating that birddog has been loaded, and leak some memory.
  //buffer_size = 0;
  //head = NULL;
  //tail = NULL;

	// Set up our mutexes here:
#ifdef WIN32
	growMutex = CreateMutex(NULL, 0, NULL);
	trimMutex = CreateMutex(NULL, 0, NULL);
#endif // WIN32
}

// Supplicant entrypoint
void DLLMAGIC cleanup()
{
  struct debug_ring *tmp = NULL;

#ifdef WIN32
  WaitForSingleObject(trimMutex, INFINITE);
  WaitForSingleObject(growMutex, INFINITE);
#endif // WIN32

  // Empty the buffer out.
  // Technically the check is <= 0, but we should never be less than
  // And we should never get into a situation where we can't flush properly
  // otherwise that's a bug.
  trim_buffer_to_size(0);

  //printf("\n[PLUGIN] - %d - Log Lines Left!\n", log_lines);

  // Clean up our mutexes:
#ifdef WIN32
  CloseHandle(growMutex);
  growMutex = NULL;

  CloseHandle(trimMutex);
  trimMutex = NULL;
#endif // WIN32
}

// Supplicant entrypoint
void DLLMAGIC log_hook_full_debug(char *msg)
{
	if(msg != NULL)
	{
		// Try to acquire the grow mutex.
#ifdef WIN32
		if(WaitForSingleObject(growMutex, INFINITE) != WAIT_OBJECT_0) {
			// If we failed to acquire the mutex, then don't 
			// fill the buffer.
			return;
		}
#endif // WIN32

		// Add the message to the buffer.
		add_to_buffer(msg);

#ifdef WIN32
		ReleaseMutex(growMutex);
#endif // WIN32

		// Try to acquire the trim mutex.
		// Time out quickly, so we don't block the main thread.
		// 50ms should be plenty.
#ifdef WIN32
		if(WaitForSingleObject(trimMutex, 50) != WAIT_OBJECT_0) {
			// If we can't acquire the trim mutex, don't trim the buffer.
			return;
		}
#endif // WIN32

		if(buffer_size > MAX_BUFFER) {
			// Trim from the buffer until we're <= MAX_BUFFER
			trim_buffer_to_size(MAX_BUFFER);
		}

#ifdef WIN32
		ReleaseMutex(trimMutex);
#endif // WIN32
	}
}

// Private function
void add_to_buffer(char *msg)
{
  struct debug_ring *tmp = NULL;

  //printf("\n[PLUGIN] Adding Message: %s (%d - %d)\n", msg, buffer_size, log_lines);

  if(tail == NULL) 
    {
      head = calloc(1, sizeof(struct debug_ring));
      tail = head;
    }
  else
    {
      tail->next = calloc(1, sizeof(struct debug_ring));
      tail = tail->next;
    }
  
  if(msg != NULL) 
  {
	  // Go ahead and add the log message
	  tail->msg    = strdup(msg);
	  tail->size   = strlen(msg);
	  buffer_size += tail->size;
	  log_lines ++;
  }
}

/*
 * Hook function to force a dump of the debug buffer contents to file.
 *
*/
int DLLMAGIC plugin_hook_trouble_ticket_dump_file(char *file) 
{
	FILE *logfile                = NULL;
	struct debug_ring *current   = NULL;
	int index                    = 0;
	char *install_path           = NULL;
	char *command                = NULL;
	size_t command_size          = 0;
	unsigned long log_size       = 0;    // Counter for how many bytes we've written to the file.

	// Grab the trim mutex, so log lines can't be deleted while we write out the log file.
#ifdef WIN32
		if(WaitForSingleObject(trimMutex, INFINITE) != WAIT_OBJECT_0) {
			// If we can't acquire the trim mutex, bail out.
			return;
		}
#endif // WIN32

		// Don't set this until after we've locked, else head might be trash.
		current = head;

		// Open the file for writing.
		logfile = fopen(file, "w");

		if(logfile == NULL)
		{
			printf("[PLUGIN] Error: BirdDog trouble ticket file pointer is NULL.  Can't dump logs.\n");
		}
		else
		{
			while(current != NULL)
			{
				if(current->msg != NULL)
				{
#ifdef WIN32
					if(WaitForSingleObject(growMutex, INFINITE) != WAIT_OBJECT_0) {
						// If we can't acquire the grow mutex, bail out.
						return;
					}
#endif // WIN32

					fputs(current->msg, logfile);

					log_size += current->size;

#ifdef WIN32
					ReleaseMutex(growMutex);
#endif // WIN32

					// Write out up to MAX_BUFFER
					// We don't go beyond this so we can avoid a race if
					// log lines are continually being added
					if(log_size >= MAX_BUFFER) {
						break;
					}
				}

				current = current->next;
			}

			fclose(logfile);
		}

		// Additionally, run any trouble ticket commands and append the data to the log file.
		for(index = 0; /* We don't know how big the list is, but it contains a NULL as the last entry. ;) */ ; index++ )
		{
			// Bail out when we hit the end of the list
			if(trouble_ticket_commands[index] == NULL)
				break;

			if(file == NULL)
				break;

			command_size = (strlen(trouble_ticket_commands[index]) * 2) + 2;
			command_size += (strlen(file) * 2) + 4;

			command = calloc(1, command_size);

			strcat(command, trouble_ticket_commands[index]);
			strcat(command, ">>");
			strcat(command, file);

			if(command != NULL)
			{
				system(command);
				free(command);
				command = NULL;
			}
			else
			{
				printf("[PLUGIN] Error: command is NULL in %s:%d\n", __FUNCTION__, __LINE__);
			}

		}

#ifdef WIN32
		ReleaseMutex(trimMutex);
#endif // WIN32

		return 0;
}


BOOL WINAPI DllMain(
					HANDLE hinstDLL, 
					DWORD dwReason, 
					LPVOID lpvReserved
					)
{
	return 1;
}

void trim_buffer_to_size(unsigned long bufferSize) 
{
	struct debug_ring *tmp = NULL;

	// Trim off any excess log messages
	while(buffer_size > bufferSize) 
	{
		if(head != NULL)
		{
			tmp = head;

			head = head->next;

			if(head == NULL)
			{
				tail = NULL;
			}

			//printf("\n[PLUGIN] Deleting message: %s (%d - %d)\n", tmp->msg, buffer_size, log_lines);
			buffer_size -= tmp->size;
			log_lines--;

			if(tmp->msg != NULL)
			{
				free(tmp->msg);
				tmp->msg = NULL;
				tmp->size = 0;
			}

			free(tmp);
			tmp = NULL;
		}
		else
		{
			// Hmm HEAD is NULL for some reason.
          // Reset the size to 0
          buffer_size = 0;
          tail = NULL;
      }
    }	
}
