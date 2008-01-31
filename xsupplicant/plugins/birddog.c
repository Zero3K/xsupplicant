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

char locked = 0;               // Poor man's mutex to avoid two threads writing at the same time.

void add_to_buffer(char *msg);

// Supplicant entrypoint
void DLLMAGIC initialize()
{
  buffer_size = 0;
  head = NULL;
  tail = NULL;
}

// Supplicant entrypoint
void DLLMAGIC cleanup()
{
  struct debug_ring *tmp = NULL;

  while(head != NULL) 
    {
      tmp = head;
      head = head->next;

      if(tmp->msg != NULL) {
	//printf("\n[PLUGIN] Deleting message: %s (%d - %d)\n", tmp->msg, buffer_size, log_lines);

	free(tmp->msg);
	buffer_size -= tmp->size;
      }

      log_lines--;     
      free(tmp);
    }

  //printf("\n[PLUGIN] - %d - Log Lines Left!\n", log_lines);

}

// Supplicant entrypoint
void DLLMAGIC log_hook_full_debug(char *msg)
{
  int index = 0;

  while (locked == 1)
  {
#ifdef WINDOWS
	  Sleep(0);   // This should cause us to allow the other thread to run.  (XXX What about other OSes?)
#endif
  }

  locked = 1;   // Lock.

  if(msg != NULL)
    {
      add_to_buffer(msg);      
    }

  locked = 0;   // Unlock.
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
  
  if(tail != NULL) 
    {
      // Go ahead and add the log message
      tail->msg    = strdup(msg);
      tail->size   = strlen(msg);
      buffer_size += tail->size;
      log_lines ++;
    }

  // Trim off any excess log messages
  while(buffer_size > MAX_BUFFER) 
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
            }

	        free(tmp);
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

/*
 * Hook function to force a dump of the debug buffer contents to file.
 *
*/
int DLLMAGIC plugin_hook_trouble_ticket_dump_file(char *file) 
{
	FILE *logfile                = NULL;
	struct debug_ring *current   = head;
	int index                    = 0;
	char *install_path           = NULL;
	char *command                = NULL;
	size_t command_size          = 0;

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
				fputs(current->msg, logfile);
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