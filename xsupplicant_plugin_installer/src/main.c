#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdlib.h>
    
#ifdef WINDOWS
#include <shlobj.h>
#endif	
    
#include "getopts.h"
#include "libxsupconfig/xsupconfig.h"
#include "libxsupconfig/xsupconfig_vars.h"
#include "libxsupconfwrite/xsupconfwrite.h"
    
#define NO_MEMORY_AVAIL   1
#define GENERAL_FAILURE	  2
#define NOT_ENOUGH_DATA	  3
#define BAD_CONFIG_PATH   4
    
// Stubs needed to make the build happy.
int error_prequeue_add(char *na) 
{
	return 0;
}

int crashdump_add_file(char *na) 
{	
	return 0;
}

int ipc_events_log_msg(char *na) 
{	
	return 0;
}

#ifdef WINDOWS

void win_impersonate_back_to_self() 
{
} 

int win_impersonate_desktop_user() 
{	
	return 0;
}

/**
 * \brief Get the path to the data store for the machine.
 *
 * \retval NULL on error, otherwise the path to the location that global supplicant data should be stored.
 **/ 
char *platform_get_machine_data_store_path() 
{	
	TCHAR szMyPath[MAX_PATH];	
	char *path = NULL;

	if (FAILED(SHGetFolderPath(NULL, CSIDL_COMMON_APPDATA, NULL, 0, szMyPath)))	
	{	
		printf("Couldn't determine the path to the common app data.\n");
		return NULL;
	}
	
	path = _strdup(szMyPath);
	return path;
}

#endif	

int need_install_plugin(struct config_plugins *plugs, char *name) 
{
	struct config_plugins *cur = NULL;

	cur = plugs;
	
	while ((cur != NULL) && (strcmp(cur->name, name) != 0))
		cur = cur->next;

	if (cur == NULL)
		return 1;
	
	return 0;
}

int add_plugin(struct config_plugins *plugs, char *name, char *path,
		 char *description, int disabled) 
{		
	struct config_plugins *cur = NULL;
	struct config_plugins *newplug = NULL;
	
	newplug = malloc(sizeof(struct config_plugins));
	if (newplug == NULL)
		return NO_MEMORY_AVAIL;
	
	memset(newplug, 0x00, sizeof(struct config_plugins));
	
	newplug->name = _strdup(name);
	newplug->path = _strdup(path);
	
	if (description != NULL)
		newplug->description = _strdup(description);
	
	if (disabled == 1)
		newplug->enabled = 0;
	else
		newplug->enabled = 1;
	
	return add_change_config_plugins(newplug);
}

int install_plugin(char *name, char *path, char *description, int disabled) 
{	
	char *path_to_config = NULL;
	char *temp = NULL;
	struct config_plugins *my_conf_plugins = NULL;
	int result = 0;
	
	temp = platform_get_machine_data_store_path();
	if (temp == NULL)
		return BAD_CONFIG_PATH;
	
	path_to_config = malloc(strlen(temp) + 20);
	if (path_to_config == NULL)
		return BAD_CONFIG_PATH;
	
	strcpy(path_to_config, temp);
	strcat(path_to_config, "\\xsupplicant.conf");
	free(temp);
	
	if (config_system_setup(path_to_config) != 0)
	 {
	    // No config exists, set up a default one.
	    printf("New config.\n");
		initialize_config_globals(&conf_globals);
	}
	
	my_conf_plugins = config_get_plugins();
	if (need_install_plugin(my_conf_plugins, name) == 1)
	{
	    // Add our plugin to the list.
	    if ((result = add_plugin(my_conf_plugins, name, path, description,
				    disabled)) == 0)
		{
		    // Save our plugin.
		    result = xsupconfwrite_write_config(path_to_config);	// Write it to the default path.
		}
	}

	free(path_to_config);

	return result;
}

int main(int argc, char *argv[]) 
{
	struct options opts[] = 
	    { 
			{1, "description", "Set a description for a plugin.", "d", 1}, 
			{2, "name", "Set a name for a plugin.", "n", 1}, 
			{3, "disabled", "Install the plugin disabled.", "i", 0}, 
			{4, "path", "Path to the plugin.", "p", 1} 
		};
	int op;
	char *args = NULL;
	char *description = NULL, *name = NULL, *path = NULL;
	int disabled = 0;
	
	while ((op = getopts(argc, argv, opts, &args)) != 0)
	{
		switch (op)
		{
		case -2:
			printf("Unknown option: %s\n", args);
			break;
		
		case -1:
			printf("Unable to allocate memory in getops()!\n");
			return NO_MEMORY_AVAIL;
			break;
		
		case 1:
			description = args;
			break;
		
		case 2:
			name = args;
			break;
		
		case 3:
		    // Should we install this plugin as disabled?
		    disabled = 1;
			break;
		
		case 4:
			path = args;
			break;
		
		default:
			printf("Unknown option provided!\n");
			return GENERAL_FAILURE;
		}
	}
	
	if ((name == NULL) || (path == NULL))
	{
		printf("Invalid name or path!\n");
		return NOT_ENOUGH_DATA;
	}
	
	return install_plugin(name, path, description, disabled);
}
