/**
 * These are stub functions that are necessary to link but not necessary for the functioning of
 * the libxsupgui library.
 *
 * Both the UI library and the engine use the same set of parser/writer routines.  Because the
 * engine runs as a user other than the desktop user, it must be able to impersonate the desktop user
 * to allow it to encrypt/decrypt passwords with the user's private encryption password.  In the libxsupgui
 * library, this isn't needed since the UI will be running as the desktop user, and the encryption functions
 * already take care of the case when we need to encrypt with the machine's private encryption password.
 **/  
int win_impersonate_desktop_user() 
{
	return 0;
}

void win_impersonate_back_to_self() 
{
} 
