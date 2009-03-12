#include <Windows.h>
#include <iostream>
#include <string>
#include <sstream>

#include "Util.h"
#include "stdlib.h"
    Util::Util() 
{
}

void Util::restartEngine(int timeout) 
{
	system("net stop xsupplicant > NUL");
	Sleep(timeout * 1000);
	system("net start xsupplicant > NUL");
} string Util::itos(int i)	// convert int to string
{
	stringstream s;
	s << i;
	return s.str();
}


