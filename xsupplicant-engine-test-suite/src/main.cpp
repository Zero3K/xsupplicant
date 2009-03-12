/**
 * Main Controller functions for the XSupplicant automated test tool.
 *
 * \author chris@open1x.org
 **/  
    
#include "RunTests.h"
    
// Provide some empty functions to make the linker happy.
extern "C" {
	 int crashdump_add_file(char *temp, char temp2)  {
		return 0;
	}
}
int main() 
{
	RunTests testsuite;
	testsuite.buildNonNetworkTests();
	testsuite.executeNonNetworkTests();
	testsuite.buildNetworkTests();
	testsuite.executeNetworkTests();
	testsuite.showScoreBoard();
	printf("Done\n");
} 
