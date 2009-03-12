#include <iostream>
#include <iomanip>

#include "RunTests.h"
#include "NonNetworkClasses.h"
#include "AuthTest.h"
#include "Util.h"
    RunTests::RunTests() 
{
	nonNetworkTests_success = 0;
	nonNetworkTests_failed = 0;
	networkTests_success = 0;
	networkTests_failed = 0;
}

RunTests::~RunTests() 
{
	
	    // Clean up our tests.
	    for (vector < TestBase * >::iterator i = nonNetworkTests.begin();
		 i != nonNetworkTests.end(); ++i)
		 {
		delete(*i);
		}
	for (vector < TestBase * >::iterator i = networkTests.begin();
	       i != networkTests.end(); ++i)
		 {
		delete(*i);
		}
}

void RunTests::buildNonNetworkTests() 
{
	nonNetworkTests.push_back(new IPCConnectTest());
	nonNetworkTests.push_back(new ConnectionConfigTests());
	nonNetworkTests.push_back(new ProfileConfigTests());
	nonNetworkTests.push_back(new TrustedServerConfigTests());
	nonNetworkTests.push_back(new GlobalConfigTests());
	nonNetworkTests.push_back(new nnIPCTests());
} void RunTests::buildNetworkTests() 
{
	
	    //networkTests.push_back(new AuthTest());
} void RunTests::executeNonNetworkTests() 
{
	for (vector < TestBase * >::iterator i = nonNetworkTests.begin();
	      i != nonNetworkTests.end(); ++i)
		 {
		if ((*i)->setupTest() == true)
			 {
			cout << "Test : " << (*i)->
			    getTestName() << " : Started\n";
			(*i)->executeTest();
			(*i)->teardownTest();
			}
		if ((*i)->checkResults() == false)
			 {
			
			    // Display our postmortem.
			    cout << "******  Test : " << (*i)->
			    getTestName() << " - FAILED!\n\n\n";
			nonNetworkTests_failed++;
			if ((*i)->terminal_error() == true)
				 {
				cout <<
				    " -- Test indicated this is a terminal error!\n";
				return;
				}
			}
		
		else
			 {
			cout << "Test : " << (*i)->
			    getTestName() << " - OK\n\n\n";
			nonNetworkTests_success++;
			}
		}
}

void RunTests::executeNetworkTests() 
{
	for (vector < TestBase * >::iterator i = networkTests.begin();
	      i != networkTests.end(); ++i)
		 {
		if ((*i)->setupTest() == true)
			 {
			(*i)->executeTest();
			(*i)->teardownTest();
			}
		if ((*i)->checkResults() == false)
			 {
			
			    // Display our postmortem.
			    cout << "******  Test : " << (*i)->
			    getTestName() << " - FAILED!\n";
			networkTests_failed++;
			if ((*i)->terminal_error() == true)
				 {
				cout <<
				    " -- Test indicated this is a terminal error!\n";
				return;
				}
			}
		
		else
			 {
			cout << "Test : " << (*i)->getTestName() << " - OK\n";
			networkTests_success++;
			}
		}
}

void RunTests::showScoreBoard() 
{
	cout << "Non-Network Enabled Tests\n";
	cout << "-------------------------\n";
	cout << "  Success : " << left << setw(10) << Util::
	    itos(nonNetworkTests_success) << setw(10) << "Failed : " << Util::
	    itos(nonNetworkTests_failed) << "\n";
	cout << "\n";
	cout << "Network Enabled Tests\n";
	cout << "---------------------\n";
	cout << "  Success : " << left << setw(10) << Util::
	    itos(networkTests_success) << setw(10) << "Failed : " << Util::
	    itos(networkTests_failed) << "\n";
}
