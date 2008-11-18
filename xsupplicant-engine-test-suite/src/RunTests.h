/**
 * Run all non network tests that have been pushed in to our vector.
 **/

#include <iostream>
#include <vector>
#include "TestBase.h"

using namespace std;

class RunTests
{
public:
	RunTests();
	~RunTests();

	void buildNonNetworkTests();
	void buildNetworkTests();

	void executeNonNetworkTests();
	void executeNetworkTests();

	void showScoreBoard();
	
private:
	vector<TestBase*> nonNetworkTests;
	vector<TestBase*> networkTests;

	unsigned int nonNetworkTests_success;
	unsigned int nonNetworkTests_failed;

	unsigned int networkTests_success;
	unsigned int networkTests_failed;
};
