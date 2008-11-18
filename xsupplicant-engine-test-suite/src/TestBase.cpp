/**
 * Base class definitions for the NonNetworkBase class of tests. 
 *    The purpose of these implementations is to complain about non-existant test members.
 *    As a result, any derived classes should override ALL of the members (except the constructor and destructor), even if they do nothing
 *    but return true.
 **/
#include <iostream>
#include <iomanip>
#include "TestBase.h"

using std::cout;

TestBase::TestBase()
{
}

TestBase::~TestBase()
{
}

bool TestBase::setupTest()
{
	cout << "You didn't override the setupTest() member of the NonNetworkBase class!\n";
	return false;
}

bool TestBase::teardownTest()
{
	cout << "You didn't override the teardownTest() member of the NonNetworkBase class!\n";
	return false;
}

bool TestBase::executeTest()
{
	cout << "You didn't override the executeTest() member of the NonNetworkBase class!\n";
	return false;
}

string TestBase::getTestName()
{
  return "Unknown test"; 
}

bool TestBase::runInnerTest(string testname, bool testresult)
{
	if (testresult)
	{
		cout << "\t" << left << setw(60) << testname << setw(10) << "- PASSED\n";
		return true;
	}
	else
	{
		cout << "\t" << left << setw(60) << testname << setw(10) << "- FAILED\n\n";
		all_tests_success = false;
		return false;
	}

	return false;
}

void TestBase::innerError(string error)
{
	cout << "\t\t" + error + "\n";
}

