/**
 * Base class for tests.
 *
 * \author chris@open1x.org
 **/

#ifndef _TESTBASE_H_
#define _TESTBASE_H_

#include <string>
#include <vector>
using namespace std;

class TestBase 
{
public:
	TestBase();
	virtual ~TestBase();

	virtual string getTestName();
	virtual bool setupTest();
	virtual bool teardownTest();
	virtual bool executeTest();
	virtual bool checkResults() { return all_tests_success; }
	virtual bool terminal_error() { return false; }
	bool runInnerTest(string testname, bool testresult);
	void innerError(string error);

protected:
	bool all_tests_success;
};

#endif  // _TESTBASE_H_
