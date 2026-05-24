/*
 *
 * How to use this test:
 * 1. start logger: logman.exe start etwspeedtest -p {1C0C3E5E-E7AD-44F5-94A1-81363FE22343} -o etwspeedtest.etl -ets -bs 8192
 * 2. run the ETW_SpeedTest.exe
 * 3. stop logger: logman.exe stop etwspeedtest -ets
 * 4. convert the .etl file to a dumpfile.csv file: tracerpt.exe etwspeedtest.etl -of CSV
 * 5. to verify if all events were logged: type summary.txt
 *    if not, increase the buffer size (bs) in step 1 and repeat the test.
 * 6. delete the .etl and .csv files, they are huge and not needed anymore.
 *
 */


#include <stdio.h>
#include <Windows.h>
#include <TraceLoggingProvider.h>
#include <winmeta.h>

#define NUM_ITERATIONS 1000000

// {1C0C3E5E-E7AD-44F5-94A1-81363FE22343}
TRACELOGGING_DEFINE_PROVIDER(
	g_EtwProvider,
	"ETW.SpeedTest",
	(0x1c0c3e5e, 0xe7ad, 0x44f5, 0x94, 0xa1, 0x81, 0x36, 0x3f, 0xe2, 0x23, 0x43));

int main(int argc, CHAR** argv)
{
	LARGE_INTEGER freq;
	LARGE_INTEGER start;
	LARGE_INTEGER end;
	double elapsed;

	TraceLoggingRegister(g_EtwProvider);

	QueryPerformanceFrequency(&freq);
	QueryPerformanceCounter(&start);

	for (long int i = 0; i < NUM_ITERATIONS; i++)
	{
		TraceLoggingWrite(
			g_EtwProvider,
			"SpeedTestEvent",
			TraceLoggingLevel(WINEVENT_LEVEL_VERBOSE),
			TraceLoggingString(argv[0], "ARG0"));
	}

	QueryPerformanceCounter(&end);

	TraceLoggingUnregister(g_EtwProvider);

	elapsed = (double)(end.QuadPart - start.QuadPart) / (double)freq.QuadPart;

	printf("Time taken: %f seconds\r\nEvents per second: ~%.3fM\r\n", elapsed, (NUM_ITERATIONS / elapsed) / 1000000.0);
}
