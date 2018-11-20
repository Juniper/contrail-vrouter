/*
 * generate_test_functions.h
 *
 * Copyright (c) 2018 Juniper Networks, Inc. All rights reserved.
 */
#define PrintTestName() print_message("\n\nRunning %s tests.\n", __func__)

#define GenerateTestCaseFunction(CaseName, inputPacketHeaderFiller, dataSize, headersSize, payloadGenerator, vrPacketFiller, inputPacketOffloadFlags, outputPacketHeaderFillers, outputPacketsNumber, assertFunction) \
    static void CaseName (void **state) \
    { \
        CheckHeadersAreValid = CheckHeadersAreValidDef; \
        Test( \
            inputPacketHeaderFiller, \
            dataSize, \
            headersSize, \
            payloadGenerator, \
            vrPacketFiller, \
            inputPacketOffloadFlags, \
            outputPacketHeaderFillers, \
            outputPacketsNumber, \
            assertFunction \
        ); \
    }

// Because stupid __VA_ARGS__ refuse to work
#define TEST_CASE(CaseName, inputPacketHeaderFiller, dataSize, headersSize, payloadGenerator, \
    vrPacketFiller, inputPacketOffloadFlags, outputPacketHeaderFillers, outputPacketsNumber, assertFunction) \
    GenerateTestCaseFunction(CaseName, inputPacketHeaderFiller, dataSize, headersSize, payloadGenerator, \
    vrPacketFiller, inputPacketOffloadFlags, outputPacketHeaderFillers, outputPacketsNumber, assertFunction)
TEST_CASES
#undef TEST_CASE

bool TEST_NAME ()
{
    PrintTestName();

    const struct CMUnitTest tests[] = {
        #define TEST_CASE(CaseName, ...) cmocka_unit_test(CaseName),
        TEST_CASES
        #undef TEST_CASE
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}

#undef TEST_NAME
#undef TEST_CASES
