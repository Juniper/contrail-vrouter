This directory contains the python based vtest UT framework for vrouter.

## Framework Design

We leverage the python sandesh library **'pysandesh'** to generate
python objects for the different **'vrouter'** sandesh objects like
vif, rt, nh etc.
A python library module **'vtest_lib.py'** is written to provide the
basic classes like **"vrouter"** and **"vtest"** to work with the framework.
The SCons script in vtest_py directory creates a virtual env in python,
copies all the required libraries and tests files into the virtual env
and then starts execution of the tests using run_test.sh script.
The path for the virtual env created is
$SB_root/build/debug/vrouter/utils/vtest_py_venv

The actual unit test cases are integrated with PyTest and Scapy and all
the features provided by these can be used.

More details about PyTest is available at
[https://docs.pytest.org/en/latest/](https://docs.pytest.org/en/latest/)

More details about Scapy is available at
[https://scapy.readthedocs.io/en/latest/usage.html](https://scapy.readthedocs.io/en/latest/usage.html)

Refer to test1.py and test2.py in tests/ directory for examples on how to use this framework.

## Running the tests

Run **scons vrouter** to build the dpdk and vtest binaries
Run **scons vrouter-py-ut:test** in the top level directory of the SB to run all the unit test cases.
Run **scons vrouter-py-ut:coverage** in the top level directory of the SB to get the code coverage of vrouter.

To run individual tests either use run_test.sh from the source directory (method1) or
goto the virtual env and run the test (method2)

Method 1 (using run_test.sh)

 - Run the following command from `$SB/vrouter/utils/vtest_py`
./run_test.sh test_file_name.py

Method 2
`
 - cd $SB/build/debug/vrouter/utils/vtest_py_venv
 - source bin/activate
 - Export the following variables to bash
             `For eg: VROUTER_DPDK_PATH=/home/anandrao/mainline_new/build/debug/vrouter/dpdk/contrail-vrouter-dpdk
                     VROUTER_SOCKET_PATH=/home/anandrao/mainline_new/build/debug/vrouter/utils/vtest_py_venv/var/run/vrouter
                     VTEST_PATH=/home/anandrao/mainline_new/build/debug/vrouter/utils/vtest/vtest
                     VTEST_PY_VENV_PATH=/home/anandrao/mainline_new/build/debug/vrouter/utils/vtest_py_venv`
 - pytest -s tests/test_file_name.py
 - deactivate
`
## Workflow for adding new tests

 - Run **scons vrouter** to build the dpdk and vtest binaries
 - Run **"scons vrouter-py-ut:test"** once so that the basic virtual env is setup for you.
 - Write the new test case file in **tests/** directory inside virtual env
 - Run the test case using either Method1 or Method2
 - Run **pycodestyle tests/test_file_name** to check for PEP errors and resolve them
 - Run **flake8 tests/test_file_name** to check for flake errors and resolve them
 - Once the test case is ready, copy the test case file to the source
   **vtest_py/tests** directory for commit

## Tips and tricks
 - To run vRouter alone in background, run the following command from `$SB/vrouter/utils/vtest_py`
   `VROUTER_ONLY_MODE=1 ./run_test.sh &`
 - To run vtest alone, run the following command from `$SB/vrouter/utils/vtest_py`
   `VTEST_ONLY_MODE=1 ./run_test.sh test1.py`
 - Then the vif, nh, rt etc. commands can be executed with the sock-dir option
 - Before running another UT, the vRouter needs to be stopped manually
