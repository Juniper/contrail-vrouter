#!/usr/bin/env sh

#Name:	    vtest_build_integ.sh
#Author: 	Juniper Networks, All Rights reserved
#Date: 		2016
#Version: 	2016.5

#export LC_ALL = your_enviroment

VERSION="2016.5"

`true`
EXIT_SUCCESS=$?

SCRIPT_NAME=`basename $0`
ARGC=$#

#TODO create a path parameter
#TODO Config file in tests directories, some tets must be runned with different parameters
#for now physical vlan tests wouldn't work.

VROUTER_PATH='taskset 0x1 /usr/bin/contrail-vrouter-dpdk'
VROUTER_RUN_PARAM='--no-daemon --socket-mem 1024'

VROUTER_PID='-1'



VTEST_PATH='./vtest'

#PARENT_DIRECTORY
VTEST_TEST_PATH='.'

VTEST_TESTS=""

PASSED_TESTS=""
FAILED_TESTS=""

function print_help {

echo " 
		${SCRIPT_NAME} vtest's script, run vtest's XML's
	options:

		[-v] - print version of program
		[-h] - print this message
		[-t] - vRouter timeout - bootstraping [integer],  default 5 sec
"
}

function enum_error {

case $1 in

    E_OK) ret_val=$EXIT_SUCCESS;; #Everything is OK

    E_BPAR) ret_val=`expr $EXIT_SUCCESS + 1 `;; #Incorrect parameters

    E_TIMEOUT) ret_val=`expr $EXIT_SUCCESS + 2 `;; #Timeout error

    E_VROUTERRUNN) ret_val=`expr $EXIT_SUCCESS + 3 `;; #VRouter is running

    E_VROUTERERR) ret_val=`expr $EXIT_SUCCESS + 4 `;; #vRouter is not killed

    E_VROUTERPAR) ret_val=`expr $EXIT_SUCCESS + 5`;; #vRouter incorrect parameter

    E_UNK) ret_val=`expr $EXIT_SUCCESS + 6`;; #Uknown error

esac

            return $ret_val
        }

function enum_string {

case $1 in

    E_OK) ;; #Everything is OK

    E_PHELP) print_help ;;

    E_BPAR) echo >&2  "Incorrect parameters. Use ${SCRIPT_NAME} -h";;

    E_VER) echo "${VERSION}";; 
    
    E_TIMEOUT) echo >&2 "Incorrect timeout parameter.";;

    E_VROUTERRUNN) echo >&2 "vRouter is already running.";;

    E_VROUTERERR) echo >&2 "Problem with killing process vRouter.";;

    E_VROUTERPAR)  echo >&2 "Incorrect vRouter CLI parameters or instance already is running.";;

    E_UNK) echo >&2 "Uknown error";;

esac
}

function check_params {

if [ "$ARGC" == "0" ] ; then

    enum_string E_BPAR; exit $(enum_error E_BPAR)
fi;         

if [ $help_flag = "on" ] ; then

    if [ $timeout_flag = "on" ] || [ $ver_flag = "on" ] ; then

        enum_string E_BPAR; exit $(enum_error E_BPAR)
    fi;

    enum_string E_PHELP; exit $(enum_error E_OK)
fi;

if [ $ver_flag = "on" ] ; then

    if  [ $file_flag = "on" ] || [ $help_flag = "on"  ]  ; then

        enum_string E_BPAR; exit $(enum_error E_BPAR)
    fi;

    enum_string E_VER; exit $(enum_error E_OK)
fi;

if [ $timeout_flag = "on" ] ; then

    if [ "" = "${timeout_value##*[!0-9]*}" ] ; then

        enum_string E_TIMEOUT; exit $(enum_error E_TIMEOUT)
    fi;
fi;


}

function run_vRouter {

    vrouter_ret_val="0"

    if [ "${VROUTER_PID}" != "-1" ] ; then
         enum_string E_VROUTERRUNN; exit $(enum_error E_VROUTERRUNN)
    fi;


    ${VROUTER_PATH} ${VROUTER_RUN_PARAM} &    
    vrouter_ret_val=$?
    if [ "${vrouter_ret_val}" != ${EXIT_SUCCESS} ]; then 
        enum_string E_VROUTERPAR; exit $(enum_error E_VROUTERPAR)
    fi;

    VROUTER_PID=$!
}


function stop_vRouter {

    kill -9 ${VROUTER_PID}
    if [ "$?" != "0" ] ; then
         enum_string E_VROUTERERR; exit $(enum_error E_VROUTERERR)
    fi;

    VROUTER_PID="-1"


}

function timeout_vRouter {

    sleep "${timeout_value}" 
}

function find_tests {

    VTEST_TESTS=$(find "${VTEST_TEST_PATH}" -name '*.xml' -type 'f')

    if [ "$?" != "${EXIT_SUCCESS}" ]; then
        enum_string E_UNK; exit $(enum_error E_UNK)
    fi;
}

function run_tests {
    
    find_tests

    cd "${VTEST_TEST_PATH}"

    for test_n in ${VTEST_TESTS}; do

        run_vRouter
        timeout_vRouter

        ${VTEST_PATH} "${test_n}"

        if [ "$?" != "${EXIT_SUCCESS}" ]; then
            echo >&2 "test ${test_n} failed"
            FAILED_TESTS="${FAILED_TESTS} ${test_n}"
        else
            echo >&2 "test ${test_n} passed"
            PASSED_TESTS="${PASSED_TESTS} ${test_n}"
        fi;

        stop_vRouter

    done;
}


##
#
#	GET PARAMETERS (ARGV)
#
##

#hELP flag
help_flag="off"

#vERSION flag
ver_flag="off"

#tIMEOUT flag
timeout_flag="off"
timeout_value="10"

while getopts vht: opt
do
    case "$opt" in
        h)      if [ $help_flag = "on" ] ; then
                        enum_string E_BPAR ; exit $(enum_error E_BPAR)
                fi;
                help_flag="on";
                ;;

        t)      if [ $timeout_flag = "on" ] ; then
                        enum_string E_BPAR ; exit $(enum_error E_BPAR)
                fi;
                timeout_flag="on"; timeout_value="$OPTARG"
                ;;

        v)      if [ $ver_flag = "on" ] ; then
                        enum_string E_BPAR ; exit $(enum_error E_BPAR)
                fi;
                ver_flag="on"
                ;;


        \?|*)
                 enum_string E_BPAR ; exit $(enum_error E_BPAR);;
    esac
done
shift $( expr $OPTIND - 1 )

##
#
#	Main routine 
#
##


check_params
run_tests


echo "PASSED TESTS:"
echo $PASSED_TESTS

echo "FAILED TESTS:"
echo $FAILED_TESTS


if [ "${#FAILED_TESTS}" != "0" ]; then 
    exit $(enum_error E_UNK)
fi;

exit $(enum_error E_OK)

