#!/bin/sh

venv_dir=$1
req_file_path=$2

virtualenv  --python=/usr/bin/python2 $venv_dir
source  $venv_dir/bin/activate
pip install -r $req_file_path
deactivate

