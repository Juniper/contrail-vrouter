#!/bin/sh
set -x

venv_dir=$1
req_file_path=$2

echo "venv_dir= $venv_dir"
echo "req_file_path= $req_file_path"

virtualenv $venv_dir
source  $venv_dir/bin/activate
echo "in venv"
pip install -r $req_file_path
echo "executing pip install"
echo "venv_dir= $venv_dir"
echo "req_file_path= $req_file_path"
deactivate

