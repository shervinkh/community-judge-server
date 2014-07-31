#!/bin/bash

cat mypassword | sudo -S -p '' -u noone ./ControlledRun $1 $2 $3 $4 > tmp/output$5