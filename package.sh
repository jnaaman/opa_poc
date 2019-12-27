#!/bin/bash
OUTPUTFILE=bundle.tar
tar -c -f $OUTPUTFILE .manifest
tar -r -f $OUTPUTFILE -s "/data//g" data
tar -r -f $OUTPUTFILE rego/authz_v1.rego
tar -r -f $OUTPUTFILE rego/common.rego
gzip -f $OUTPUTFILE