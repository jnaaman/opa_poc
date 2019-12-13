#!/bin/bash
OUTPUTFILE=bundle.tar
tar -c -f $OUTPUTFILE .manifest
tar -r -f $OUTPUTFILE policies
tar -r -f $OUTPUTFILE rego
gzip -f $OUTPUTFILE