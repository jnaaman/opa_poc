#!/bin/bash
OUTPUTFILE=bundle.tar
tar -c -f $OUTPUTFILE .manifest
tar -r -f $OUTPUTFILE examples
tar -r -f $OUTPUTFILE policy
gzip -f $OUTPUTFILE