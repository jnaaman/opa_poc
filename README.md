# opa_poc
OPA PoC code

Build bundle
```
./package.sh
```

To Run the opa server
```
opa run -s -b bundle.tar.gz 
```

To test the opa endpoint
```
curl localhost:8181/v1/data/authz_v1/authorized -H 'Content-Type: application/json' -d @inputs/v1-data-input.json
```