#!/bin/bash
echo "=== Examining CDI Spec Created by DRA Driver ==="
echo "Date: $(date)"
echo

echo "CDI spec content:"
cat /var/run/cdi/nic-60b7bf1c-7b05-4976-8c1f-c50b711cdc04.json | jq . 2>/dev/null || cat /var/run/cdi/nic-60b7bf1c-7b05-4976-8c1f-c50b711cdc04.json

echo
echo "=== CDI Spec Examination Complete ==="