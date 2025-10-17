#!/bin/bash
echo "=== Checking CDI Files After Enabling CDI ==="
echo "Date: $(date)"
echo

echo "1. CDI files in /var/run/cdi:"
ls -la /var/run/cdi/ 2>/dev/null || echo "No files in /var/run/cdi"
echo

echo "2. Looking for the specific CDI device mentioned in error:"
echo "Looking for: nic-e093a832-3901-49d5-86a4-3ac79e5e1e01"
find /var/run/cdi /etc/cdi -name "*e093a832*" 2>/dev/null || echo "CDI file not found for this device"
echo

echo "3. All CDI JSON files:"
find /var/run/cdi /etc/cdi -name "*.json" 2>/dev/null | while read file; do
    echo "=== $file ==="
    cat "$file" | jq . 2>/dev/null || cat "$file"
    echo
done

echo "4. CDI status from crictl:"
crictl info | grep -A 5 -B 5 -i cdi 2>/dev/null || echo "Could not get CDI info"

echo
echo "=== CDI Files Check Complete ==="