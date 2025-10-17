#!/bin/bash
echo "=== Enabling CDI in Containerd Configuration ==="
echo "Date: $(date)"
echo

# Backup the current config
echo "1. Backing up current containerd config..."
cp /etc/containerd/config.toml /etc/containerd/config.toml.backup.$(date +%Y%m%d-%H%M%S)
echo "Backup created: /etc/containerd/config.toml.backup.$(date +%Y%m%d-%H%M%S)"
echo

echo "2. Current containerd config size: $(wc -l /etc/containerd/config.toml)"
echo

# Check if CDI config already exists
if grep -q "enable_cdi" /etc/containerd/config.toml; then
    echo "CDI configuration already exists in containerd config"
    grep -A 2 -B 2 "enable_cdi" /etc/containerd/config.toml
else
    echo "3. Adding CDI configuration to containerd..."
    
    # Find the [plugins."io.containerd.grpc.v1.cri"] section and add CDI config
    if grep -q '\[plugins\."io\.containerd\.grpc\.v1\.cri"\]' /etc/containerd/config.toml; then
        echo "Found CRI plugin section, adding CDI configuration..."
        
        # Create a temporary file with the CDI configuration added
        awk '
        /^\[plugins\."io\.containerd\.grpc\.v1\.cri"\]/ {
            print $0
            print "        enable_cdi = true"
            print "        cdi_spec_dirs = [\"/etc/cdi\", \"/var/run/cdi\"]"
            next
        }
        { print }
        ' /etc/containerd/config.toml > /tmp/config.toml.new
        
        # Verify the new config looks good
        echo "4. Verifying new configuration..."
        if grep -q "enable_cdi = true" /tmp/config.toml.new; then
            echo "✅ CDI configuration added successfully"
            mv /tmp/config.toml.new /etc/containerd/config.toml
            echo "✅ Containerd config updated"
        else
            echo "❌ Failed to add CDI configuration"
            rm -f /tmp/config.toml.new
            exit 1
        fi
    else
        echo "❌ Could not find CRI plugin section in containerd config"
        echo "Current config structure:"
        grep "^\[" /etc/containerd/config.toml
        exit 1
    fi
fi

echo
echo "5. New configuration:"
grep -A 3 -B 1 "enable_cdi" /etc/containerd/config.toml || echo "CDI config not found"
echo

echo "6. Restarting containerd service..."
systemctl restart containerd
sleep 5

echo "7. Checking containerd service status..."
systemctl is-active containerd

echo "8. Verifying CDI is now enabled..."
sleep 10  # Give containerd time to start up completely
crictl info | grep -i cdi || echo "Could not verify CDI status"

echo
echo "=== CDI Enable Complete ==="
echo "Note: You may need to restart pods for CDI changes to take effect"