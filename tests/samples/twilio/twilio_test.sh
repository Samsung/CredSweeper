#!/bin/bash

echo "Running Twilio Test Cases"

# Test true positives
echo "🔍 Testing True Positives..."
grep -r "AC1234567890abcdef1234567890abcdef" . && echo "✅ Account SID found" || echo "❌ Account SID missing"
grep -r "9f8e7d6c5b4a39281706f5e4d3c2b1a0" . && echo "✅ Auth Token found" || echo "❌ Auth Token missing"

# Test false positives
echo "🔍 Testing False Positives..."
grep -r "7e79bf807aa611eb9cbdd7bda7eaf1aa" . && echo "❌ Checksum should NOT be found" || echo "✅ Checksum correctly filtered"

echo "Done"
