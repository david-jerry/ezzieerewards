#!/bin/bash

# Update package list and install dependencies
sudo apt update -y
sudo apt install mkcert libnss3-tools -y

# Generate a self-signed certificate for localhost.domain
mkcert localhost.domain

# Install the generated CA in the system trust store
mkcert -install

# (Optional) Verify the installation by checking if the certificate exists
ls /usr/local/share/ca-certificates/localhost.domain.crt

echo "Successfully installed mkcert and self-signed certificate for localhost.domain."

# (Optional) Restart Firefox if you use it and need the certificate to be trusted
# (Adapt this line depending on your system and browser)
pkill -f firefox
