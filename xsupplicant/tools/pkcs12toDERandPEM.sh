#!/bin/sh

if [ $# -eq 1 ]; then
  if [ -r $1 ]; then
     echo "Converting file $1 to PEM format"
     openssl pkcs12 -des3 -in $1 -out key.pem
     if [ -w key.pem ]; then
        echo "Key successfully extracted to file \"key.pem\"."
        openssl x509 -inform PEM -outform DER -in key.pem -out cert.cer
     else 
        echo "Failed to extract key...exiting."
        exit
     fi
     if [ -w cert.cer ]; then
        echo "Certificate successfully extracted to file \"cert.cer\"."
     fi
  else 
     echo "Could not open file $1"
  fi
else
  echo "Please provide a filename to convert"
fi
