# zcs-install
install.sh wrapper script
* This will automate the install of ZCS+ Zimbra 10.1 (Daffodil) GA (FOSS) fully configured for testing in the lab
* Tested on Ubuntu 22.04 LTS
* To test run: ./zcsinstall.sh example.com 

* Note: To use with Letsencrypt/Cloudflare plugins, export these two variables before running the script.
  - export CF_TOKEN= 'yourcloudflare api token'
* ./zcsinstall.sh -e y example.com 
