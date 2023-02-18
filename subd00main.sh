#!/usr/bin/env bash

#
# Cleaned up version of leaked Conti group subdomain recon script with dig wrapper to resolve names to IPs
#

# sanity checks
if [ "$1" == "" ]
then
    echo "Usage:"
    echo "./subd00main.sh <targetDomain> <outputFile>"
    echo " "
    echo "Example:"
    echo "./subd00main.sh example.com ./example-com-subdomains.csv"
    exit
fi

# params
targetDomain=$1
outputFile=$2
tmpFile="/tmp/subd00main.tmp"

# curl recon action
echo [+] Starting subdomain recon
echo " "
echo [+] Scraping: threatcrowd.org
curl --silent https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=$targetDomain | grep -o -E "[a-zA-Z0-9._-]+\.$1" > $tmpFile
echo [+] Scraping: hackertarget.com
curl --silent https://api.hackertarget.com/hostsearch/?q=$targetDomain | grep -o -E "[a-zA-Z0-9._-]+\.$1" >> $tmpFile
echo [+] Scraping: crt.sh
curl --silent https://crt.sh/?q=%.$targetDomain | grep -oP "\<TD\>\K.*\.$1" | sed -e 's/\<BR\>/\n/g' | grep -oP "\K.*\.$1" | sed -e 's/[\<|\>]//g' | grep -o -E "[a-zA-Z0-9._-]+\.$1" >> $tmpFile
curl --silent https://crt.sh/?q=%.%.$targetDomain | grep -oP "\<TD\>\K.*\.$1" | sed -e 's/\<BR\>/\n/g' | sed -e 's/[\<|\>]//g' | grep -o -E "[a-zA-Z0-9._-]+\.$1" >> $tmpFile
curl --silent https://crt.sh/?q=%.%.%.$targetDomain | grep "$1" | cut -d '>' -f2 | cut -d '<' -f1 | grep -v " " | grep -o -E "[a-zA-Z0-9._-]+\.$1" | sort -u >> $tmpFile
curl --silent https://crt.sh/?q=%.%.%.%.$targetDomain | grep "$1" | cut -d '>' -f2 | cut -d '<' -f1 | grep -v " " | grep -o -E "[a-zA-Z0-9._-]+\.$1" | sort -u >> $tmpFile
echo [+] Scraping: certspotter.com
curl --silent https://certspotter.com/api/v0/certs?domain=$targetDomain | grep -o '\[\".*\"\]' | sed -e 's/\[//g' | sed -e 's/\"//g' | sed -e 's/\]//g' | sed -e 's/\,/\n/g' | grep -o -E "[a-zA-Z0-9._-]+\.$1" >> $tmpFile
echo [+] Scraping: spyse.com
curl --silent https://spyse.com/target/domain/$targetDomain | grep -E -o "button.*>.*\.$1\/button>" | grep -o -E "[a-zA-Z0-9._-]+\.$1" >> $tmpFile
echo [+] Scraping: bufferover.run
curl --silent https://tls.bufferover.run/dns?q=$targetDomain | grep -o -E "[a-zA-Z0-9._-]+\.$1" >> $tmpFile
curl --silent https://dns.bufferover.run/dns?q=.$targetDomain | grep -o -E "[a-zA-Z0-9._-]+\.$1" >> $tmpFile
echo [+] Scraping: urlscan.io
curl --silent https://urlscan.io/api/v1/search/?q=$targetDomain | grep -o -E "[a-zA-Z0-9._-]+\.$1" >> $tmpFile
echo [+] Scraping: synapsint.com
curl --silent -X POST https://synapsint.com/report.php -d "name=http%3A%2F%2F$1" | grep -o -E "[a-zA-Z0-9._-]+\.$1" >> $tmpFile
echo [+] Scraping: jldc.me
curl --silent https://jldc.me/anubis/subdomains/$targetDomain | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([Az]))\w+" >> $tmpFile
echo [+] Scraping: omnisint.io
curl --silent https://sonar.omnisint.io/subdomains/$targetDomain | grep -o -E "[a-zA-Z0-9._-]+\.$1" >> $tmpFile
echo [+] Scraping: alienvault.com
curl --silent https://otx.alienvault.com/api/v1/indicators/domain/$targetDomain/passive_dns | grep -o -E "[a-zA-Z0-9._-]+\.$1" >> $tmpFile
echo [+] Scraping: riddler.io
curl --silent https://riddler.io/search/exportcsv?q=pld:$targetDomain | grep -o -E "[a-zA-Z0-9._-]+\.$1" >> $tmpFile
echo " "


# loop through domain names
echo [+] Resolving DNS names to IPs

# print column headers
if [[ $# -eq 2 ]]; then
    echo DOMAIN_NAME,DIG_RESULT > $outputFile
else
    echo " "
    printf '%s\t%s\n' DOMAIN_NAME DIG_RESULT
fi

for subdomain in $(cat $tmpFile | sed -e "s/\*\.$1//g" | sed -e "s/^\..*//g" | grep -o -E "[a-zA-Z0-9._-]+\.$1" | sort -u); do

    # dns lookup
    digresult=$(dig +short $subdomain)

    if [ "$digresult" != "" ]; then

        # output to file if defined else print to console
        if [[ $# -eq 2 ]]; then
            # output to file
            echo $subdomain','$digresult >> $outputFile
        else
            # output to console
            printf '%s\t%s\n' $subdomain $digresult
        fi

    fi

done

# cleanup
rm -f $tmpFile

# done
echo " "
echo [+] Done!
