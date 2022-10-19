#!/bin/bash 

  

url=$1 

  

if [ ! -d "$url" ];then 

mkdir $url  

fi 

  

if [ ! -d "$url/recon" ] ; then 

mkdir $url/recon 

fi 

  

if [ ! -d "$url/recon/httprobe" ];then 

        mkdir $url/recon/httprobe 

fi 

  

if [ ! -d "$url/recon/3rd-lvls" ];then 

        mkdir $url/recon/3rd-lvls 

fi 

  

if [ ! -d "$url/recon/potential_takeovers" ];then 

        mkdir $url/recon/potential_takeovers 

fi 

  

if [ ! -f "$url/recon/potential_takeovers/domains.txt" ];then 

        touch $url/recon/potential_takeovers/domains.txt 

fi 

  

if [ ! -f "$url/recon/potential_takeovers/potential_takeovers1.txt" ];then 

        touch $url/recon/potential_takeovers/potential_takeovers1.txt 

fi 

  

if [ ! -d "$url/recon/wayback" ];then 

        mkdir $url/recon/wayback 

fi 

  

if [ ! -d "$url/recon/wayback/params" ];then 

        mkdir $url/recon/wayback/params 

fi 

  

if [ ! -d "$url/recon/wayback/extensions" ];then 

        mkdir $url/recon/wayback/extensions 

fi 

  

if [ ! -d "$url/recon/scans" ];then 

        mkdir $url/recon/scans 

    fi 

     

     

echo "[+] Harvesting subdomain with asset finder " 

assetfinder $url >> $url/recon/assets.txt 

cat $url/recon/assets.txt |grep $1 >> $url/recon/final.txt 

rm $url/recon/assets.txt 

  

echo "[+] Harvesting subdomains with Amass..." 

amass enum -d $url >> $url/recon/f.txt 

sort -u $url/recon/f.txt >> $url/recon/final.txt 

rm $url/recon/f.txt 

  

echo "[+] Probing for alive domains..." 

cat $url/recon/final.txt | sort -u | httprobe -s -p https:443 | sed 's/https\?:\/\///' | tr -d ':443' >> $url/recon/httprobe/alive.txt 

  

echo "[+] Compiling 3rd lvl domains..." 

cat $url/recon/final.txt | grep -Po '(\w+\.\w+\.\w+)$' | sort -u >> $url/recon/3rd-lvls/3rd-lvl-domains.txt 

for line in $(cat $url/recon/3rd-lvls/3rd-lvl-domains.txt);do echo $line | sort -u | tee -a $url/recon/final.txt;done 

  

echo "[+] Harvesting full 3rd lvl domains with sublist3r..." 

for domain in $(cat $url/recon/3rd-lvls/3rd-lvl-domains.txt);do sublist3r -d $domain -o $url/recon/3rd-lvls/$domain.txt;done 

  

echo "[+] Checking for possible subdomain takeover..." 

     

for line in $(cat $url/recon/final.txt);do echo $line |sort -u >> $url/recon/potential_takeovers/domains.txt;done 

subjack -w $url/recon/httprobe/alive.txt -t 100 -timeout 30 -ssl -c ~/go/src/subjack/fingerprints.json -v 3 >> $url/recon/potential_takeovers/potential_takeovers1.txt 

sort -u $url/recon/potential_takeovers/potential_takeovers1.txt >> $url/recon/potential_takeovers/potential_takeovers.txt 

rm $url/recon/potential_takeovers/potential_takeovers1.txt 

  

  

echo "[+] Scraping wayback data..." 

    cat $url/recon/final.txt | waybackurls | tee -a  $url/recon/wayback/wayback_output1.txt 

    sort -u $url/recon/wayback/wayback_output1.txt >> $url/recon/wayback/wayback_output.txt 

    rm $url/recon/wayback/wayback_output1.txt 

     

echo "[+] Pulling and compiling all possible params found in wayback data..." 

    cat $url/recon/wayback/wayback_output.txt | grep '?*=' | cut -d '=' -f 1 | sort -u >> $url/recon/wayback/params/wayback_params.txt 

    for line in $(cat $url/recon/wayback/params/wayback_params.txt);do echo $line'=';done 

     

echo "[+] Pulling and compiling js/php/aspx/jsp/json files from wayback output..." 

    for line in $(cat $url/recon/wayback/wayback_output.txt);do 

        ext="${line##*.}" 

        if [[ "$ext" == "js" ]]; then 

            echo $line | sort -u | tee -a  $url/recon/wayback/extensions/js.txt 

        fi 

        if [[ "$ext" == "html" ]];then 

            echo $line | sort -u | tee -a $url/recon/wayback/extensions/jsp.txt 

        fi 

        if [[ "$ext" == "json" ]];then 

            echo $line | sort -u | tee -a $url/recon/wayback/extensions/json.txt 

        fi 

        if [[ "$ext" == "php" ]];then 

            echo $line | sort -u | tee -a $url/recon/wayback/extensions/php.txt 

        fi 

        if [[ "$ext" == "aspx" ]];then 

            echo $line | sort -u | tee -a $url/recon/wayback/extensions/aspx.txt 

        fi 

    done     

     

echo "[+] Scanning for open ports..." 

    nmap -iL $url/recon/httprobe/alive.txt -T4 -oA $url/recon/scans/scanned.txt 

     

   
