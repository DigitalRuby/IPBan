VERSION_DOTS="1.5.3.0"
VERSION_UNDERSCORES=${VERSION_DOTS//./_}
FILE_NAME="IPBan-Linux-x64_$VERSION_UNDERSCORES.zip"

# run entire script from url, do sudo -i first
# sudo -i;
# bash <(wget -qO- https://raw.githubusercontent.com/DigitalRuby/IPBan/master/IPBanCore/Linux/Scripts/Install.sh)

# install unzipper, install iptables and ipset, make folder /opt/ipban
sudo apt-get -q -y install unzip; sudo apt-get install -q -y iptables; sudo apt-get install -q -y ipset; sudo apt-get -q -y update; sudo mkdir /opt/ipban -p; cd /opt/ipban;

# download latest release and extract to /opt/ipban
sudo wget https://github.com/DigitalRuby/IPBan/releases/download/$VERSION_DOTS/$FILE_NAME; unzip -qq $FILE_NAME; rm $FILE_NAME;

# allow execute permissions for /opt/ipban/DigitalRuby.IPBan
sudo chmod +x /opt/ipban/DigitalRuby.IPBan

# install service to run the executable
sudo cat > /lib/systemd/system/ipban.service <<"END.OF.TEMPLATE"

[Unit]
Description=IPBan Service
After=network.target

[Service]
WorkingDirectory=/opt/ipban
ExecStart=/opt/ipban/DigitalRuby.IPBan
Restart=on-failure

[Install]
WantedBy=multi-user.target
END.OF.TEMPLATE

# enable and start service, ensure that it is running on reboots as well
sudo systemctl daemon-reload; sudo systemctl start ipban; sudo systemctl restart ipban; sudo systemctl enable ipban; sudo systemctl status ipban;

# open up config editor to make any additional changes like whitelist or min failed attempt to ban, etc.
sudo nano /opt/ipban/DigitalRuby.IPBan.dll.config
