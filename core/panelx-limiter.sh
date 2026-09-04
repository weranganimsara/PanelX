#!/bin/bash
# =============================================================================
# SGPX Real-Time Session & Bandwidth Limiter Daemon
# Automatically enforces simultaneous device logins & bandwidth quotas
# Author: Weranga Nimsara (SG Home) & Open-Source Community
# =============================================================================

DB_FILE="/etc/panelx/users.db"
BW_DIR="/etc/panelx/bandwidth"
PID_DIR="$BW_DIR/pidtrack"
BANNER_DIR="/etc/panelx/banners"
SCAN_INTERVAL=5

mkdir -p "$BW_DIR" "$PID_DIR" "$BANNER_DIR"
mkdir -p /var/log/panelx
ln -sfn "$BW_DIR" /var/log/panelx/bw 2>/dev/null || true
shopt -s nullglob

write_banner_if_changed() {
    local user="$1"
    local content="$2"
    local banner_file="$BANNER_DIR/${user}.txt"
    local tmp_file="${banner_file}.tmp"

    printf "%s" "$content" > "$tmp_file"
    if ! cmp -s "$tmp_file" "$banner_file" 2>/dev/null; then
        mv "$tmp_file" "$banner_file"
    else
        rm -f "$tmp_file"
    fi
}

while true; do
    if [[ ! -s "$DB_FILE" ]]; then
        sleep "$SCAN_INTERVAL"
        continue
    fi

    printf -v current_ts '%(%s)T' -1
    dynamic_banners_enabled=false

    # Reset associative arrays each cycle
    unset session_pids locked_users uid_to_user loginuid_pids user_proc_pids user_db_list
    declare -A session_pids=()
    declare -A locked_users=()
    declare -A uid_to_user=()
    declare -A loginuid_pids=()
    declare -A user_proc_pids=()
    declare -A user_db_list=()

    # Preload users from users.db
    while IFS=: read -r u _p _e _l _b _r; do
        [[ -n "$u" && "$u" != \#* ]] && user_db_list["$u"]=1
    done < "$DB_FILE"

    while IFS=: read -r username _ uid _rest; do
        [[ -n "$username" && "$uid" =~ ^[0-9]+$ ]] && uid_to_user["$uid"]="$username"
    done < /etc/passwd

    # Method 1: Process owner from ps (matches sshd and sshd-session on Ubuntu 20/22/24 & Debian)
    while read -r ssh_pid ssh_owner; do
        [[ "$ssh_pid" =~ ^[0-9]+$ ]] || continue
        if [[ -n "$ssh_owner" && "$ssh_owner" != "root" && "$ssh_owner" != "sshd" ]]; then
            session_pids["$ssh_owner"]+="$ssh_pid "
        fi
    done < <(ps -C sshd,sshd-session -o pid=,user= 2>/dev/null)

    # Method 2: Kernel loginuid (reliable even when sshd privsep runs as root)
    for p in /proc/[0-9]*/loginuid; do
        [[ -f "$p" ]] || continue
        login_uid=""
        read -r login_uid < "$p" || login_uid=""
        [[ "$login_uid" =~ ^[0-9]+$ && "$login_uid" != "4294967295" ]] || continue

        session_user="${uid_to_user[$login_uid]}"
        [[ -n "$session_user" ]] || continue

        pid_dir=$(dirname "$p")
        pid_num=$(basename "$pid_dir")
        comm=""
        read -r comm < "$pid_dir/comm" || comm=""
        [[ "$comm" == sshd* ]] || continue

        ppid_val=""
        while read -r key value; do
            if [[ "$key" == "PPid:" ]]; then
                ppid_val="${value:-}"
                break
            fi
        done < "$pid_dir/status"
        [[ "$ppid_val" == "1" ]] && continue

        loginuid_pids["$session_user"]+="$pid_num "
    done

    # Method 3: Direct User Process Detection (Finds any process owned by client user)
    for uname in "${!user_db_list[@]}"; do
        for upid in $(pgrep -u "$uname" 2>/dev/null); do
            [[ "$upid" =~ ^[0-9]+$ ]] && user_proc_pids["$uname"]+="$upid "
        done
    done

    # Detect locked users via /etc/shadow
    if [[ -r /etc/shadow ]]; then
        while IFS=: read -r shadow_user shadow_hash _rest; do
            [[ -n "$shadow_user" && "${shadow_hash:0:1}" == "!" ]] && locked_users["$shadow_user"]=1
        done < /etc/shadow
    else
        while read -r passwd_user _ passwd_status _rest; do
            [[ "$passwd_status" == "L" ]] && locked_users["$passwd_user"]=1
        done < <(passwd -Sa 2>/dev/null)
    fi

    if [[ -f "/etc/panelx/banners_enabled" ]]; then
        mkdir -p "$BANNER_DIR"
        dynamic_banners_enabled=true
    fi

    # Read each user from users.db: user:pass:expiry:limit:bandwidth_gb
    while IFS=: read -r user pass expiry limit bandwidth_gb _extra; do
        [[ -z "$user" || "$user" == \#* ]] && continue

        unset unique_pids
        declare -A unique_pids=()

        # Merge all three process detection sources
        for pid in ${session_pids[$user]} ${loginuid_pids[$user]} ${user_proc_pids[$user]}; do
            [[ "$pid" =~ ^[0-9]+$ ]] && unique_pids["$pid"]=1
        done

        online_count=${#unique_pids[@]}
        user_locked=false
        if [[ -n "${locked_users[$user]+x}" ]]; then
            user_locked=true
        fi

        # 1. Check Account Expiry
        expiry_ts=0
        if [[ "$expiry" != "Never" && -n "$expiry" && "$expiry" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
            expiry_ts=$(date -d "$expiry" +%s 2>/dev/null || echo 0)
            if [[ "$expiry_ts" =~ ^[0-9]+$ ]] && (( expiry_ts > 0 && expiry_ts < current_ts )); then
                if ! $user_locked; then
                    usermod -L "$user" &>/dev/null
                    killall -u "$user" -9 &>/dev/null
                    locked_users["$user"]=1
                fi
                continue
            fi
        fi

        # 2. Check Device Limits (Simultaneous Logins)
        [[ "$limit" =~ ^[0-9]+$ ]] || limit=1
        if (( online_count > limit )); then
            if ! $user_locked; then
                usermod -L "$user" &>/dev/null
                killall -u "$user" -9 &>/dev/null
                (sleep 90; usermod -U "$user" &>/dev/null) &
                locked_users["$user"]=1
                user_locked=true
            else
                killall -u "$user" -9 &>/dev/null
            fi
        fi

        # 3. Dynamic Banner Update (Optional)
        if $dynamic_banners_enabled; then
            days_left="Active"
            if [[ "$expiry" != "Never" && -n "$expiry" && "$expiry_ts" =~ ^[0-9]+$ && $expiry_ts -gt 0 ]]; then
                diff_secs=$((expiry_ts - current_ts))
                if (( diff_secs <= 0 )); then
                    days_left="EXPIRED"
                else
                    d_l=$(( diff_secs / 86400 ))
                    h_l=$(( (diff_secs % 86400) / 3600 ))
                    days_left="${d_l}d ${h_l}h left"
                fi
            fi

            bw_info="Unlimited"
            if [[ "$bandwidth_gb" != "0" && -n "$bandwidth_gb" ]]; then
                usagefile="$BW_DIR/${user}.usage"
                accum_disp=0
                if [[ -f "$usagefile" ]]; then
                    read -r accum_disp < "$usagefile"
                    [[ "$accum_disp" =~ ^[0-9]+$ ]] || accum_disp=0
                fi
                used_gb_int=$((accum_disp / 1073741824))
                used_gb_frac=$(( (accum_disp % 1073741824) * 100 / 1073741824 ))
                printf -v used_gb "%d.%02d" "$used_gb_int" "$used_gb_frac"
                bw_info="${used_gb}/${bandwidth_gb} GB"
            fi

            banner_content="<br><font color="#00f2fe"><b>=== SGPX VIP SSH Status ===</b></font><br>"
            banner_content+="<font color="white">Username: $user</font><br>"
            banner_content+="<font color="white">Expiry: $expiry ($days_left)</font><br>"
            banner_content+="<font color="white">Bandwidth: $bw_info</font><br>"
            banner_content+="<font color="white">Active Devices: $online_count/$limit</font><br><br>"
            write_banner_if_changed "$user" "$banner_content"
        fi

        # 4. Count Bandwidth for ALL active users (Unlimited & Limited alike)
        usagefile="$BW_DIR/${user}.usage"
        accumulated=0
        if [[ -f "$usagefile" ]]; then
            read -r accumulated < "$usagefile"
            [[ "$accumulated" =~ ^[0-9]+$ ]] || accumulated=0
        fi

        if (( ${#unique_pids[@]} == 0 )); then
            rm -f "$PID_DIR/${user}__"*.last 2>/dev/null
            continue
        fi

        delta_total=0
        for pid in "${!unique_pids[@]}"; do
            io_file="/proc/$pid/io"
            cur=0
            if [[ -r "$io_file" ]]; then
                rchar=0
                wchar=0
                while read -r key value; do
                    case "$key" in
                        rchar:) rchar=${value:-0} ;;
                        wchar:) wchar=${value:-0} ;;
                    esac
                done < "$io_file"
                cur=$((rchar + wchar))
            fi

            pidfile="$PID_DIR/${user}__${pid}.last"
            if [[ -f "$pidfile" ]]; then
                read -r prev < "$pidfile"
                [[ "$prev" =~ ^[0-9]+$ ]] || prev=0
                if (( cur >= prev )); then
                    d=$((cur - prev))
                else
                    d=$cur
                fi
                delta_total=$((delta_total + d))
            else
                # When pid is first seen, cur is the initial bytes consumed so far
                delta_total=$((delta_total + cur))
            fi
            printf "%s
" "$cur" > "$pidfile"
        done

        for f in "$PID_DIR/${user}__"*.last; do
            [[ -f "$f" ]] || continue
            fpid=${f##*__}
            fpid=${fpid%.last}
            [[ -d "/proc/$fpid" ]] || rm -f "$f"
        done

        new_total=$((accumulated + delta_total))
        printf "%s
" "$new_total" > "$usagefile"

        # 5. Lock Account if Bandwidth Quota is exceeded (only if bandwidth_gb > 0)
        if [[ -n "$bandwidth_gb" && "$bandwidth_gb" =~ ^[0-9]+$ && "$bandwidth_gb" -gt 0 ]]; then
            quota_bytes=$(( bandwidth_gb * 1073741824 ))
            if (( new_total >= quota_bytes )); then
                if ! $user_locked; then
                    usermod -L "$user" &>/dev/null
                    killall -u "$user" -9 &>/dev/null
                    locked_users["$user"]=1
                fi
            fi
        fi
    done < "$DB_FILE"

    sleep "$SCAN_INTERVAL"
done
