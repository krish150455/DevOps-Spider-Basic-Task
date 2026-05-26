#!/usr/bin/bash
TARGET_DIR="$1"
if [ -z "$TARGET_DIR" ];then
	echo "Type as: ./vault_sweep.sh <directory>"
	exit 1
fi

echo "Currently scanning directory: $TARGET_DIR"

#For Logging and Audit
LOG_DIR="logs"
LOG_FILE="$LOG_DIR/vault_sweep.log"
mkdir -p "$LOG_DIR"
touch "$LOG_FILE"
chmod 700 "$LOG_DIR"
chmod 600 "$LOG_FILE"

log_msg(){
        local lvl="$1"
        local msg="$2"
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$lvl] $msg" >> "$LOG_FILE"
}

DANGEROUS_PATTERNS=(
    "rm -rf /"
    "mkfs"
    "shutdown"
    "reboot"
    "curl.+\|.+sh"
    "curl.+\|.+bash"
    "wget.+\|.+sh"
    "wget.+\|.+bash"
    "/dev/tcp/"
    "dd if="
    "chmod 777"
    "sudo su"
    "scp"
)

SECRETIVE_PATTERNS=(
    "API_KEY"
    "TOKEN"
    "SECRET"
    "PASSWORD"
    "sk-[a-zA-Z0-9]+"
)

find "$TARGET_DIR" -type f | while read -r file; do
	echo "Currently reading file: $file"
	log_msg "INFO" "Scanned file: $file"
	#File Cleaning:
	if [[ ("$file" == *.env || "$file" == *.env*) && "$file" != *.sanitized ]]; then
		echo "Detected a environment file:$file....sanitizing it"
		SANITIZED_ENV="$file.sanitized"
		> "$SANITIZED_ENV"
		valid_num=0
		invalid_num=0
		while IFS= read -r line; do
			if [[ "$line" =~ ^[A-Z0-9_]+=[^\"\'[:space:]]+$ ]]; then
				if [[ "${line%%=*}" =~ ^(PASSWORD|PATH|TOKEN|SECRET)$ ]];then
					echo "[WARN] $file Reason: Rejected sensitive info:$line "
					((invalid_num++))
					log_msg "SKIP" "Rejected sensitive info in $file:$line"
				else
					echo "$line" >> "$SANITIZED_ENV"
					((valid_num++))
				fi
			else
				echo "[SKIP] $file Reason: Rejected invalid ENV variable line:$line"
				((invalid_num++))
				log_msg "SKIP" "Rejected line in $file: $line"
			fi
		done < "$file"
		log_msg "INFO" "For $file, valid:$valid_num and invalid:$invalid_num"
	#Threat Detection:
	elif [[ "$file" == *.sh ]]; then
		echo "Detected a script file:$file...now scanning threats"
		if find "$file" -perm -o+w | grep -q .; then
    			echo "[WARN] $file Reason: World writable permissions detected in file"
			log_msg "WARN" "World writable permissions detected in $file"
			read -p "Fix permissions for $file? (yes/no): " answer < /dev/tty
			if [[ "$answer"=="yes" ]]; then
				chmod o-w "$file"
				echo "[FIX] $file Reason: Removed world write permission from $file"
				log_msg "FIX" "Removed world write permission from $file"
			fi
		fi
		for pattern in "${DANGEROUS_PATTERNS[@]}"; do
			if grep -Eq "$pattern" "$file"; then #-Eq to search dngrous patterns without printing if matching
				echo "[WARN] $file Reason: Dangerous pattern in file: $pattern"
				log_msg "WARN" "Dangerous pattern:$pattern found in $file"
			fi
		done
	#Bonus Task - 1
	elif [[ "$file" == *.py || "$file" == *.js ]]; then
		echo "Detected other type of file:$file...now scanning secrets"
		for pattern in "${SECRETIVE_PATTERNS[@]}"; do
			if grep -En "$pattern" "$file"; then #To show line number along with regex search
				echo "[WARN] $file Reason: Possible secret pattern detected: $pattern"
				log_msg "WARN" "Possible secret pattern:$pattern detected in $file"
			fi
		done
	fi
done
