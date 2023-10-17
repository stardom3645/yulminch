#!/usr/bin/env bash
#########################################
#Copyright (c) 2023 ABLECLOUD Co. Ltd.
#
#ccvm 초기화(bootstrap)하는 스크립트
#
#최초작성자 : 배태주 책임
#최초작성일 : 2023-07-12
#########################################
set -x
LOGFILE="/var/log/mold_install.log"

# hosts=$(grep -v mngt /etc/hosts | grep -v scvm | grep -v pn | grep -v localhost | awk {'print $1'})

#dnf -y --nogpgcheck install /opt/ablestack-4.0.0/rpms/* 2>&1 | tee -a $LOGFILE
dnf -y --nogpgcheck install /opt/ablestack-4.0.0/mold_rpms/* 2>&1 | tee -a $LOGFILE


sed -i "s/[openssl_init]/[openssl_init]\nrandom = random_section/" /etc/ssl/openssl.cnf
echo "" >> /etc/ssl/openssl.cnf && echo "[random_section]">> /etc/ssl/openssl.cnf && echo "random = CTR_DRBG" >> /etc/ssl/openssl.cnf

systemctl enable --now mysqld
DATABASE_PASSWD="Ablecloud1!"
DATABASE_PASSWD_ENC_KEY=$(openssl rand -base64 16)

################# firewall setting
firewall-cmd --permanent --zone=public --add-port=8080/tcp 2>&1 | tee -a $LOGFILE
firewall-cmd --permanent --zone=public --add-port=8443/tcp 2>&1 | tee -a $LOGFILE
firewall-cmd --permanent --zone=public --add-port=3306/tcp 2>&1 | tee -a $LOGFILE
firewall-cmd --permanent --zone=public --add-port=4444/tcp 2>&1 | tee -a $LOGFILE
firewall-cmd --permanent --zone=public --add-port=4567/tcp 2>&1 | tee -a $LOGFILE
firewall-cmd --permanent --zone=public --add-port=4568/tcp 2>&1 | tee -a $LOGFILE
firewall-cmd --permanent --zone=public --add-port=4569/tcp 2>&1 | tee -a $LOGFILE

firewall-cmd --permanent --zone=public --add-port=20048/tcp 2>&1 | tee -a $LOGFILE
firewall-cmd --permanent --zone=public --add-port=20048/udp 2>&1 | tee -a $LOGFILE
firewall-cmd --permanent --zone=public --add-port=21064/tcp 2>&1 | tee -a $LOGFILE
firewall-cmd --permanent --zone=public --add-port=2049/tcp 2>&1 | tee -a $LOGFILE

firewall-cmd --permanent --zone=public --add-port=875/tcp 2>&1 | tee -a $LOGFILE
firewall-cmd --permanent --zone=public --add-port=32803/tcp 2>&1 | tee -a $LOGFILE
firewall-cmd --permanent --zone=public --add-port=32769/tcp 2>&1 | tee -a $LOGFILE
firewall-cmd --permanent --zone=public --add-port=892/tcp 2>&1 | tee -a $LOGFILE
firewall-cmd --permanent --zone=public --add-port=600/tcp 2>&1 | tee -a $LOGFILE
firewall-cmd --permanent --zone=public --add-port=662/tcp 2>&1 | tee -a $LOGFILE
firewall-cmd --permanent --zone=public --add-port=8250/tcp 2>&1 | tee -a $LOGFILE
firewall-cmd --permanent --zone=public --add-service=mysql 2>&1 | tee -a $LOGFILE

firewall-cmd --reload
firewall-cmd --list-all 2>&1 | tee -a $LOGFILE

#nfs 구성
mkdir /nfs
echo '/nfs *(rw,no_root_squash,async)' >> /etc/exports
systemctl enable --now nfs-server.service

mkdir /nfs/primary
mkdir /nfs/secondary

# # Crushmap 설정 추가 (ceph autoscale)
# scvm=$(grep scvm-mngt /etc/hosts | awk {'print $1'})
# ssh -o StrictHostKeyChecking=no $scvm /usr/local/sbin/setCrushmap.sh

################# Setting Database
mysqladmin -uroot password $DATABASE_PASSWD
setenforce 0
#systemctl enable --now ablestack-usage
systemctl enable --now cloudstack-usage

#sed -i 's/SELINUX=enforcing/SELINUX=permissive/g' /etc/selinux/config
#cloudstack-setup-databases cloud:$DATABASE_PASSWD --deploy-as=root:$DATABASE_PASSWD 2>&1 | tee -a $LOGFILE
cloudstack-setup-databases cloud:$DATABASE_PASSWD --deploy-as=root:$DATABASE_PASSWD -m $DATABASE_PASSWD_ENC_KEY 2>&1 | tee -a $LOGFILE

# override DEK to 0 and 1
DATABASE_PASSWD_ENC_KEY=010101010101010101
DATABASE_PASSWD_ENC_KEY=100110101011010101
DATABASE_PASSWD_ENC_KEY=010010101001000110
DATABASE_PASSWD_ENC_KEY=111101011101101001
DATABASE_PASSWD_ENC_KEY=001001001111001110

# Cloudstack Global Setting
global_settings=("user.password.encoders.order=SHA256SALT,MD5,LDAP,PLAINTEXT" \
"user.password.encoders.exclude=" "usage.execution.timezone=Asia/Seoul" \
"network.loadbalancer.haproxy.stats.visibility=all" \
"storage.overprovisioning.factor=1" "enable.dynamic.scale.vm=true" \
"kvm.ha.activity.check.interval=60" "kvm.ha.activity.check.max.attempts=10" \
"kvm.ha.activity.check.timeout=60" "kvm.snapshot.enabled=true" )
for i in "${global_settings[@]}"
do
  key=$(echo $i | cut -d "=" -f 1)
  value=$(echo $i | cut -d "=" -f 2)
  mysql --user=root --password=$DATABASE_PASSWD -e "use cloud; UPDATE configuration SET value='$value' where name='$key';"  2>&1 | tee -a $LOGFILE
done

#ablestack-setup-management 2>&1 | tee -a $LOGFILE
cloudstack-setup-management 2>&1 | tee -a $LOGFILE
systemctl enable --now cloudstack-management 2>&1 | tee -a $LOGFILE

# #UEFI 설정 파일 생성
# echo -e "guest.nvram.template.secure=/usr/share/edk2/ovmf/OVMF_VARS.secboot.fd
# guest.nvram.template.legacy=/usr/share/edk2/ovmf/OVMF_VARS.fd
# guest.loader.secure=/usr/share/edk2/ovmf/OVMF_CODE.secboot.fd
# guest.loader.legacy=/usr/share/edk2/ovmf/OVMF_CODE.secboot.fd
# guest.nvram.path=/var/lib/libvirt/qemu/nvram/" > /root/uefi.properties

# for host in $hosts
# do
#   scp -o StrictHostKeyChecking=no /root/uefi.properties $host:/etc/cloudstack/agent/
# done

# rm -rf /root/uefi.properties

# #tpm 설정 파일 생성
# echo -e "host.tpm.enable=true" > /root/tpm.properties

# for host in $hosts
# do
#   scp -o StrictHostKeyChecking=no /root/tpm.properties $host:/etc/cloudstack/agent/
# done

# rm -rf /root/tpm.properties

#systemvm template 등록
/usr/share/cloudstack-common/scripts/storage/secondary/cloud-install-sys-tmplt \
-m /nfs/secondary \
-f /opt/ablestack-4.0.0/systemvmtemplate-* \
-h kvm -F  | tee -a $LOGFILE


# for host in $hosts
# do
#   ssh -o StrictHostKeyChecking=no $host /usr/bin/systemctl enable --now pacemaker
#   ssh -o StrictHostKeyChecking=no $host /usr/bin/systemctl enable --now corosync
# done

################# Security Check
# management 서비스 체크
# 3초 간격으로 서비스가 정상적으로 올라왔는지 체크하며, 5분 이후에 실패/성공에 상관없이 Security Check 실행
count=0
while [ $count -lt 100 ]
do
	cat /var/log/cloudstack/management/management-server.log | grep "Startup CloudStack management server"
	if [[ $? == 0 ]]; then
		break
	fi
	sleep 3;
	count=$((count+1))
done

# Security Check 실행
# mysql --user=root --password=$DATABASE_PASSWD -e "use cloud; CREATE TABLE IF NOT EXISTS security_check (id bigint unsigned NOT NULL AUTO_INCREMENT, mshost_id bigint unsigned NOT NULL COMMENT 'the ID of the mshost', check_name varchar(255) NOT NULL COMMENT 'name of the security check', last_update datetime DEFAULT NULL COMMENT 'last check update time', check_result tinyint(1) NOT NULL COMMENT 'check executions success or failure', check_details blob COMMENT 'check result detailed message', PRIMARY KEY (id), UNIQUE KEY i_security_checks__mshost_id__check_name (mshost_id,check_name), KEY i_security_checks__mshost_id (mshost_id), CONSTRAINT fk_security_checks__mshost_id FOREIGN KEY (mshost_id) REFERENCES mshost (id) ON DELETE CASCADE) ENGINE=InnoDB CHARSET=utf8mb3;" 2>&1 | tee -a $LOGFILE

# UUID=$(cat /proc/sys/kernel/random/uuid)
# mysql --user=root --password=$DATABASE_PASSWD -e "use cloud; INSERT INTO event (uuid, type, state, description, user_id, account_id, domain_id, resource_id, created, level, start_id, archived, display) VALUES ('$UUID', 'SECURITY.CHECK', 'Started', 'running security check on management server', '2', '2', '1', '0', now(), 'INFO', '0', '0', '1');" 2>&1 | tee -a $LOGFILE

# systemctl status mysqld | grep -i running &> /dev/null
# if [[ $? == 0 ]]; then
#   mysql --user=root --password=$DATABASE_PASSWD -e "use cloud; INSERT INTO security_check (mshost_id, check_name, last_update, check_result, check_details) VALUES ('1', 'mysql', now(), '1', 'service is running');" 2>&1 | tee -a $LOGFILE
# else
#   UUID=$(cat /proc/sys/kernel/random/uuid)
#   mysql --user=root --password=$DATABASE_PASSWD -e "use cloud; INSERT INTO security_check (mshost_id, check_name, last_update, check_result, check_details) VALUES ('1', 'mysql', now(), '0', 'service down at last check');" 2>&1 | tee -a $LOGFILE
#   mysql --user=root --password=$DATABASE_PASSWD -e "use cloud; INSERT INTO alert (uuid, type, pod_id, data_center_id, subject, sent_count, created, last_sent, archived, name) VALUES ('$UUID', '14', '0', '0', 'Management server node security check failed: mysql service down at last check', '1', now(), now(), '0', 'ALERT.MANAGEMENT');" 2>&1 | tee -a $LOGFILE
# fi

# systemctl status firewalld | grep -i running &> /dev/null
# if [[ $? == 0 ]]; then
#   mysql --user=root --password=$DATABASE_PASSWD -e "use cloud; INSERT INTO security_check (mshost_id, check_name, last_update, check_result, check_details) VALUES ('1', 'firewalld', now(), '1', 'service is running');" 2>&1 | tee -a $LOGFILE
# else
#   UUID=$(cat /proc/sys/kernel/random/uuid)
#   mysql --user=root --password=$DATABASE_PASSWD -e "use cloud; INSERT INTO security_check (mshost_id, check_name, last_update, check_result, check_details) VALUES ('1', 'firewalld', now(), '0', 'service down at last check');" 2>&1 | tee -a $LOGFILE
#   mysql --user=root --password=$DATABASE_PASSWD -e "use cloud; INSERT INTO alert (uuid, type, pod_id, data_center_id, subject, sent_count, created, last_sent, archived, name) VALUES ('$UUID', '14', '0', '0', 'Management server node security check failed: firewalld service down at last check', '1', now(), now(), '0', 'ALERT.MANAGEMENT');" 2>&1 | tee -a $LOGFILE
# fi

# systemctl status cloudstack-management | grep -i running &> /dev/null
# if [[ $? == 0 ]]; then
#   mysql --user=root --password=$DATABASE_PASSWD -e "use cloud; INSERT INTO security_check (mshost_id, check_name, last_update, check_result, check_details) VALUES ('1', 'management', now(), '1', 'service is running');" 2>&1 | tee -a $LOGFILE
# else
#   UUID=$(cat /proc/sys/kernel/random/uuid)
#   mysql --user=root --password=$DATABASE_PASSWD -e "use cloud; INSERT INTO security_check (mshost_id, check_name, last_update, check_result, check_details) VALUES ('1', 'management', now(), '0', 'service down at last check');" 2>&1 | tee -a $LOGFILE
#   mysql --user=root --password=$DATABASE_PASSWD -e "use cloud; INSERT INTO alert (uuid, type, pod_id, data_center_id, subject, sent_count, created, last_sent, archived, name) VALUES ('$UUID', '14', '0', '0', 'Management server node security check failed: management service down at last check', '1', now(), now(), '0', 'ALERT.MANAGEMENT');" 2>&1 | tee -a $LOGFILE
# fi

# UUID=$(cat /proc/sys/kernel/random/uuid)
# mysql --user=root --password=$DATABASE_PASSWD -e "use cloud; INSERT INTO event (uuid, type, state, description, user_id, account_id, domain_id, resource_id, created, level, start_id, archived, display) VALUES ('$UUID', 'SECURITY.CHECK', 'Completed', 'Successfully completed running security check on management server', '2', '2', '1', '0', now(),  'INFO', '0', '0', '1');" 2>&1 | tee -a $LOGFILE

################# Integrity Verification
# management 서비스 체크
# 3초 간격으로 서비스가 정상적으로 올라왔는지 체크하며, 5분 이후에 실패/성공에 상관없이 Integrity Verification 실행
count=0
while [ $count -lt 100 ]
do
	cat /var/log/cloudstack/management/management-server.log | grep "Startup CloudStack management server"
	if [[ $? == 0 ]]; then
		break
	fi
	sleep 3;
	count=$((count+1))
done

# 주요 파일에 대해 해시 값을 활용한 무결성 검증
echo "Run Integrity Verification"

# Integrity Verification 실행
mysql --user=root --password=$DATABASE_PASSWD -e "use cloud; CREATE TABLE IF NOT EXISTS integrity_verification_initial_hash (id bigint unsigned NOT NULL AUTO_INCREMENT, mshost_id bigint unsigned NOT NULL COMMENT 'the ID of the mshost', file_path varchar(255) NOT NULL COMMENT 'the file path for integrity verification', initial_hash_value varchar(255) COMMENT 'the initial hash value of the file', comparison_hash_value varchar(255) COMMENT 'the hash value for file comparison', verification_result tinyint(1) DEFAULT 1 COMMENT 'check executions success or failure', verification_date datetime DEFAULT NULL COMMENT 'the last verification time', verification_details blob COMMENT 'verification result detailed message', PRIMARY KEY (id), UNIQUE KEY i_integrity_verify__mshost_id__file_path (mshost_id,file_path), KEY i_integrity_verify__mshost_id (mshost_id), CONSTRAINT fk_integrity_verify__mshost_id FOREIGN KEY (mshost_id) REFERENCES mshost (id) ON DELETE CASCADE) ENGINE=InnoDB CHARSET=utf8mb3;" 2>&1 | tee -a $LOGFILE

UUID=$(cat /proc/sys/kernel/random/uuid)
mysql --user=root --password=$DATABASE_PASSWD -e "use cloud; INSERT INTO event (uuid, type, state, description, user_id, account_id, domain_id, resource_id, created, level, start_id, archived, display) VALUES ('$UUID', 'INTEGRITY.VERIFICATION', 'Started', 'Running integrity verification on management server when operating the product.', '2', '2', '1', '0', now(), 'INFO', '0', '0', '1');" 2>&1 | tee -a $LOGFILE

# 주요 파일 초기 해시 값 추출
paths=(
  "/etc/cloudstack/management/config.json"
  "/etc/cloudstack/management/db.properties"
  "/etc/cloudstack/management/environment.properties"
  "/etc/cloudstack/management/log4j-cloud.xml"
  "/etc/cloudstack/management/server.properties"
  "/etc/cloudstack/usage/log4j-cloud.xml"
)
for path in "${paths[@]}"; do
    for file in $(find "$path" -type f); do
        hash_value=$(sha512sum "$file" | awk '{print $1}')
        mysql --user=root --password=$DATABASE_PASSWD -e "use cloud; INSERT INTO integrity_verification_initial_hash (mshost_id, file_path, initial_hash_value, verification_date) VALUES ('1','$file', '$hash_value', now())" > /dev/null 2>&1
    done
done
# jar 파일 초기 해시 값 추출
directory="/usr/share/cloudstack-usage/lib"
declare -a jar_file_paths
for jar_file in $(find "$directory" -type f -name "*.jar"); do
    jar_file_paths+=("$jar_file")
done
for jar_path in "${jar_file_paths[@]}"; do
    for jar_file in $(find "$jar_path" -type f); do
        jar_hash_value=$(sha512sum "$jar_file" | awk '{print $1}')
        mysql --user=root --password=$DATABASE_PASSWD -e "use cloud; INSERT INTO integrity_verification_initial_hash (mshost_id, file_path, initial_hash_value, verification_date) VALUES ('1','$jar_file', '$jar_hash_value', now())" > /dev/null 2>&1
    done
done


# 주요 파일 비교 해시 값 추출 후, 실패 파일 리스트 업데이트
for path in "${paths[@]}"; do
    for file in $(find "$path" -type f); do
        hash_value=$(sha512sum "$file" | awk '{print $1}')
        mysql --user=root --password=$DATABASE_PASSWD -e "use cloud; UPDATE integrity_verification_initial_hash SET comparison_hash_value='$hash_value', verification_date=now() WHERE mshost_id='1' AND file_path='$file';" > /dev/null 2>&1
        mysql --user=root --password=$DATABASE_PASSWD -e "use cloud; UPDATE integrity_verification_initial_hash SET verification_result = (initial_hash_value = comparison_hash_value);" | tail -n +2 
        value="$(mysql --user=root --password=$DATABASE_PASSWD -se "use cloud; SELECT file_path FROM integrity_verification_initial_hash WHERE mshost_id='1' AND file_path='$file' AND verification_result=0;")"
        if [ -n "$value" ]; then
            failed_files+="$value, "
        fi
    done
done
# jar 파일 비교 해시 값 추출 후, 실패 파일 리스트 업데이트
for jar_path in "${jar_file_paths[@]}"; do
    for jar_file in $(find "$jar_path" -type f); do
        jar_hash_value=$(sha512sum "$jar_file" | awk '{print $1}')
        mysql --user=root --password=$DATABASE_PASSWD -e "use cloud; UPDATE integrity_verification_initial_hash SET comparison_hash_value='$jar_hash_value', verification_date=now() WHERE mshost_id='1' AND file_path='$jar_file';" > /dev/null 2>&1
        mysql --user=root --password=$DATABASE_PASSWD -e "use cloud; UPDATE integrity_verification_initial_hash SET verification_result = (initial_hash_value = comparison_hash_value);" | tail -n +2
        value="$(mysql --user=root --password=$DATABASE_PASSWD -se "use cloud; SELECT file_path FROM integrity_verification_initial_hash WHERE mshost_id='1' AND file_path='$jar_file' AND verification_result=0;")" > /dev/null 2>&1
        if [ -n "$value" ]; then
            failed_files+="$value, "
        fi
    done
done

# Remove the trailing comma from the last element
failed_files="${failed_files%, }"

# final result table 생성
mysql --user=root --password=$DATABASE_PASSWD -e "use cloud; CREATE TABLE IF NOT EXISTS integrity_verification_initial_hash_final_result (id bigint unsigned NOT NULL AUTO_INCREMENT, uuid varchar(40) null, mshost_id bigint unsigned NOT NULL COMMENT 'the ID of the mshost', verification_final_result tinyint(1) default 1 not null comment 'check executions success or failure', verification_date datetime DEFAULT NULL COMMENT 'the last verification time', verification_failed_list mediumtext null, type varchar(32) null, PRIMARY KEY (id), UNIQUE KEY i_integrity_verify__mshost_id__final_result (uuid, mshost_id), KEY i_integrity_verify__mshost_id (mshost_id), CONSTRAINT i_integrity_verify__mshost_id__file_path_final_result FOREIGN KEY (mshost_id) REFERENCES mshost (id) ON DELETE CASCADE) ENGINE=InnoDB CHARSET=utf8mb3;" 2>&1 | tee -a $LOGFILE
result=$(mysql --user=root --password=$DATABASE_PASSWD -se "use cloud; SELECT EXISTS(SELECT * FROM integrity_verification_initial_hash WHERE verification_result=0);")
UUID=$(cat /proc/sys/kernel/random/uuid)
if [ "$result" -eq 1 ]; then
    echo "exists failed files"
    mysql --user=root --password=$DATABASE_PASSWD -e "use cloud; INSERT INTO integrity_verification_initial_hash_final_result (uuid, mshost_id, verification_failed_list, verification_final_result, verification_date, type) VALUES ('$UUID', '1','$failed_files', '0', now(), 'Initial')" > /dev/null 2>&1
    UUID=$(cat /proc/sys/kernel/random/uuid)
    mysql --user=root --password=$DATABASE_PASSWD -e "use cloud; INSERT INTO alert (uuid, type, pod_id, data_center_id, subject, sent_count, created, last_sent, archived, name) VALUES ('$UUID', '14', '0', '0', 'Management server node integrity verification failed when operating the product.', '1', now(), now(), '0', 'ALERT.MANAGEMENT');" 2>&1 | tee -a $LOGFILE
    UUID=$(cat /proc/sys/kernel/random/uuid)
    mysql --user=root --password=$DATABASE_PASSWD -e "use cloud; INSERT INTO event (uuid, type, state, description, user_id, account_id, domain_id, resource_id, created, level, start_id, archived, display) VALUES ('$UUID', 'INTEGRITY.VERIFICATION', 'Completed', 'Failed to execute integrity verification on the management server when operating the product.', '2', '2', '1', '0', now(), 'INFO', '0', '0', '1');" 2>&1 | tee -a $LOGFILE
else
    echo "not exists failed files"
    mysql --user=root --password=$DATABASE_PASSWD -e "use cloud; INSERT INTO integrity_verification_initial_hash_final_result (uuid, mshost_id, verification_failed_list, verification_final_result, verification_date, type) VALUES ('$UUID','1','$failed_files', '1', now(), 'Initial')" > /dev/null 2>&1
    UUID=$(cat /proc/sys/kernel/random/uuid)
    mysql --user=root --password=$DATABASE_PASSWD -e "use cloud; INSERT INTO event (uuid, type, state, description, user_id, account_id, domain_id, resource_id, created, level, start_id, archived, display) VALUES ('$UUID', 'INTEGRITY.VERIFICATION', 'Completed', 'Successfully completed integrity verification on the management server when operating the product.', '2', '2', '1', '0', now(), 'INFO', '0', '0', '1');" 2>&1 | tee -a $LOGFILE
fi

# Security global setting 
# global_settings_hidden=("api.source.cidr.checks.enabled" "password.policy.allowUseOfLastUsedPassword" \
# "password.policy.allowContinuousLettersAndNumbersInputOnKeyboard" "password.policy.allowConsecutiveRepetitionsOfSameLettersAndNumbers" \
# "password.policy.allowPasswordToContainUsername" "password.policy.minimum.digits"  \
# "password.policy.minimum.lowercase.letters" "password.policy.minimum.special.characters" \
# "password.policy.minimum.uppercase.letters" "password.policy.minimum.length" "password.policy.maximum.length" \
# "incorrect.login.attempts.allowed" "incorrect.login.enable.time" "block.connected.session" \
# "allow.concurrent.connect.session" "event.delete.enabled" "event.purge.delay")
# for j in "${global_settings_hidden[@]}"
# do
#   name=$(echo $j)
#   mysql --user=root --password=$DATABASE_PASSWD -e "use cloud; UPDATE configuration SET category='Hidden' where name='$name';"  2>&1 | tee -a $LOGFILE
# done

echo "Mold install complete!!"  | tee -a $LOGFILE
echo "/opt/ablestack-4.0.0/after_setting.sh Please proceed."  | tee -a $LOGFILE
rm -rf /opt/ablestack-4.0.0/bootstrap.sh