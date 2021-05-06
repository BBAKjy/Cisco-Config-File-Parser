import sys
import re

def decrypt_type7(ep):

    xlat = [0x64, 0x73, 0x66, 0x64, 0x3b, 0x6b, 0x66, 0x6f, 0x41, 0x2c, 0x2e, 0x69, 0x79, 0x65, 0x77, 0x72, 0x6b, 0x6c, 0x64
, 0x4a, 0x4b, 0x44, 0x48, 0x53, 0x55, 0x42, 0x73, 0x67, 0x76, 0x63, 0x61, 0x36, 0x39, 0x38, 0x33, 0x34, 0x6e, 0x63,
0x78, 0x76, 0x39, 0x38, 0x37, 0x33, 0x32, 0x35, 0x34, 0x6b, 0x3b, 0x66, 0x67, 0x38, 0x37]

    dp = ''
    regex = re.compile('(^[0-9A-Fa-f]{2})([0-9A-Fa-f]+)')
    result = regex.search(ep)
    s, e = int(result.group(1)), result.group(2)
    for pos in range(0, len(e), 2):
    	magic = int(e[pos] + e[pos+1], 16)
    	if s <= 50:
    		# xlat length is 51
    		newchar = '%c' % (magic ^ xlat[s])
    		s += 1
    	if s == 51: s = 0
    	dp += newchar
    return dp

def validatePassword(password):
    count = 0

    if len(password) < 8:
        return False

    if re.findall('[0-9]+', password):
        count += 1

    if re.findall('[a-z]', password):
        count += 1
        
    if re.findall('[A-Z]', password):
        count += 1

    if re.findall('[`~!@#$%^&*(),<.>/?]+', password):
        count += 1

    if count >= 3:
        return True

    return False

#===========================================================================================================#
#===========================================================================================================#
#===========================================================================================================#

try:
    readFile = open(sys.argv[1], mode = 'r', encoding="UTF-16")

except:
    print("\n[!] Usage : python [Python Script] [Target File]\n")
    sys.exit()

try:
    config = readFile.readlines()
except:
    readFile = open(sys.argv[1], mode = 'r', encoding="UTF-8")
    config = readFile.readlines()

writeFile = open(sys.argv[1]+"_result.txt", mode = 'w')

#===========================================================================================================#
#===========================================================================================================#
#===========================================================================================================#

temp = []

writeFile.write("1. 계정 관리\n")
writeFile.write("1.1 패스워드 설정\n")
writeFile.write("==============================\n")
writeFile.write("[기준]\n")
writeFile.write("기본 패스워드를 변경하여 사용하는 경우 양호\n")
writeFile.write("==============================\n")
writeFile.write("[현황]\n")
writeFile.write("[+] 계정 목록\n")

for i in range(len(config)):
    if 'username' in config[i]:
        writeFile.write(config[i])
        temp.append(config[i]) 

writeFile.write("\n")
writeFile.write("[+] 비밀번호 복호화\n")

for account in temp:
    if 'password 7' in account:
        writeFile.write(account.split()[1] + " : " + decrypt_type7(account.split()[-1])+"\n")

    else:
        writeFile.write(account.split()[1] + " : " + "복호화 불가\n")

writeFile.write("\n")

#===========================================================================================================#
#===========================================================================================================#
#===========================================================================================================#

writeFile.write("1.2 패스워드 복잡성 설정\n")
writeFile.write("==============================\n")
writeFile.write("[기준]\n")
writeFile.write("대상 기관 정책에 맞추어 적절한 패스워드 복잡성이 설정된 경우 양호\n")
writeFile.write("==============================\n")
writeFile.write("[현황]\n")

for account in temp:
    if 'password 7' in account and not validatePassword(decrypt_type7(account.split()[-1])):
        writeFile.write(account.split()[1] + " : " + "취약\n")

    else:
        writeFile.write(account.split()[1] + " : " + "양호\n")

writeFile.write("\n")

#===========================================================================================================#
#===========================================================================================================#
#===========================================================================================================#

writeFile.write("1.3 암호화된 패스워드 사용\n")
writeFile.write("==============================\n")
writeFile.write("[기준]\n")
writeFile.write("패스워드 암호화 설정이 적용된 경우 양호 -> Secret 설정이 존재해야 함\n")
writeFile.write("==============================\n")
writeFile.write("[현황]\n")
for account in temp:
    if not "secret" in account:
        writeFile.write(account.split()[1] + " : " + "취약\n")

    else:
        writeFile.write(account.split()[1] + " : " + "양호\n")

writeFile.write("\n")

#===========================================================================================================#
#===========================================================================================================#
#===========================================================================================================#

writeFile.write("1.4 사용자 명령어별 권한 수준 설정\n")
writeFile.write("==============================\n")
writeFile.write("[기준]\n")
writeFile.write("업무에 맞게 계정의 권한이 부여되어 있을 경우 양호 -> 0 ~ 15까지의 권한이 존재\n")
writeFile.write("==============================\n")
writeFile.write("[현황]\n")

flag = False

for i in range(len(config)):
    if 'privilege exec' in config[i] or 'privilege-exec' in config[i]:
        writeFile.write(config[i])
        flag = True

if flag == False:
    writeFile.write("해당 설정 없음\n")

writeFile.write("\n")

#===========================================================================================================#
#===========================================================================================================#
#===========================================================================================================#

writeFile.write("2. 접근 관리")
writeFile.write("2.1 VTY 접근(ACL) 설정\n")
writeFile.write("==============================\n")
writeFile.write("[기준]\n")
writeFile.write("원격 터미널(VTY) 접근 시 지정된 IP에서만 접근할 수 있도록 설정되어 있다면 양호\n")
writeFile.write("==============================\n")
writeFile.write("[현황]\n")
writeFile.write("[+] VTY 목록\n")

temp = []

for i in range(len(config)):
    if 'vty' in config[i]:
        for j in range(99999):
            if '!' in config[i+j] and not 'vty' in config[i+j+1]: 
                break
            
            writeFile.write(config[i+j])
            temp.append(config[i+j])

        flag = True

        break

writeFile.write("\n")
writeFile.write("[+] Access-Lists\n")

for i in range(len(temp)):
    if 'access-class' in temp[i]:
        for j in range(len(config)):
            if 'access-list ' + temp[i].split()[1] in config[j]:
                writeFile.write(config[j])

writeFile.write("\n")

#===========================================================================================================#
#===========================================================================================================#
#===========================================================================================================#

writeFile.write("2.2 Session Timeout 설정\n")
writeFile.write("==============================\n")
writeFile.write("[기준]\n")
writeFile.write("Session Timeout 시간을 기관 정책에 맞게 설정한 경우 양호(5분 이하 권고)\n")
writeFile.write("==============================\n")
writeFile.write("[현황]\n")

flag = False
writeFile.write("[+] Lines\n")
for i in range(len(config)):
    if config[i].startswith('line'):
        for j in range(99999):
            if '!' in config[i+j] and not 'line' in config[i+j+1]:
                break

            writeFile.write(config[i+j])
    
        flag = True

        break

writeFile.write("\n")
writeFile.write("[+] 결과\n")

for i in range(len(config)):
    if 'timeout' in config[i]:
        writeFile.write(config[i])
        flag = True

if flag == False:
    writeFile.write("해당 설정 없음\n")

writeFile.write("\n")

#===========================================================================================================#
#===========================================================================================================#
#===========================================================================================================#

flag = False

writeFile.write("2.3 VTY 접속 시 안전한 프로토콜 사용\n")
writeFile.write("==============================\n")
writeFile.write("[기준]\n")
writeFile.write("VTY 접근 시 암호화 프로토콜(SSH)을 이용한 접근만 허용하고 있는 경우 양호\n")
writeFile.write("==============================\n")
writeFile.write("[현황]\n")
writeFile.write("[+] Lines\n")

for i in range(len(config)):
    if 'vty' in config[i]:
        for j in range(99999):
            if '!' in config[i+j] and not 'vty' in config[i+j+1]: 
                break
            
            writeFile.write(config[i+j])

        flag = True

        break

writeFile.write("\n")
writeFile.write("[+] 결과\n")

for i in range(len(config)):
    if config[i].startswith('login') or config[i].startswith(' login'):
        writeFile.write(config[i])
        flag = True

if flag == False:
    writeFile.write("해당 설정 없음\n")

writeFile.write("\n")

#===========================================================================================================#
#===========================================================================================================#
#===========================================================================================================#


writeFile.write("2.4 불필요한 보조 입/출력 포트 사용 금지\n")
writeFile.write("==============================\n")
writeFile.write("[기준]\n")
writeFile.write("불필요한 포트를 사용하고 있지 않은 경우 양호\n")
writeFile.write("==============================\n")
writeFile.write("[현황]\n")
writeFile.write("[+] Lines\n")

flag = False

for i in range(len(config)):
    if config[i].startswith('line'):
        for j in range(99999):
            if '!' in config[i+j] and not 'line' in config[i+j+1]:
                break

            writeFile.write(config[i+j])
    
        flag = True

        break

writeFile.write("\n")
writeFile.write("[+] 결과\n")

for i in range(len(config)):
    if config[i].startswith('line'):
        writeFile.write(config[i])
        flag = True


writeFile.write("\n")

if flag == False:
    writeFile.write("해당 설정 없음\n")

#===========================================================================================================#
#===========================================================================================================#
#===========================================================================================================#

flag = False

writeFile.write("2.5 로그온 시 경고 메시지 설정\n")
writeFile.write("==============================\n")
writeFile.write("[기준]\n")
writeFile.write("로그온 시 경고 메시지를 설정한 경우 양호\n")
writeFile.write("==============================\n")
writeFile.write("[현황]\n")
for i in range(len(config)):
    if config[i].startswith('banner'):
        for j in range(99999):
            if config[i+j].startswith('^C'):
                break

            writeFile.write(config[i+j])
        
        flag = True

        break

if flag == False:
    writeFile.write("해당 설정 없음\n")

#===========================================================================================================#
#===========================================================================================================#
#===========================================================================================================#

writeFile.write("\n3. 패치 관리\n")
writeFile.write("3.1 최신 보안 패치 및 벤더 권고사항 적용\n")
writeFile.write("==============================\n")
writeFile.write("[기준]\n")
writeFile.write("패치 적용 정책을 수립하여 주기적인 패치 관리를 하고 있는 경우 양호\n")
writeFile.write("==============================\n")
writeFile.write("[현황]\n")
for i in range(len(config)):
    if 'version' in config[i]:
        writeFile.write(config[i])

writeFile.write("\n")

#===========================================================================================================#
#===========================================================================================================#
#===========================================================================================================#

writeFile.write("4. 로그 관리\n")
writeFile.write("4.1 원격 로그 서버 사용\n")
writeFile.write("==============================\n")
writeFile.write("[기준]\n")
writeFile.write("별도의 로그 서버를 통해 로그를 관리하는 경우 양호\n")
writeFile.write("==============================\n")
writeFile.write("[현황]\n")

flag = False

for i in range(len(config)):
    if 'logging host' in config[i]:
        writeFile.write(config[i])
        flag= True

if flag == False:
    writeFile.write("해당 설정 없음\n")

writeFile.write("\n")

#===========================================================================================================#
#===========================================================================================================#
#===========================================================================================================#

writeFile.write("4.2 로깅 버퍼 크기 설정\n")
writeFile.write("==============================\n")
writeFile.write("[기준]\n")
writeFile.write("저장되는 로그 데이터의 크기를 고려하여 버퍼 크기를 설정하였다면 양호\n")
writeFile.write("==============================\n")
writeFile.write("[현황]\n")

flag = False

for i in range(len(config)):
    if 'logging buffer' in config[i]:
        writeFile.write(config[i])

        flag = True

if flag == False:
    writeFile.write("해당 설정 없음\n")

writeFile.write("\n")

#===========================================================================================================#
#===========================================================================================================#
#===========================================================================================================#

writeFile.write("4.3 정책에 따른 로깅 설정\n")
writeFile.write("==============================\n")
writeFile.write("[기준]\n")
writeFile.write("로그 정책에 따라 로깅 설정이 되어있는 경우 양호\n")
writeFile.write("==============================\n")
writeFile.write("[현황]\n")
writeFile.write("1. Console Logging 확인\n")
writeFile.write("2. Buffered Logging 확인\n")
writeFile.write("3. Terminal Logging 확인\n")
writeFile.write("4. Syslog 확인\n")
writeFile.write("5. SNMP Traps 확인\n")
writeFile.write("6. ACL 침입 Logging 확인\n")

writeFile.write("\n")

#===========================================================================================================#
#===========================================================================================================#
#===========================================================================================================#

writeFile.write("4.4 NTP 서버 연동\n")
writeFile.write("==============================\n")
writeFile.write("[기준]\n")
writeFile.write("NTP 서버를 통한 시스템 간 실시간 시간 동기화가 설정된 경우 양호\n")
writeFile.write("==============================\n")
writeFile.write("[현황]\n")

flag = False

for i in range(len(config)):
    if 'ntp' in config[i]:
        writeFile.write(config[i])

        flag = True

if flag == False:
    writeFile.write("해당 설정 없음\n")

writeFile.write("\n")

#===========================================================================================================#
#===========================================================================================================#
#===========================================================================================================#

writeFile.write("4.5 timestamp 로그 설정\n")
writeFile.write("==============================\n")
writeFile.write("[기준]\n")
writeFile.write("Timestamp 로그 설정이 되어있는 경우 양호\n")
writeFile.write("==============================\n")
writeFile.write("[현황]\n")

flag = False

for i in range(len(config)):
    if 'timestamp' in config[i]:
        writeFile.write(config[i])

        flag = True

if flag == False:
    writeFile.write("해당 설정 없음\n")

writeFile.write("\n")

#===========================================================================================================#
#===========================================================================================================#
#===========================================================================================================#

writeFile.write("5. 기능 관리\n")
writeFile.write("5.1 SNMP 서비스 확인\n")
writeFile.write("==============================\n")
writeFile.write("[기준]\n")
writeFile.write("SNMP v3 이상 버전을 사용하거나 서비스를 사용하지 않는 경우 양호\n")
writeFile.write("==============================\n")
writeFile.write("[현황]\n")

flag = False

for i in range(len(config)):
    if 'snmp' in config[i]:
        writeFile.write(config[i])

        flag = True

if flag == False:
    writeFile.write("해당 설정 없음\n")

writeFile.write("\n")

#===========================================================================================================#
#===========================================================================================================#
#===========================================================================================================#

writeFile.write("5.2 SNMP Community String 복잡성 설정\n")
writeFile.write("[기준]\n")
writeFile.write("==============================\n")
writeFile.write("SNMP 서비스를 사용하지 않거나, 적절한 복잡성을 가진 Community String을 사용한다면 양호\n")
writeFile.write("==============================\n")
writeFile.write("[현황]\n")

flag = False

for i in range(len(config)):
    if 'community' in config[i]:
        temp = config[i].split()

        for j in range(len(temp)):
            if temp[j] == 'community':
                writeFile.write(temp[j+1] + " : " + str(validatePassword(temp[j+1])))

        flag = True

writeFile.write("\n")

if flag == False:
    writeFile.write("해당 설정 없음\n")

writeFile.write("\n")

#===========================================================================================================#
#===========================================================================================================#
#===========================================================================================================#

writeFile.write("5.3 SNMP ACL 설정\n")
writeFile.write("==============================\n")
writeFile.write("[기준]\n")
writeFile.write("SNMP 서비스를 사용하지 않거나, SNMP 접근에 대한 ACL을 적용한 경우 양호\n")
writeFile.write("==============================\n")
writeFile.write("[현황]\n")
writeFile.write("추후 수정\n")
writeFile.write("\n")

#===========================================================================================================#
#===========================================================================================================#
#===========================================================================================================#

writeFile.write("5.4 SNMP 커뮤니티 권한 설정\n")
writeFile.write("==============================\n")
writeFile.write("[기준]\n")
writeFile.write("SNMP Community String 권한이 RO인 경우 양호\n")
writeFile.write("==============================\n")
writeFile.write("[현황]\n")

flag = False

for i in range(len(config)):
    if 'community' in config[i]:
        writeFile.write(config[i])

        flag = True

if flag == False:
    writeFile.write("해당 설정 없음\n")

writeFile.write("\n")

#===========================================================================================================#
#===========================================================================================================#
#===========================================================================================================#

writeFile.write("5.5 TFTP 서비스 차단\n")
writeFile.write("==============================\n")
writeFile.write("[기준]\n")
writeFile.write("TFTP 서비스를 사용하지 않거나, ACL을 적용하여 사용하는 경우 양호\n")
writeFile.write("==============================\n")
writeFile.write("[현황]\n")

flag = False

for i in range(len(config)):
    if 'tftp' in config[i]:
        writeFile.write(config[i])

        flag = True

if flag == False:
    writeFile.write("해당 설정 없음\n")

writeFile.write("\n")

#===========================================================================================================#
#===========================================================================================================#
#===========================================================================================================#

writeFile.write("5.6 Spoofing 방지 필터링 적용\n")
writeFile.write("==============================\n")
writeFile.write("[기준]\n")
writeFile.write("악의적인 공격에 대비하여 Source IP에 ACL을 적용한 경우 양호\n")
writeFile.write("==============================\n")
writeFile.write("[현황]\n")
writeFile.write("추후 수정\n")

writeFile.write("\n")

#===========================================================================================================#
#===========================================================================================================#
#===========================================================================================================#

writeFile.write("5.7 DDoS 공격 방어 설정\n")
writeFile.write("==============================\n")
writeFile.write("[기준]\n")
writeFile.write("DDoS 공격 방어 설정이 되어있는 경우 양호\n")
writeFile.write("==============================\n")
writeFile.write("[현황]\n")
writeFile.write("추후 수정\n")

writeFile.write("\n")

#===========================================================================================================#
#===========================================================================================================#
#===========================================================================================================#

writeFile.write("5.8 사용하지 않는 인터페이스의 Shutdown 설정\n")
writeFile.write("==============================\n")
writeFile.write("[기준]\n")
writeFile.write("사용하지 않는 인터페이스가 차단된 경우 양호\n")
writeFile.write("==============================\n")
writeFile.write("[현황]\n")

flag = False

for i in range(len(config)):
    if config[i].startswith("interface"):
        for j in range(99999):
            if '!' in config[i+j] and not 'interface' in config[i+j+1]:
                break
        
            writeFile.write(config[i+j])

            flag = True

        break

writeFile.write("\n")

if flag == False:
    writeFile.write("해당 설정 없음\n")

#===========================================================================================================#
#===========================================================================================================#
#===========================================================================================================#

writeFile.write("5.9 TCP KeepAlive 서비스 설정\n")
writeFile.write("==============================\n")
writeFile.write("[현황]\n")

flag = False

for i in range(len(config)):
    if 'keepalive' in config[i]:
        writeFile.write(config[i])

        flag = True

if flag == False:
    writeFile.write("해당 설정 없음\n")

writeFile.write("\n")

#===========================================================================================================#
#===========================================================================================================#
#===========================================================================================================#

writeFile.write("5.10 Finger 서비스 차단\n")
writeFile.write("==============================\n")
writeFile.write("[현황]\n")

flag = False

for i in range(len(config)):
    if 'finger' in config[i]:
        writeFile.write(config[i])

        flag = True

if flag == False:
    writeFile.write("해당 설정 없음\n")

writeFile.write("\n")

#===========================================================================================================#
#===========================================================================================================#
#===========================================================================================================#

writeFile.write("5.11 웹 서비스 차단\n")
writeFile.write("==============================\n")
writeFile.write("[현황]\n")

flag = False

for i in range(len(config)):
    if 'ip http' in config[i]:
        writeFile.write(config[i])

        flag = True

if flag == False:
    writeFile.write("해당 설정 없음\n")

writeFile.write("\n")

#===========================================================================================================#
#===========================================================================================================#
#===========================================================================================================#

writeFile.write("5.12 TCP/UDP Small 서비스 차단\n")
writeFile.write("==============================\n")
writeFile.write("[현황]\n")

flag = False

for i in range(len(config)):
    if 'tcp-small' in config[i] or 'udp-small' in config[i]:
        writeFile.write(config[i])

        flag = True

if flag == False:
    writeFile.write("해당 설정 없음\n")

writeFile.write("\n")

#===========================================================================================================#
#===========================================================================================================#
#===========================================================================================================#

writeFile.write("5.13 Bootp 서비스 차단\n")
writeFile.write("==============================\n")
writeFile.write("[현황]\n")

flag = False

for i in range(len(config)):
    if 'bootp' in config[i]:
        writeFile.write(config[i])

        flag = True

if flag == False:
    writeFile.write("해당 설정 없음\n")

writeFile.write("\n")

#===========================================================================================================#
#===========================================================================================================#
#===========================================================================================================#

writeFile.write("5.14 CDP 서비스 차단\n")
writeFile.write("==============================\n")
writeFile.write("[기준]\n")
writeFile.write("CDP 서비스가 제한되어 있는 경우 양호\n")
writeFile.write("==============================\n")
writeFile.write("[현황] - CDP 서비스가 제한되지 않은 인터페이스\n")

buffer = []

for i in range(len(config)):
    if config[i].startswith("interface"):
        for j in range(99999):
            if '!' in config[i+j] and not 'interface' in config[i+j+1]: 
                break
                
            if '!' in config[i+j]:
                if("no cdp enable" not in buffer):
                    writeFile.write(buffer[0] + "\n")
                    buffer = []

                    continue
            
            buffer.append(config[i+j].strip())
        break

writeFile.write("\n")

#===========================================================================================================#
#===========================================================================================================#
#===========================================================================================================#

writeFile.write("5.15 Directed-Broadcast 차단\n")
writeFile.write("==============================\n")
writeFile.write("[현황]\n")

flag = False

for i in range(len(config)):
    if 'directed-Broadcast' in config[i]:
        writeFile.write(config[i])

        flag = True

if flag == False:
    writeFile.write("해당 설정 없음\n")

writeFile.write("\n")

#===========================================================================================================#
#===========================================================================================================#
#===========================================================================================================#

writeFile.write("5.16 Source 라우팅 차단\n")
writeFile.write("==============================\n")
writeFile.write("[현황]\n")

flag = False

for i in range(len(config)):
    if 'source-route' in config[i]:
        writeFile.write(config[i])

        flag = True

if flag == False:
    writeFile.write("해당 설정 없음\n")

writeFile.write("\n")

#===========================================================================================================#
#===========================================================================================================#
#===========================================================================================================#

writeFile.write("5.17 Proxy ARP 차단\n")
writeFile.write("==============================\n")
writeFile.write("[기준]\n")
writeFile.write("ARP Proxy 서비스가 제한되어 있는 경우 양호\n")
writeFile.write("==============================\n")
writeFile.write("[현황] - ARP Proxy 서비스가 제한되어 있지 않은 인터페이스\n")

buffer = []

for i in range(len(config)):
    if config[i].startswith("interface"):
        for j in range(99999):
            if '!' in config[i+j] and not 'interface' in config[i+j+1]: 
                break
                
            if '!' in config[i+j]:
                if("no ip proxy-arp" not in buffer):
                    writeFile.write(buffer[0] + "\n")
                    buffer = []
                    
                    continue
            
            buffer.append(config[i+j].strip())
        break

writeFile.write("\n")

#===========================================================================================================#
#===========================================================================================================#
#===========================================================================================================#

writeFile.write("5.18 ICMP Unreachable, Redirect 차단\n")
writeFile.write("==============================\n")
writeFile.write("[기준]\n")
writeFile.write("ICMP Unreachable, ICMP Redirect가 차단되어 있는 경우 양호\n")
writeFile.write("==============================\n")
writeFile.write("[현황] - ICMP Unreachable, ICMP Redirect가 차단되어 있지 않은 인터페이스\n")

buffer = []

for i in range(len(config)):
    if config[i].startswith("interface"):
        for j in range(99999):
            if '!' in config[i+j] and not 'interface' in config[i+j+1]: 
                break
                
            if '!' in config[i+j]:
                if("no ip redirects" not in buffer and "no ip unreachables" not in buffer):
                    writeFile.write(buffer[0] + "\n")
                    buffer = []
                    
                    continue
            
            buffer.append(config[i+j].strip())
        break

writeFile.write("\n")

#===========================================================================================================#
#===========================================================================================================#
#===========================================================================================================#

writeFile.write("5.19 identd 서비스 차단\n")
flag = False

writeFile.write("==============================\n")
writeFile.write("[현황]\n")

for i in range(len(config)):
    if 'identd' in config[i]:
        writeFile.write(config[i])

        flag = True

if flag == False:
    writeFile.write("해당 설정 없음\n")

writeFile.write("\n")

#===========================================================================================================#
#===========================================================================================================#
#===========================================================================================================#

writeFile.write("5.20 Domain lookup 차단\n")

flag = False

writeFile.write("==============================\n")
writeFile.write("[현황]\n")

for i in range(len(config)):
    if 'domain' in config[i]:
        writeFile.write(config[i])

        flag = True

if flag == False:
    writeFile.write("해당 설정 없음\n")

writeFile.write("\n")

#===========================================================================================================#
#===========================================================================================================#
#===========================================================================================================#

writeFile.write("5.21 pad 차단\n")

flag = False

writeFile.write("==============================\n")
writeFile.write("[현황]\n")

for i in range(len(config)):
    if 'no service pad' in config[i].strip():
        writeFile.write(config[i])

        flag = True

if flag == False:
    writeFile.write("해당 설정 없음\n")

writeFile.write("\n")

#===========================================================================================================#
#===========================================================================================================#
#===========================================================================================================#

writeFile.write("5.22 Mask-reply 차단\n")

flag = False

writeFile.write("==============================\n")
writeFile.write("[현황]\n")

for i in range(len(config)):
    if 'mask-reply' in config[i]:
        writeFile.write(config[i])

        flag = True

if flag == False:
    writeFile.write("해당 설정 없음\n")

writeFile.write("\n")

#===========================================================================================================#
#===========================================================================================================#
#===========================================================================================================#

writeFile.write("5.23 스위치, 허브 보안 강화\n")


writeFile.write("==============================\n")
writeFile.write("[현황]\n")
writeFile.write("L2 스위치 및 허브는 일반적으로 N/A처리\n")

writeFile.write("\n")

#===========================================================================================================#
#===========================================================================================================#
#===========================================================================================================#

writeFile.write("<<끝>>")