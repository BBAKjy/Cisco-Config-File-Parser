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

writeFile.write("1. ?????? ??????\n")
writeFile.write("1.1 ???????????? ??????\n")
writeFile.write("==============================\n")
writeFile.write("[??????]\n")
writeFile.write("?????? ??????????????? ???????????? ???????????? ?????? ??????\n")
writeFile.write("==============================\n")
writeFile.write("[??????]\n")
writeFile.write("[+] ?????? ??????\n")

for i in range(len(config)):
    if 'username' in config[i]:
        writeFile.write(config[i])
        temp.append(config[i]) 

writeFile.write("\n")
writeFile.write("[+] ???????????? ?????????\n")

for account in temp:
    if 'password 7' in account:
        writeFile.write(account.split()[1] + " : " + decrypt_type7(account.split()[-1])+"\n")

    else:
        writeFile.write(account.split()[1] + " : " + "????????? ??????\n")

writeFile.write("\n")

#===========================================================================================================#
#===========================================================================================================#
#===========================================================================================================#

writeFile.write("1.2 ???????????? ????????? ??????\n")
writeFile.write("==============================\n")
writeFile.write("[??????]\n")
writeFile.write("?????? ?????? ????????? ????????? ????????? ???????????? ???????????? ????????? ?????? ??????\n")
writeFile.write("==============================\n")
writeFile.write("[??????]\n")

for account in temp:
    if 'password 7' in account and not validatePassword(decrypt_type7(account.split()[-1])):
        writeFile.write(account.split()[1] + " : " + "??????\n")

    else:
        writeFile.write(account.split()[1] + " : " + "??????\n")

writeFile.write("\n")

#===========================================================================================================#
#===========================================================================================================#
#===========================================================================================================#

writeFile.write("1.3 ???????????? ???????????? ??????\n")
writeFile.write("==============================\n")
writeFile.write("[??????]\n")
writeFile.write("???????????? ????????? ????????? ????????? ?????? ?????? -> Secret ????????? ???????????? ???\n")
writeFile.write("==============================\n")
writeFile.write("[??????]\n")
for account in temp:
    if not "secret" in account:
        writeFile.write(account.split()[1] + " : " + "??????\n")

    else:
        writeFile.write(account.split()[1] + " : " + "??????\n")

writeFile.write("\n")

#===========================================================================================================#
#===========================================================================================================#
#===========================================================================================================#

writeFile.write("1.4 ????????? ???????????? ?????? ?????? ??????\n")
writeFile.write("==============================\n")
writeFile.write("[??????]\n")
writeFile.write("????????? ?????? ????????? ????????? ???????????? ?????? ?????? ?????? -> 0 ~ 15????????? ????????? ??????\n")
writeFile.write("==============================\n")
writeFile.write("[??????]\n")

flag = False

for i in range(len(config)):
    if 'privilege exec' in config[i] or 'privilege-exec' in config[i]:
        writeFile.write(config[i])
        flag = True

if flag == False:
    writeFile.write("?????? ?????? ??????\n")

writeFile.write("\n")

#===========================================================================================================#
#===========================================================================================================#
#===========================================================================================================#

writeFile.write("2. ?????? ??????")
writeFile.write("2.1 VTY ??????(ACL) ??????\n")
writeFile.write("==============================\n")
writeFile.write("[??????]\n")
writeFile.write("?????? ?????????(VTY) ?????? ??? ????????? IP????????? ????????? ??? ????????? ???????????? ????????? ??????\n")
writeFile.write("==============================\n")
writeFile.write("[??????]\n")
writeFile.write("[+] VTY ??????\n")

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

writeFile.write("2.2 Session Timeout ??????\n")
writeFile.write("==============================\n")
writeFile.write("[??????]\n")
writeFile.write("Session Timeout ????????? ?????? ????????? ?????? ????????? ?????? ??????(5??? ?????? ??????)\n")
writeFile.write("==============================\n")
writeFile.write("[??????]\n")

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
writeFile.write("[+] ??????\n")

for i in range(len(config)):
    if 'timeout' in config[i]:
        writeFile.write(config[i])
        flag = True

if flag == False:
    writeFile.write("?????? ?????? ??????\n")

writeFile.write("\n")

#===========================================================================================================#
#===========================================================================================================#
#===========================================================================================================#

flag = False

writeFile.write("2.3 VTY ?????? ??? ????????? ???????????? ??????\n")
writeFile.write("==============================\n")
writeFile.write("[??????]\n")
writeFile.write("VTY ?????? ??? ????????? ????????????(SSH)??? ????????? ????????? ???????????? ?????? ?????? ??????\n")
writeFile.write("==============================\n")
writeFile.write("[??????]\n")
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
writeFile.write("[+] ??????\n")

for i in range(len(config)):
    if config[i].startswith('login') or config[i].startswith(' login'):
        writeFile.write(config[i])
        flag = True

if flag == False:
    writeFile.write("?????? ?????? ??????\n")

writeFile.write("\n")

#===========================================================================================================#
#===========================================================================================================#
#===========================================================================================================#


writeFile.write("2.4 ???????????? ?????? ???/?????? ?????? ?????? ??????\n")
writeFile.write("==============================\n")
writeFile.write("[??????]\n")
writeFile.write("???????????? ????????? ???????????? ?????? ?????? ?????? ??????\n")
writeFile.write("==============================\n")
writeFile.write("[??????]\n")
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
writeFile.write("[+] ??????\n")

for i in range(len(config)):
    if config[i].startswith('line'):
        writeFile.write(config[i])
        flag = True


writeFile.write("\n")

if flag == False:
    writeFile.write("?????? ?????? ??????\n")

#===========================================================================================================#
#===========================================================================================================#
#===========================================================================================================#

flag = False

writeFile.write("2.5 ????????? ??? ?????? ????????? ??????\n")
writeFile.write("==============================\n")
writeFile.write("[??????]\n")
writeFile.write("????????? ??? ?????? ???????????? ????????? ?????? ??????\n")
writeFile.write("==============================\n")
writeFile.write("[??????]\n")
for i in range(len(config)):
    if config[i].startswith('banner'):
        for j in range(99999):
            if config[i+j].startswith('^C'):
                break

            writeFile.write(config[i+j])
        
        flag = True

        break

if flag == False:
    writeFile.write("?????? ?????? ??????\n")

#===========================================================================================================#
#===========================================================================================================#
#===========================================================================================================#

writeFile.write("\n3. ?????? ??????\n")
writeFile.write("3.1 ?????? ?????? ?????? ??? ?????? ???????????? ??????\n")
writeFile.write("==============================\n")
writeFile.write("[??????]\n")
writeFile.write("?????? ?????? ????????? ???????????? ???????????? ?????? ????????? ?????? ?????? ?????? ??????\n")
writeFile.write("==============================\n")
writeFile.write("[??????]\n")
for i in range(len(config)):
    if 'version' in config[i]:
        writeFile.write(config[i])

writeFile.write("\n")

#===========================================================================================================#
#===========================================================================================================#
#===========================================================================================================#

writeFile.write("4. ?????? ??????\n")
writeFile.write("4.1 ?????? ?????? ?????? ??????\n")
writeFile.write("==============================\n")
writeFile.write("[??????]\n")
writeFile.write("????????? ?????? ????????? ?????? ????????? ???????????? ?????? ??????\n")
writeFile.write("==============================\n")
writeFile.write("[??????]\n")

flag = False

for i in range(len(config)):
    if 'logging host' in config[i]:
        writeFile.write(config[i])
        flag= True

if flag == False:
    writeFile.write("?????? ?????? ??????\n")

writeFile.write("\n")

#===========================================================================================================#
#===========================================================================================================#
#===========================================================================================================#

writeFile.write("4.2 ?????? ?????? ?????? ??????\n")
writeFile.write("==============================\n")
writeFile.write("[??????]\n")
writeFile.write("???????????? ?????? ???????????? ????????? ???????????? ?????? ????????? ?????????????????? ??????\n")
writeFile.write("==============================\n")
writeFile.write("[??????]\n")

flag = False

for i in range(len(config)):
    if 'logging buffer' in config[i]:
        writeFile.write(config[i])

        flag = True

if flag == False:
    writeFile.write("?????? ?????? ??????\n")

writeFile.write("\n")

#===========================================================================================================#
#===========================================================================================================#
#===========================================================================================================#

writeFile.write("4.3 ????????? ?????? ?????? ??????\n")
writeFile.write("==============================\n")
writeFile.write("[??????]\n")
writeFile.write("?????? ????????? ?????? ?????? ????????? ???????????? ?????? ??????\n")
writeFile.write("==============================\n")
writeFile.write("[??????]\n")
writeFile.write("1. Console Logging ??????\n")
writeFile.write("2. Buffered Logging ??????\n")
writeFile.write("3. Terminal Logging ??????\n")
writeFile.write("4. Syslog ??????\n")
writeFile.write("5. SNMP Traps ??????\n")
writeFile.write("6. ACL ?????? Logging ??????\n")

writeFile.write("\n")

#===========================================================================================================#
#===========================================================================================================#
#===========================================================================================================#

writeFile.write("4.4 NTP ?????? ??????\n")
writeFile.write("==============================\n")
writeFile.write("[??????]\n")
writeFile.write("NTP ????????? ?????? ????????? ??? ????????? ?????? ???????????? ????????? ?????? ??????\n")
writeFile.write("==============================\n")
writeFile.write("[??????]\n")

flag = False

for i in range(len(config)):
    if 'ntp' in config[i]:
        writeFile.write(config[i])

        flag = True

if flag == False:
    writeFile.write("?????? ?????? ??????\n")

writeFile.write("\n")

#===========================================================================================================#
#===========================================================================================================#
#===========================================================================================================#

writeFile.write("4.5 timestamp ?????? ??????\n")
writeFile.write("==============================\n")
writeFile.write("[??????]\n")
writeFile.write("Timestamp ?????? ????????? ???????????? ?????? ??????\n")
writeFile.write("==============================\n")
writeFile.write("[??????]\n")

flag = False

for i in range(len(config)):
    if 'timestamp' in config[i]:
        writeFile.write(config[i])

        flag = True

if flag == False:
    writeFile.write("?????? ?????? ??????\n")

writeFile.write("\n")

#===========================================================================================================#
#===========================================================================================================#
#===========================================================================================================#

writeFile.write("5. ?????? ??????\n")
writeFile.write("5.1 SNMP ????????? ??????\n")
writeFile.write("==============================\n")
writeFile.write("[??????]\n")
writeFile.write("SNMP v3 ?????? ????????? ??????????????? ???????????? ???????????? ?????? ?????? ??????\n")
writeFile.write("==============================\n")
writeFile.write("[??????]\n")

flag = False

for i in range(len(config)):
    if 'snmp' in config[i]:
        writeFile.write(config[i])

        flag = True

if flag == False:
    writeFile.write("?????? ?????? ??????\n")

writeFile.write("\n")

#===========================================================================================================#
#===========================================================================================================#
#===========================================================================================================#

writeFile.write("5.2 SNMP Community String ????????? ??????\n")
writeFile.write("[??????]\n")
writeFile.write("==============================\n")
writeFile.write("SNMP ???????????? ???????????? ?????????, ????????? ???????????? ?????? Community String??? ??????????????? ??????\n")
writeFile.write("==============================\n")
writeFile.write("[??????]\n")

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
    writeFile.write("?????? ?????? ??????\n")

writeFile.write("\n")

#===========================================================================================================#
#===========================================================================================================#
#===========================================================================================================#

writeFile.write("5.3 SNMP ACL ??????\n")
writeFile.write("==============================\n")
writeFile.write("[??????]\n")
writeFile.write("SNMP ???????????? ???????????? ?????????, SNMP ????????? ?????? ACL??? ????????? ?????? ??????\n")
writeFile.write("==============================\n")
writeFile.write("[??????]\n")
writeFile.write("?????? ??????\n")
writeFile.write("\n")

#===========================================================================================================#
#===========================================================================================================#
#===========================================================================================================#

writeFile.write("5.4 SNMP ???????????? ?????? ??????\n")
writeFile.write("==============================\n")
writeFile.write("[??????]\n")
writeFile.write("SNMP Community String ????????? RO??? ?????? ??????\n")
writeFile.write("==============================\n")
writeFile.write("[??????]\n")

flag = False

for i in range(len(config)):
    if 'community' in config[i]:
        writeFile.write(config[i])

        flag = True

if flag == False:
    writeFile.write("?????? ?????? ??????\n")

writeFile.write("\n")

#===========================================================================================================#
#===========================================================================================================#
#===========================================================================================================#

writeFile.write("5.5 TFTP ????????? ??????\n")
writeFile.write("==============================\n")
writeFile.write("[??????]\n")
writeFile.write("TFTP ???????????? ???????????? ?????????, ACL??? ???????????? ???????????? ?????? ??????\n")
writeFile.write("==============================\n")
writeFile.write("[??????]\n")

flag = False

for i in range(len(config)):
    if 'tftp' in config[i]:
        writeFile.write(config[i])

        flag = True

if flag == False:
    writeFile.write("?????? ?????? ??????\n")

writeFile.write("\n")

#===========================================================================================================#
#===========================================================================================================#
#===========================================================================================================#

writeFile.write("5.6 Spoofing ?????? ????????? ??????\n")
writeFile.write("==============================\n")
writeFile.write("[??????]\n")
writeFile.write("???????????? ????????? ???????????? Source IP??? ACL??? ????????? ?????? ??????\n")
writeFile.write("==============================\n")
writeFile.write("[??????]\n")
writeFile.write("?????? ??????\n")

writeFile.write("\n")

#===========================================================================================================#
#===========================================================================================================#
#===========================================================================================================#

writeFile.write("5.7 DDoS ?????? ?????? ??????\n")
writeFile.write("==============================\n")
writeFile.write("[??????]\n")
writeFile.write("DDoS ?????? ?????? ????????? ???????????? ?????? ??????\n")
writeFile.write("==============================\n")
writeFile.write("[??????]\n")
writeFile.write("?????? ??????\n")

writeFile.write("\n")

#===========================================================================================================#
#===========================================================================================================#
#===========================================================================================================#

writeFile.write("5.8 ???????????? ?????? ?????????????????? Shutdown ??????\n")
writeFile.write("==============================\n")
writeFile.write("[??????]\n")
writeFile.write("???????????? ?????? ?????????????????? ????????? ?????? ??????\n")
writeFile.write("==============================\n")
writeFile.write("[??????]\n")

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
    writeFile.write("?????? ?????? ??????\n")

#===========================================================================================================#
#===========================================================================================================#
#===========================================================================================================#

writeFile.write("5.9 TCP KeepAlive ????????? ??????\n")
writeFile.write("==============================\n")
writeFile.write("[??????]\n")

flag = False

for i in range(len(config)):
    if 'keepalive' in config[i]:
        writeFile.write(config[i])

        flag = True

if flag == False:
    writeFile.write("?????? ?????? ??????\n")

writeFile.write("\n")

#===========================================================================================================#
#===========================================================================================================#
#===========================================================================================================#

writeFile.write("5.10 Finger ????????? ??????\n")
writeFile.write("==============================\n")
writeFile.write("[??????]\n")

flag = False

for i in range(len(config)):
    if 'finger' in config[i]:
        writeFile.write(config[i])

        flag = True

if flag == False:
    writeFile.write("?????? ?????? ??????\n")

writeFile.write("\n")

#===========================================================================================================#
#===========================================================================================================#
#===========================================================================================================#

writeFile.write("5.11 ??? ????????? ??????\n")
writeFile.write("==============================\n")
writeFile.write("[??????]\n")

flag = False

for i in range(len(config)):
    if 'ip http' in config[i]:
        writeFile.write(config[i])

        flag = True

if flag == False:
    writeFile.write("?????? ?????? ??????\n")

writeFile.write("\n")

#===========================================================================================================#
#===========================================================================================================#
#===========================================================================================================#

writeFile.write("5.12 TCP/UDP Small ????????? ??????\n")
writeFile.write("==============================\n")
writeFile.write("[??????]\n")

flag = False

for i in range(len(config)):
    if 'tcp-small' in config[i] or 'udp-small' in config[i]:
        writeFile.write(config[i])

        flag = True

if flag == False:
    writeFile.write("?????? ?????? ??????\n")

writeFile.write("\n")

#===========================================================================================================#
#===========================================================================================================#
#===========================================================================================================#

writeFile.write("5.13 Bootp ????????? ??????\n")
writeFile.write("==============================\n")
writeFile.write("[??????]\n")

flag = False

for i in range(len(config)):
    if 'bootp' in config[i]:
        writeFile.write(config[i])

        flag = True

if flag == False:
    writeFile.write("?????? ?????? ??????\n")

writeFile.write("\n")

#===========================================================================================================#
#===========================================================================================================#
#===========================================================================================================#

writeFile.write("5.14 CDP ????????? ??????\n")
writeFile.write("==============================\n")
writeFile.write("[??????]\n")
writeFile.write("CDP ???????????? ???????????? ?????? ?????? ??????\n")
writeFile.write("==============================\n")
writeFile.write("[??????] - CDP ???????????? ???????????? ?????? ???????????????\n")

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

writeFile.write("5.15 Directed-Broadcast ??????\n")
writeFile.write("==============================\n")
writeFile.write("[??????]\n")

flag = False

for i in range(len(config)):
    if 'directed-Broadcast' in config[i]:
        writeFile.write(config[i])

        flag = True

if flag == False:
    writeFile.write("?????? ?????? ??????\n")

writeFile.write("\n")

#===========================================================================================================#
#===========================================================================================================#
#===========================================================================================================#

writeFile.write("5.16 Source ????????? ??????\n")
writeFile.write("==============================\n")
writeFile.write("[??????]\n")

flag = False

for i in range(len(config)):
    if 'source-route' in config[i]:
        writeFile.write(config[i])

        flag = True

if flag == False:
    writeFile.write("?????? ?????? ??????\n")

writeFile.write("\n")

#===========================================================================================================#
#===========================================================================================================#
#===========================================================================================================#

writeFile.write("5.17 Proxy ARP ??????\n")
writeFile.write("==============================\n")
writeFile.write("[??????]\n")
writeFile.write("ARP Proxy ???????????? ???????????? ?????? ?????? ??????\n")
writeFile.write("==============================\n")
writeFile.write("[??????] - ARP Proxy ???????????? ???????????? ?????? ?????? ???????????????\n")

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

writeFile.write("5.18 ICMP Unreachable, Redirect ??????\n")
writeFile.write("==============================\n")
writeFile.write("[??????]\n")
writeFile.write("ICMP Unreachable, ICMP Redirect??? ???????????? ?????? ?????? ??????\n")
writeFile.write("==============================\n")
writeFile.write("[??????] - ICMP Unreachable, ICMP Redirect??? ???????????? ?????? ?????? ???????????????\n")

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

writeFile.write("5.19 identd ????????? ??????\n")
flag = False

writeFile.write("==============================\n")
writeFile.write("[??????]\n")

for i in range(len(config)):
    if 'identd' in config[i]:
        writeFile.write(config[i])

        flag = True

if flag == False:
    writeFile.write("?????? ?????? ??????\n")

writeFile.write("\n")

#===========================================================================================================#
#===========================================================================================================#
#===========================================================================================================#

writeFile.write("5.20 Domain lookup ??????\n")

flag = False

writeFile.write("==============================\n")
writeFile.write("[??????]\n")

for i in range(len(config)):
    if 'domain' in config[i]:
        writeFile.write(config[i])

        flag = True

if flag == False:
    writeFile.write("?????? ?????? ??????\n")

writeFile.write("\n")

#===========================================================================================================#
#===========================================================================================================#
#===========================================================================================================#

writeFile.write("5.21 pad ??????\n")

flag = False

writeFile.write("==============================\n")
writeFile.write("[??????]\n")

for i in range(len(config)):
    if 'no service pad' in config[i].strip():
        writeFile.write(config[i])

        flag = True

if flag == False:
    writeFile.write("?????? ?????? ??????\n")

writeFile.write("\n")

#===========================================================================================================#
#===========================================================================================================#
#===========================================================================================================#

writeFile.write("5.22 Mask-reply ??????\n")

flag = False

writeFile.write("==============================\n")
writeFile.write("[??????]\n")

for i in range(len(config)):
    if 'mask-reply' in config[i]:
        writeFile.write(config[i])

        flag = True

if flag == False:
    writeFile.write("?????? ?????? ??????\n")

writeFile.write("\n")

#===========================================================================================================#
#===========================================================================================================#
#===========================================================================================================#

writeFile.write("5.23 ?????????, ?????? ?????? ??????\n")


writeFile.write("==============================\n")
writeFile.write("[??????]\n")
writeFile.write("L2 ????????? ??? ????????? ??????????????? N/A??????\n")

writeFile.write("\n")

#===========================================================================================================#
#===========================================================================================================#
#===========================================================================================================#

writeFile.write("<<???>>")