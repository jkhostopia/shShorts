from flask import render_template, request, make_response, jsonify
from app import app
import spur, sys, re, geoip2.database, json

@app.route('/')
@app.route('/index')
def index():
    pagesettings = {'title': 'Index Page'}
    return render_template('index.html')


# code for the r1soft checking tool
@app.route('/r1check_results')
@app.route('/r1check', methods=['GET', 'POST'])
def r1check():
    # triggered when the submit button is pressed
    if request.method == 'POST':
    
        # prepares ssh login
        sshhost = request.form.get('sshhost')
        sshuser = request.form['sshuser']
        sshpass = request.form['sshpass']
        sshport = request.form['sshport']
        shell = spur.SshShell(hostname=sshhost, 
                        username=sshuser, 
                        password=sshpass,
                        port = sshport,
                        missing_host_key=spur.ssh.MissingHostKey.accept)
                        
        # options in ssh command
        sshhosttype = request.form['hosttype']
        sshr1server = request.form['r1server']
                
        with shell:
        
            #### START prepares ssh commands to run
            
            # lists network routes
            com_route = shell.run(["sh", "-c", f"route -n"])
            str_route = f"route -n"
            
            # Lists network interfaces
            com_nics = shell.run(["sh", "-c", f"ip a"])
            str_nics = "ip a"
            
            # pings the r1soft server 4 times
            com_r1ping = shell.run(["sh", "-c", f"ping -c 4 {sshr1server}"])
            str_r1ping = f"ping -c 4 {sshr1server}"

            # gets the kernel version
            com_kernelver = shell.run(["sh", "-c", "uname -r"])
            str_kernelver = "uname -r"

            # lists installed kernel modules
            com_kernelmods = shell.run(["sh", "-c", r"rpm -qa | grep kernel"])
            str_kernelmods = r"rpm -qa | grep kernel"

            #### END prepares ssh commands to run
            
            # outputs to r1check_results.html and renders the ssh command results
            return render_template('r1check_results.html',
                                com_r1ping=com_r1ping, str_r1ping=str_r1ping,
                                com_nics=com_nics, str_nics=str_nics,
                                com_route=com_route, str_route=str_route,
                                com_kernelver=com_kernelver, str_kernelver=str_kernelver,
                                com_kernelmods=com_kernelmods, str_kernelmods=str_kernelmods,
                                sshhost=sshhost, sshhosttype=sshhosttype, sshr1server=sshr1server
                                )
        
    return render_template('r1check.html', 
        title='R1soft Connection Checker')


# code for the large files and folders checking tool
@app.route('/diskcheck_results')
@app.route('/diskcheck', methods=['GET', 'POST'])
def diskcheck():
    # triggered when the submit button is pressed
    if request.method == 'POST':
    
        # prepares ssh login
        sshhost = request.form.get('sshhost')
        sshuser = request.form['sshuser']
        sshpass = request.form['sshpass']
        sshport = request.form['sshport']
        shell = spur.SshShell(hostname=sshhost, 
                        username=sshuser, 
                        password=sshpass,
                        port = sshport,
                        missing_host_key=spur.ssh.MissingHostKey.accept)
                        
        # options in ssh command
        ssh_minfilesize = request.form['minfilesize']
                
        with shell:
        
            #### START prepares ssh commands to run
            
            # displays disk usage numbers
            com_df = shell.run(["sh", "-c", r"df -h -t ext4 -t ext3"])
            str_df = r"df -h -t ext4 -t ext3"
            
            # lists all files larger than ssh_minfilesize under /home/ and /backup/
            com_largefiles = shell.run(["sh", "-c", r"find /home/ /backup/ /var/log/ /usr/local/ -type f -size +" + ssh_minfilesize + " -exec ls -lh {} \; | awk {'print $5, $9'}  | sort -h"])
            str_largefiles = r"find /home/ /backup/ /var/log/ /usr/local/ -type f -size +" + ssh_minfilesize + " -exec ls -lh {} \; | awk {'print $5, $9'}  | sort -h"
            
            # lists 20 largest folders under /home/ and /backup/
            com_largedirs = shell.run(["sh", "-c", r"du -Sh /home/ /backup/ | sort -rh | head -20"])
            str_largedirs = r"du -Sh /home/ /backup/ | sort -rh | head -20"
            
            # gets hostname, for ticket template
            com_hostname = shell.run(["sh", "-c", r"hostname"])
            
            # gets percentage used space
            com_spaceused = shell.run(["sh", "-c", r"df -h -t ext4 -t ext3 | grep -v Filesystem  | awk 'FNR == 1 {print $5}'"])
            
            # gets size of free space
            com_spacefree = shell.run(["sh", "-c", r"df -h -t ext4 -t ext3 | grep -v Filesystem  | awk 'FNR == 1 {print $4}'"])
            
            #### END prepares ssh commands to run
            
            # outputs to diskcheck_results.html and renders the ssh command results
            return render_template('diskcheck_results.html', 
                                    com_largefiles=com_largefiles, str_largefiles=str_largefiles,
                                    com_largedirs=com_largedirs, str_largedirs=str_largedirs,
                                    com_df=com_df, str_df=str_df, com_hostname=com_hostname,
                                    com_spaceused=com_spaceused, com_spacefree=com_spacefree,
                                    sshhost=sshhost, ssh_minfilesize=ssh_minfilesize)
                
    return render_template('diskcheck.html',
        title='Disk Usage Check')


# code for the bot and WP attack checking tool
@app.route('/botwpcheck_results')
@app.route('/botwpcheck', methods=['GET', 'POST'])
def wpcheck():
    # triggered when the submit button is pressed
    if request.method == 'POST':
    
        # prepares ssh login
        sshhost = request.form.get('sshhost')
        sshuser = request.form['sshuser']
        sshpass = request.form['sshpass']
        sshport = request.form['sshport']
        shell = spur.SshShell(hostname=sshhost, 
                        username=sshuser, 
                        password=sshpass,
                        port = sshport,
                        missing_host_key=spur.ssh.MissingHostKey.accept)
                        
        with shell:
        
            #### START prepares ssh commands to run
            
            # checks access logs for xmlrpc and wp-login hits
            #com_atkcheck = shell.run(["sh", "-c", r"less /home/*/access-logs/* | grep -iE 'xmlrpc|wp-login' |  awk '{print $1 " " $12}' | sort | uniq -c | awk '{print $2 " " $1 " " $3}'"])
            com_atkcheck = shell.run(["sh", "-c", r"less /home/*/access-logs/* | grep -iE 'xmlrpc|wp-login' |  awk '{print $1 " " $12}' | sort | uniq -c"])
            str_atkcheck = r"less /home/*/access-logs/* | grep -i 'xmlrpc\|wp-login\' |  awk '{print $1}' | sort | uniq -c | sort -n"
            
            com_botcheck = shell.run(["sh", "-c", r"less /home/*/access-logs/* | grep -i 'semrush\|dotbot\|mj12\|ahrefs\|yandex\' |  awk '{print $1}' | sort | uniq -c | sort -n"])
            str_botcheck = r"less /home/*/access-logs/* | grep -i 'semrush\|dotbot\|mj12\|ahrefs\|yandex\' |  awk '{print $1}' | sort | uniq -c | sort -n"
            
            #### END prepares ssh commands to run
            
            ### START converts the command outputs from binary to dict
            
            print('#########################################')
            print("changes com_atkcheck (a) and com_botcheck (b) type from binary to multiline str")
            print('#########################################')
            
            # changes com_atkcheck (a) and com_botcheck (b) type from binary to multiline str
            a_str = com_atkcheck.output.decode()
            a_str = a_str.splitlines()
            
            b_str = com_botcheck.output.decode()
            b_str = b_str.splitlines()
            
            print('#########################################')
            print("changes com_atkcheck (a) and com_botcheck (b) type from binary to multiline str")
            print(a_str, file=sys.stderr)
            print('#########################################')
            
            # converts atkcheck_str (a) and com_botcheck (b) from multiline str to list
            
            a_str = [re.sub('      ', '', i) for i in a_str]
            b_str = [re.sub('      ', '', i) for i in b_str]
            a_str = [re.sub('     ', '', i) for i in a_str]
            b_str = [re.sub('     ', '', i) for i in b_str]
           
            
            # separates the user agent into it's own list item
            a_list = []
            
            for i in a_str:
                i = i.split('"')
                a_list.extend(i)
                
            b_list = []    
            for i in b_str:
                i = i.split('"')
                b_list.extend(i)

            
            # separates the IP and count into their own list items
            a_listb = []
            for i in a_list:
                i = i.split(" ", 1)
                a_listb.extend(i)
                
            b_listb = []
            for i in a_list:
                i = i.split(" ", 1)
                b_listb.extend(i)

            # separates the IP and count into their own list items
             
            # converts the lists into dicts
            a_dict = {}
            for i, j, k in zip(a_listb[0::3], a_listb[1::3], a_listb[2::3]):
                a_dict.update( {j: [i, k]} )
                
            b_dict = {}
            for i, j, k in zip(b_listb[0::3], b_listb[1::3], b_listb[2::3]):
                b_dict.update( {j: [i, k]} )
            
            ### END converts the command outputs from binary to dict
            
            ### START add geoip data to dict
            
            with geoip2.database.Reader('GeoLite2-City.mmdb') as reader:
                for k, v in a_dict.items():
                    response = reader.city(k)
                    i = response.country.name
                    v.append(i)
                    
                for k, v in b_dict.items():
                    response = reader.city(k)
                    i = response.country.name
                    v.append(i)
                
            with geoip2.database.Reader('GeoLite2-ASN.mmdb') as reader:
                for k, v in a_dict.items():
                    response = reader.asn(k)
                    i = response.autonomous_system_organization
                    v.append(i)
                    
                for k, v in b_dict.items():
                    response = reader.asn(k)
                    i = response.autonomous_system_organization
                    v.append(i)
            
            ### END add geoip data to dict
            
            # converts the dicts to json, edits code to make prettier when rendered
            check_wpattack = json.dumps(a_dict, separators=(',', ':')).replace("],", "\n")
            check_wpattack = check_wpattack.translate(str.maketrans({'{': '', '}': '', '"': '', '[': '', ']': '', ',': ' - ', ':': ': '}))
            
            check_botattack = json.dumps(b_dict, separators=(',', ':')).replace("],", "\n")
            check_botattack = check_botattack.translate(str.maketrans({'{': '', '}': '', '"': '', '[': '', ']': '', ',': ' - ', ':': ': '}))
            
            # outputs to diskcheck_results.html and renders the ssh command results
            return render_template('botwpcheck_results.html',  
                                    check_wpattack=check_wpattack, str_atkcheck=str_atkcheck,
                                    check_botattack=check_botattack, str_botcheck=str_botcheck,
                                    sshhost=sshhost,)
        
        
    return render_template('botwpcheck.html',
        title='Bot & WP Attack Check')


# code for the "what happened to the server around this time" checking tool
@app.route('/timecheck_results')        
@app.route('/timecheck', methods=['GET', 'POST'])
def timecheck():
    # triggered when the submit button is pressed
    if request.method == 'POST':
    
        # prepares ssh login
        sshhost = request.form.get('sshhost')
        sshuser = request.form['sshuser']
        sshpass = request.form['sshpass']
        sshport = request.form['sshport']
        shell = spur.SshShell(hostname=sshhost, 
                        username=sshuser, 
                        password=sshpass,
                        port = sshport,
                        missing_host_key=spur.ssh.MissingHostKey.accept)
                        
        # options in ssh command                        
        sshsite = request.form['sshsite']
        sshaccesstime = request.form['sshaccesstime']
        sshapachetime = request.form['sshapachetime']
        sshmysqltime = request.form['sshmysqltime']
        sshsarday = request.form['sshsarday']
        
        #### START prepares ssh commands to run                        
        
        # command to check cPanel access logs
        com_accesslog = shell.run(["sh", "-c", r'zgrep "' + sshaccesstime + '" /home/*/logs/* /home/*/access-logs/*'],
                        allow_error=True)
        str_accesslog = r'zgrep "' + sshaccesstime + '" /home/*/logs/* /home/*/access-logs/*'
            
        
        print('#########################################')
        print("Access Logs")
        print(str_accesslog, file=sys.stderr)
        print('#########################################')
        
        
        # command to check Apache error logs
        com_apacheerror = shell.run(["sh", "-c", r'grep "' + sshapachetime + '" /usr/local/apache/logs/error_log' + f" | awk '/{sshsite}/'" ])
        str_apacheerror = r'grep "' + sshapachetime + '" /usr/local/apache/logs/error_log'
        
        # command to check MySQL error logs
        # finds error log file
        findmycnf = shell.run(["sh", "-c", r'grep log-error= /etc/my.cnf' ],
                        allow_error=True)
        findmycnf = findmycnf.output.decode()
        findmycnf = findmycnf[10:]

        com_mysqlerror = shell.run(["sh", "-c", f'grep {sshmysqltime} {findmycnf}'],
                        allow_error=True)
        str_mysqlerror = f'grep {sshmysqltime} {findmycnf}'
        
        # sar memory stats
        com_sarmem = shell.run(["sh", "-c", f'sar -r -f /var/log/sa/sa{sshsarday}'],
                                    allow_error=True)
        str_sarmem = f'sar -r -f /var/log/sa/sa{sshsarday}'
        
        # sar cpu stats
        com_sarcpu = shell.run(["sh", "-c", f'sar -u -f /var/log/sa/sa{sshsarday}'],
                                    allow_error=True)
        str_sarcpu = f'sar -u -f /var/log/sa/sa{sshsarday}'
        
        # sar load average stats
        com_sarload = shell.run(["sh", "-c", f'sar -u -f /var/log/sa/sa{sshsarday}'],
                                    allow_error=True)
        str_sarload = f'sar -u -f /var/log/sa/sa{sshsarday}'
        
        # sar io stats
        com_sario = shell.run(["sh", "-c", f'sar -b -f /var/log/sa/sa{sshsarday}'],
                                    allow_error=True)
        str_sario = f'sar -b -f /var/log/sa/sa{sshsarday}'


        #### END prepares ssh commands to run
        
        return render_template('timecheck_results.html',
                                com_accesslog=com_accesslog, str_accesslog=str_accesslog,
                                com_apacheerror=com_apacheerror, str_apacheerror=str_apacheerror,
                                com_mysqlerror=com_mysqlerror, str_mysqlerror=str_mysqlerror,
                                com_sarmem=com_sarmem, str_sarmem=str_sarmem,
                                com_sarcpu=com_sarcpu, str_sarcpu=str_sarcpu,
                                com_sarload=com_sarload, str_sarload=str_sarload,
                                com_sario=com_sario, str_sario=str_sario,
                                sshhost=sshhost, sshsite=sshsite)
        
    return render_template('timecheck.html',
        title='Find what happend around a certain time')


# code for the tool that runs custom commands
@app.route('/customcommand_results')        
@app.route('/customcommand', methods=['GET', 'POST'])
def customcommand():
    # triggered when the submit button is pressed
    if request.method == 'POST':
    
        # prepares ssh login
        sshhost = request.form.get('sshhost')
        sshuser = request.form['sshuser']
        sshpass = request.form['sshpass']
        sshport = request.form['sshport']
        shell = spur.SshShell(hostname=sshhost, 
                        username=sshuser, 
                        password=sshpass,
                        port = sshport,
                        missing_host_key=spur.ssh.MissingHostKey.accept)
        
        # options in ssh command
        sshcustom = request.form['sshcustom']
        
        #### START prepares ssh commands to run                        

        com_custom = shell.run(["sh", "-c", f"{sshcustom}"])
        str_custom = f"{sshcustom}"

        #### END prepares ssh commands to run

        # logs in to host, runs commands, outputs results to new window     
        if re.match("rm", sshcustom):
            return "command not allowed"
        else:
            return render_template('customcommand_results.html',
                                    com_custom=com_custom, str_custom=str_custom,
                                    sshhost=sshhost)
                        
    return render_template('customcommand.html',
        title='Custom Command')