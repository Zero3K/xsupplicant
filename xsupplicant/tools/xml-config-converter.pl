#!/usr/bin/env perl

use strict;
use Getopt::Long;

my $debug = 1;

my $configFile = "../etc/xsupplicant.conf";

my @oldConfigLines = ();

my @configAreas = ("Globals");
my $configArea = "Globals";
my $lastConfigArea = "Globals";
my $indentLevel = "\t";

my $expectNewArea = 0;

my $xmlConfig = ();
my @xmlConfigList = ();
my @globalsList = ();

my %xmlConfigHints = (
		      "scan_timeout", "Scan_Timeout",
		      "ipc_group", "IPC_Group",
		      "roaming", "Roaming",
		      "passive_scanning", "Passive_Scanning",
		      "passive_timer", "Passive_Timer",
		      "use_eap_hints", "Use_EAP_Hints",
		      "logfile", "Logfile",
		      "log_facility", "Log_Facility",
		      "association", "Association",
		      "association_timeout", "Association_Timeout",
		      "auth_period", "Auth_Period",
		      "held_period", "Held_Period",
		      "max_starts", "Max_Starts",
		      "priority", "Priority",
		      "wpa_group_cipher", "WPA_Group_Cipher",
		      "wpa_pairwise_cipher", "WPA_Pairwise_Cipher",
		      "dest_mac", "Dest_MAC",
		      "key", "Key",
		      "hex-key", "Hex_Key",
		      "identity", "Identity",
		      "allow_provision", "Allow_Provision",
		      "pacfile", "PAC_File",
		      "chunk_size", "Chunk_Size",
		      "password", "Password",
		      "username", "Username",
		      "initial_wep", "Initial_WEP",
		      "initial-wep", "Initial_WEP",
		      "static_wep", "Static_WEP",
		      "static-wep", "Static_WEP",
		      "key1", "Key1",
		      "key2", "Key2",
		      "key3", "Key3",
		      "key4", "Key4",
		      "tx_key", "TX_Key",
		      "user_cert", "User_Certificate",
		      "user_key", "User_Key_File",
		      "user_key_pass", "User_Key_Password",
		      "root_cert", "Root_Certificate",
		      "root_dir", "Root_Certificate_Directory",
		      "crl_dir", "CRL_Directory",
		      "user_key", "User_Key_File",
		      "session_resume", "Session_Resume",
		      "random_file", "Random_File",
		      "engine_id", "Engine_ID",
		      "opensc_so_path", "OpenSC_Lib_Path",
		      "key_id", "Key_ID",
		      "auto_realm", "Auto_Realm",
		      
		      # Deprecated keywords:
		      "network_list", "",
		      
		      # Phase 2 types:
		      "wpa_psk", "wpa-psk",
		      "eap_tls", "eap-tls",
		      "eap_fast", "eap-fast",
		      "eap_md5", "eap-md5",
		      "eap_ttls", "eap-ttls",
		      "eap_leap", "eap-leap",
		      "eap_mschapv2", "eap-mschapv2",
		      "eap_gtc", "eap-gtc",
		      "eap_otp", "eap-otp",
		      "eap_sim", "eap-sim",
		      "eap_aka", "eap-aka",
		      "eap_tnc", "eap-tnc",
		      "ias_quirk", "IAS_Quirk",
		      );

GetOptions("c|config-file=s" => \$configFile);

$configFile = "/etc/xsupplicant.conf" unless $configFile;

print '<?xml version="1.0"?>'."\n";
print "<XsupplicantConfig>\n";

open(CONFIG, "< $configFile");

while(<CONFIG>)
{
    my $line = $_;

    # If it's a blank line, skip it.
    next if $line =~ /^\s*$/;

    convert_line_to_xml($line);
}

close(CONFIG);

print "<Globals>\n";

foreach my $global (@globalsList)
{
    print $global;
}

print "</Globals>\n";

print "</XsupplicantConfig>\n";

sub convert_line_to_xml
{
    my ($line) = @_;
    
    chomp $line;
    
    if($line =~ /^\s*#/)
       {	   
	   $line =~ s/#(.*)/<!-- $1 -->/;

	   if($configArea eq "Globals")
	   {
	       push(@globalsList, $line."\n");
	   }
	   else
	   {
	       print $line."\n";
	   }
	   
	   return 0;
       }
       
       if($line =~ /\}/)
       {
	   # Flush current block and pop 
	   $indentLevel = "\t";
	   
	   print "${indentLevel}</$configArea>\n";

	   chop $indentLevel;
	   chop $indentLevel;

	   if($#configAreas > -1)
	   {      
	       $configArea = pop(@configAreas);
	   }
	   else
	   {
	       print "Error: \@configAreas has no values!\n";
	       $configArea = "Globals";
	   }	  
       
	   return 0;
       }
	
       if($line =~ /^\s*\{\s*$/)
       {
	   return 0;
       }
       elsif($line =~/^\s*(\S*)\s*\{/)
       {
	   push(@configAreas, $configArea);
	   $configArea = $1;

	   $indentLevel .= "\t";

	   print "${indentLevel}<$configArea>\n";

	   return 0;
       }
       
       if($line =~ /^\s*(\S*)\s*=/)
       {
	   my $key = $1;
	   my $value = "";

	   if($line =~ /=\s*"(.*)"/)
	   {
	       $value = $1;
	   }
	   elsif($line =~ /=\s*(\S*)\s*\#?.*$/)
	   {
	       $value = $1;
	   }
	   else
	   {
	       print "Couldn't apply value!: '$line'\n";
	   }

	   if(exists $xmlConfigHints{$key})
	   {
	       if($xmlConfigHints{$key} ne "")
	       {
		   $indentLevel  .= "\t";

		   my $tag = "${indentLevel}<$xmlConfigHints{$key}>$value</$xmlConfigHints{$key}>\n";

		   if($configArea eq "Globals")
		   {
		       push(@globalsList, $tag);
		   }
		   else
		   {
		       print $tag;
		   }
		   
		   chop $indentLevel;
		   chop $indentLevel;
	       }
	       else
	       {
		   #print "$key is a deprecated keyword... skipping.\n";
	       }
	       	       
	       return 0;
	   }
	   else
	   {
	       return 0;
	   }
       }
       else
       {
	   #print "$line: No match for key/value\n";
       }
       
       if($line =~ /\s*(\S*)\s*/)
       {
	   push(@configAreas, $configArea);
	   $configArea = $1;

	   $indentLevel .= "\t";

	   print "${indentLevel}<$configArea>\n";
	   
	   return 0;
       }
       else
       {
	   print "No match for new area: '$line'\n";
       }
   }
    
