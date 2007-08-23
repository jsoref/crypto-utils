#!%INSTDIR%/bin/perl
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# 02110-1301, US
#
# Generate a keypair.  Get a keysize from the user, generate
# some useful random data, generate a key, produce a CSR if
# required and add a passphrase if required.
#
# genkey.pl -- based on genkey and genkey.aux from Stronghold
#
# Mark J Cox, mjc@redhat.com and Joe Orton, jorton@redhat.com
#
# 200103 Initial version
# 200106 Converted to Newt
# 200106 Added gencert/genreq functionality
# 200106 Added some state
# 200111 Added makeca functionality
# 200305 Hide passwords entered for private key
# 200308 Adapted for Taroon
# 200308 Fix warnings in UTF-8 locale
# 200409 Added --days support
#
#
$bindir = "%INSTDIR%/bin";
$ssltop = "%INSTDIR%/conf/ssl";
$sslconf = "%INSTDIR%/conf/ssl/openssl.conf";
$cadir = "$ssltop/CA";

use Crypt::Makerand;
use Newt;
use Getopt::Long;

sub InitRoot
{
    my $help = shift;

    Newt::Cls();
    Newt::DrawRootText(0, 0, 
		       "Red Hat Keypair Generation (c) 2005 Red Hat, Inc.");

    if ($help == 1) {
	Newt::PushHelpLine("  <Tab>/<Alt-Tab> between elements  |" .
			   "  <Space> selects  |" .
			   "  <Escape> to quit");
    }
}

sub FinishRoot
{
    Newt::PopHelpLine();
    Newt::Cls();
}

sub usage 
{
    print STDERR <<EOH;
Usage: genkey [options] servername
    --test   Test mode, skip random data creation, overwrite existing key
    --genreq Just generate a CSR from an existing key
    --makeca Generate a private CA key instead
    --days   Days until expiry of self-signed certificate (default 30)
EOH
    exit 1;
}

# Run a form with support for pressing escape and enter.
sub RunForm
{
    my ($panel, $onenter, $onescape) = @_;
    
    # set defaults
    $onenter = "Next" if (!defined($onenter));
    $onescape = "Cancel" if (!defined($onescape));    

    $panel->AddHotKey(Newt::NEWT_KEY_ESCAPE());
    $panel->AddHotKey(Newt::NEWT_KEY_ENTER()) unless $onenter eq "Ignore";

    ($reason, $data) = $panel->Run();

    if ($reason eq Newt::NEWT_EXIT_HOTKEY) {
	if ($data == Newt::NEWT_KEY_ESCAPE()) {
	    # They pressed ESCAPE; pretend they pressed "Cancel" or "No"
	    return $onescape;
	}
	elsif ($data == Newt::NEWT_KEY_ENTER()) {
	    my $current = $panel->GetCurrent();
	    if ($panel->{refs}{$$current}->Tag()) {
		# They pressed ENTER over a button; pretend they pressed it.
		return $panel->{refs}{$$current}->Tag();
	    }
	    return $onenter;
	}
    }
    elsif ($reason eq Newt::NEWT_EXIT_COMPONENT) {
	return $data->Tag();
    }
    die "unhandled event ", $reason, " ", $data, "\n";
}

#
# main
#

my $test_mode = '';
my $genreq_mode = '';
my $ca_mode = '';
my $cert_days = 30;
GetOptions('test|t' => \$test_mode, 
	   'genreq' => \$genreq_mode,
           'days=i' => \$cert_days,
	   'makeca' => \$ca_mode) or usage();
usage() unless @ARGV != 0;
$skip_random = $test_mode;
$overwrite_key = $test_mode;
$servername = $ARGV[0];
$randfile = $ssltop."/.rand.".$$;
$keyfile = $ssltop."/private/".$servername.".key";
if ($ca_mode) {
    $keyfile = $cadir."/private/".$servername;
}

### State variables
my $bits = 0;
my $myca = "";
my $useca = 0;
my $cadetails;
#

Newt::Init();
InitRoot(1);

local $SIG{__DIE__} = sub { @err=@_; Newt::Finished(); die @err;};

#
# Does the key already exist? don't overwrite
#

if (!$genreq_mode && -f $keyfile && !$overwrite_key) {
    Newt::newtWinMessage("Error", "Close", 
		"You already have a key file for this host in file:\n\n" .
		$keyfile . "\n\n" .
		"This script will not overwrite an existing key.\n" . 
		"You will need to remove or rename this file in order to" .
		"generate a new key for this host, then run\n" .
		"\"genkey $servername\"");
    Newt::Finished();
    exit 1;
}

if ($genreq_mode && !(-f $keyfile)) {
    Newt::newtWinMessage("Error", "Close", 
                         "You do not have a key file for this host");
    Newt::Finished();
    exit 1;
}

######################################################################
# Main
#

# Array of windows which we cycle through. Each window function should
# return: 
#   "Next" or "Skip" -> go on to the next window
#   "Back" -> go back to the last window which returned "Next"
#   "Cancel" -> cancelled: quit and return failure.
#
# "Skip" is to allow for windows which don't display anything (due
# to choices made in previous windows, for instance).
#
my @windows;
if ($genreq_mode) {
    $useca = 1;
    @windows = (whichCAWindow,
		genReqWindow,
		);
    $doingwhat="CSR generation";
} elsif ($ca_mode) {
    @windows = (CAwelcomeWindow,
		getkeysizeWindow,
		customKeySizeWindow,
		getRandomDataWindow, ## leaves newt suspended
		generateKey,
		genCACertWindow,
		encryptKeyWindow,
		);
    $doingwhat="CA key generation";
} else {
    @windows = (welcomeWindow,
		getkeysizeWindow,
		customKeySizeWindow,
		getRandomDataWindow, ## leaves newt suspended
		generateKey,
		wantCAWindow,
		whichCAWindow,
		genReqWindow,
		genCertWindow,
		encryptKeyWindow,
		### @EXTRA@ ### Leave this comment here.
		);
    $doingwhat="key generation";
}

my $screen = 0;

my @screenstack;

my $result;

while ($screen <= $#windows) {
    $result = $windows[$screen]->();
    print STDERR "undef from window #" .$screen . "\n" if (!$result);
    if ($result eq "Cancel") {
	my $panel = Newt::Panel(1, 2, "Confirm");

	$panel->Add(0, 0, 
		  Newt::TextboxReflowed(60, 10, 10, 0, 
					"Do you want to cancel ".$doingwhat.
					"?"));

	$panel->Add(0, 1, DoubleButton("Yes", "No"));
	# Default to NOT cancel if escape is pressed (again)
	$ret = &RunForm($panel, "No", "No");

	$panel->Hide();
	undef $panel;

	last if $ret eq "Yes";
	next;
    }

    $nextscreen = $screen + 1 if ($result eq "Next" or $result eq "Skip"
				  or !$result);
    $nextscreen = pop @screenstack if ($result eq "Back" and scalar(@screenstack));
    push @screenstack, $screen if ($result eq "Next");
    $screen = $nextscreen;
}

# Exit
Newt::Finished();
exit 1 if ($result eq "Cancel");
exit 0;

######################################################################
# Handy functions

# Returns a panel containing two buttons of given names.
sub DoubleButton {
    my ($left, $right) = @_;
    
    my $leftb = Newt::Button($left)->Tag($left);
    my $rightb = Newt::Button($right)->Tag($right);

    Newt::Panel(2, 1)
      ->Add(0, 0, $leftb, Newt::NEWT_ANCHOR_RIGHT(), 0, 1, 0, 0)
	  ->Add(1, 0, $rightb, Newt::NEWT_ANCHOR_LEFT(), 1, 1, 0, 0);
}

# Returns a panel containing next/back/cancel buttons.
sub NextBackCancelButton {
    
    my $nextb = Newt::Button('Next')->Tag('Next');
    my $backb = Newt::Button('Back')->Tag('Back');
    my $cancelb = Newt::Button('Cancel')->Tag('Cancel');

    Newt::Panel(3, 1)
      ->Add(0, 0, $nextb, Newt::NEWT_ANCHOR_RIGHT(), 0, 1, 0, 0)
	  ->Add(1, 0, $backb, Newt::NEWT_ANCHOR_RIGHT(), 1, 1, 0, 0)
	      ->Add(2, 0, $cancelb, Newt::NEWT_ANCHOR_LEFT(), 1, 1, 0, 0);
}

######################################################################
# The window functions

sub makerand
{
    require Fcntl;

    my ($bits,$filename) = @_;

    my $count = 0;
    
    my @credits = ("This software contains the truerand library",
		   "developed by Matt Blaze, Jim Reeds, and Jack",
		   "Lacy. Copyright (c) 1992, 1994 AT&T.");
    my ($cols, $rows) = Newt::GetScreenSize();
    
    foreach (@credits) {
	$count++;
	Newt::DrawRootText($cols-45, $rows-5 + $count, $_);
    }

    $count = 0;
    
    my $panel = Newt::Panel(1, 2, "Generating random bits");
    my $scale = Newt::Scale(40, $bits);

    $panel->Add(0, 0, Newt::Label("(this may take some time)"));

    $panel->Add(0, 1, $scale, 0, 0, 1);
		
    $panel->Draw();
    
    if (!sysopen($randfh,$filename,Fcntl::O_WRONLY()|Fcntl::O_CREAT()
		 |Fcntl::O_TRUNC()|Fcntl::O_EXCL(),0600)) {
	Newt::newtWinMessage("Error", "Close", 
			     "Can't create random data file");
	$panel->Hide();
	undef $panel;
	return "Cancel";
    }

    Newt::Refresh();
    while ($count++ < $bits/32) { 
        use bytes; # random data is not UTF-8, prevent warnings
	# decode as an "native-length" unsigned long
	syswrite($randfh,pack("L!",Crypt::Makerand::trand32()));
	$scale->Set($count*32);
	Newt::Refresh();
    }
    $panel->Hide();
    undef $panel;
    close $randfh;
}

sub getkeysizeWindow()
{
    $minbits = 512;
    $maxbits = 8192;

    my $title= <<EOT;
Choose the size of your key. The smaller the key you choose the faster
your server response will be, but you'll have less security. Keys of
less than 1024 bits are easily cracked.  Keys greater than 1024 bits
don't work with all currently available browsers. 

We suggest you select the default, 1024 bits
EOT
    my $panel = Newt::Panel(1, 3, "Choose key size");
    my $listbox = Newt::Listbox(5, 0);
    my $text = Newt::Textbox(70, 6, 0, $title);
    my @listitems = ("512 (insecure)",
		     "1024 (medium-grade, fast speed) [RECOMMENDED]",
		     "2048 (high-security, medium speed)",
		     "4096 (paranoid-security, tortoise speed)",
		     "Choose your own");

    $listbox->Append(@listitems);
    
    $panel->Add(0, 0, $text);
    $panel->Add(0, 1, $listbox, 0, 0, 1);
    $panel->Add(0, 2, NextBackCancelButton());
    
    Newt::newtListboxSetCurrent($listbox->{co}, 1);

    $panel->Draw();

    $ret = &RunForm($panel);    

    if ($ret eq "Cancel" or $ret eq "Back") {
	$panel->Hide();
	undef $panel;
	return $ret;
    }
    
    $bits = 256;

    foreach $item(@listitems) {
	$bits = $bits * 2;
	if ($item eq $listbox->Get()) {
	    last;
	}
    }

    $panel->Hide();
    undef $panel;
    return $ret;
}

sub customKeySizeWindow()
{
    return "Next" if $bits < 8192; # else, choose custom size.

    Newt::Refresh();
    
    $bits = 0;

    $title = <<EOT;
Select the exact key size you want to use. Note that some browsers do
not work correctly with arbitrary key sizes. For maximum compatibility
you should use 512 or 1024, and for a reasonable level of security you
should use 1024.
EOT

    $panel = Newt::Panel(1, 3, "Select exact key size");
    my $entry = Newt::Entry(10, 0, "");

    $panel->Add(0, 0, Newt::Textbox(70, 4, 0, $title));
    $panel->Add(0, 1, $entry);
    $panel->Add(0, 2, NextBackCancelButton());
    
    do {
	$panel->Focus($entry);

	$ret = &RunForm($panel);

	if ($ret eq "Cancel" or $ret eq "Back") {
	    $panel->Hide();
	    undef $panel;
	    return $ret;
	}

	if ($entry->Get() ne "") {
	    $bits = int($entry->Get());
	} else {
	    $bits = 0;
	}
    } while ($bits < $minbits || $bits > $maxbits);
    
    $panel->Hide();
    undef $panel;

    return "Next";
}

sub welcomeWindow()
{
    my $name = $servername;
    my $message = <<EOT;
You are now generating a new keypair which will be used to encrypt all
SSL traffic to the server named $name. 
Optionally you can also create a certificate request and send it to a
certificate authority (CA) for signing.

The key will be stored in 
    $ssltop/private/$name.key
The certificate stored in 
    $ssltop/certs/$name.cert

If the key generation fails, move the file 
    $ssltop/private/$name.key 
to a backup location and try again.
EOT

    my $panel = Newt::Panel(1, 2, "Keypair generation");
    my $text = Newt::Textbox(70, 10, Newt::NEWT_TEXTBOX_SCROLL(), $message);
    my $ret;

    $panel->Add(0, 0, $text);
    $panel->Add(0, 1, DoubleButton("Next","Cancel"));

    $ret = &RunForm($panel);

    $panel->Hide();
    undef $panel;

    return $ret;
}

sub CAwelcomeWindow()
{
    my $name = $servername;
    my $message = <<EOT;
You are now generating a new keypair which will be used for your
private CA

The key will be stored in 
    $cadir/private/$name

If the key generation fails, move the file 
    $cadir/private/$name
to a backup location and try again.
EOT

    my $panel = Newt::Panel(1, 2, "CA Key generation");
    my $text = Newt::Textbox(70, 10, Newt::NEWT_TEXTBOX_SCROLL(), $message);
    my $ret;

    $panel->Add(0, 0, $text);
    $panel->Add(0, 1, DoubleButton("Next","Cancel"));

    $ret = &RunForm($panel);

    $panel->Hide();
    undef $panel;

    return $ret;
}

sub wantCAWindow
{
    my $panel = Newt::Panel(1, 2, "Generate CSR");

    $panel->Add(0, 0, 
	      Newt::TextboxReflowed(60, 10, 10, 0, 
				    "Would you like to send a Certificate Request (CSR) " .
				    "to a Certificate Authority (CA)?"));

    $panel->Add(0, 1, DoubleButton("Yes", "No"));

    $ret = &RunForm($panel);

    $panel->Hide();
    undef $panel;

    if ($ret eq "Cancel") {
	return "Cancel";
    }

    $useca = ($ret eq "Yes") ? 1 : 0;

    return "Next";
}

sub encryptKeyWindow
{
    my $message = <<EOT;
At this stage you can set the passphrase on your private key. If you
set the passphrase you will have to enter it every time the server
starts.  The passphrase you use to encrypt your key must be the same
for all the keys used by the same server installation.

If you do not encrypt your passphrase, if someone breaks into your
server and grabs the file containing your key, they will be able to
decrypt all communications to and from the server that were negotiated
using that key. If your passphrase is encrypted it would be much more
work for someone to retrieve the private key.
EOT
    $panel = Newt::Panel(1, 3, "Protecting your private key");

    $panel->Add(0, 0, Newt::Textbox(70, 11, 0, $message));

    my $checkbox = Newt::Checkbox("Encrypt the private key");
    $panel->Add(0, 1, $checkbox);

    $panel->Add(0, 2, NextBackCancelButton());

    $ret = &RunForm($panel);

    my $plain = 1;
    $plain = 0 if $checkbox->Checked();

    $panel->Hide();
    undef $panel;

    return $ret if ($ret eq "Back" or $ret eq "Cancel" or $plain == 1);
 
    $panel = Newt::Panel(1, 3, "Set private key passphrase");

    $message = <<EOT;
Now we are going to set the passphrase on the private key. This
passphrase is used to encrypt your private key when it is stored
on disk. You will have to type this passphrase when the server
starts. If you do not want to store the key encrypted on disk
read about the "decrypt_key" command in the documentation.

-- DO NOT LOSE THIS PASS PHRASE --

If you lose the pass phrase you will not be able to run the server
with this private key. You will need to generate a new private/public
key pair and request a new certificate from your certificate authority.
EOT
    $panel->Add(0, 0, Newt::Textbox(70, 11, 0, $message));
    $subp = Newt::Panel(2,2);
    $entp1 = AddField($subp,0,"Passphrase (>4 characters)","",30,0,
                      Newt::NEWT_FLAG_HIDDEN());
    $entp2 = AddField($subp,1,"Passphrase (again)        ","",30,0,
                      Newt::NEWT_FLAG_HIDDEN());

    $panel->Add(0, 1, $subp, 0, 0, 1);
    $panel->Add(0, 2, NextBackCancelButton());

    while (1) {
        # Clear the password entry boxes to avoid confusion on looping
        $entp1->Set("");
        $entp2->Set("");

	$panel->Focus($entp1);

	# Pass "Ignore" to make enter go to next widget.
	$ret = &RunForm($panel, "Ignore");

	if ($ret eq "Cancel" or $ret eq "Back") {
	    $panel->Hide();
	    undef $subp;
	    undef $panel;
	    return $ret;
	}
	$pass1 = $entp1->Get();
	$pass2 = $entp2->Get();

	if ($pass1 ne $pass2) {
	    Newt::newtWinMessage("Error", "Close",
                                 "The passphrases you entered do not match.");
	    next;
	}
	if (length($pass1)<4) {
	    Newt::newtWinMessage("Error", "Close",
			       "The passphrase must be at least 4 characters".
			       "\n\nPress return to try again");
	    next;
	}
	last;
    }

    $panel->Hide();
    undef $panel;

    return $ret if ($ret eq "Back" or $ret eq "Cancel");

    my $enckey = $keyfile . ".tmp";

    unlink($enckey);

    if (!open (PIPE,
               "|$bindir/openssl rsa -des3 -in $keyfile -passout stdin ".
               "-out $enckey")) {
        Newt::newtWinMessage("Error", "Close",
                             "Unable to set passphrase".
			    "\n\nPress return to continue");
	return "Back";
    }
    print PIPE $pass1."\n";
    close(PIPE);

    if (-f $enckey) {
	if (chmod(0400, $enckey) != 1
            || !rename($enckey, $keyfile)) {
            Newt::newtWinMessage("Error", "Close", 
                                 "Could not install private key file.\n".
                                 "$! - $enckey");
            unlink($enckey);
            return "Back";
        }
    } else {
        Newt:newtWinMessage("Error", "Close",
                            "Unable to set passphrase\n\n".
			    "Press return to continue");
	return "Back";
    }
    return "Next";
}

sub genReqblah()
{
    my ($name) = @_;
    my $message = <<EOT;
Now we will create a self-signed certificate for use until the CA of your
choice signs your certificate. You will have to use this cert until
your CA responds with the actual signed certificate.
EOT

    my $panel = Newt::Panel(1, 2, "Keypair generation");
    my $text = Newt::Textbox(70, 10, 0, $message);
    my $ret;

    $text->TakesFocus(1);

    $panel->Add(0, 0, $text);
    $panel->Add(0, 1, NextBackCancelButton());

    $ret = &RunForm($panel);

    $panel->Hide();
    undef $panel;

    return $ret;
}

#
# makeCert
#
# Given a keyfile, expiry date, and set of certificate information
# create a X509 certificate to make a key and store it
#

sub makeCert
{
    my ($keyfile,$certfile,$cert,$days) = @_;
    use Fcntl;

    $tempfile = "/tmp/rand.".$$;
    if (!sysopen(OUT, $tempfile, O_WRONLY|O_EXCL|O_CREAT)) {
        Newt::newtWinMessage("Fatal Error", "Close", "Could not write to ".
			     "temporary file $tempfile");
	Newt::Finished();
        exit 1;
    }

    foreach my $field ('C', 'ST', 'L', 'O', 'OU', 'CN', 
		       'Challenge', 'CompanyName') {
	my $value = $cert{$field} || '.';
	print OUT "$value\n";
    }
    close(OUT);

    system("$bindir/openssl req -config $sslconf -new -key $keyfile $days -out $certfile < $tempfile 2> /dev/null");
    unlink($tempfile);

    if (!-f $certfile) {
        Newt::newtWinMessage("Error", "Close", 
			     "Was not able to create a certificate for this ".
			     "host:\n\nPress return to exit");
	Newt::Finished();
	exit 1;
    }
}


sub AddField
{
    my ($panel, $row, $msg, $default, $width, $topspace, $flags) = (@_, 0, 0);
    my $entry;

    $panel->Add(0, $row, Newt::Label($msg), Newt::NEWT_ANCHOR_RIGHT(), 0, $topspace);
    $entry = Newt::Entry($width, $flags, $default);
    $panel->Add(1, $row, $entry, Newt::NEWT_ANCHOR_LEFT(), 1, $topspace);

    $entry;
}

sub getCertDetails
{
    my ($fqdn, $msg, $iscsr) = (@_, 0);
    my $cert;
    my $panel;
    my $subp;

    my $ents = {}, $cert = {};

    $panel = Newt::Panel(1, 3, "Enter details for your certificate");

    $panel->Add(0, 0, Newt::TextboxReflowed(65, 10, 10, 0, $msg));
    
    if ($iscsr) {
	$subp = Newt::Panel(2, 9);
    } else {
	$subp = Newt::Panel(2, 6);
    }

    $ents{'C'} = AddField($subp, 0, "Country Name (ISO 2 letter code)", "GB", 3);
    $ents{'ST'} = AddField($subp, 1, 
			   "State or Province Name (full name)", "Berkshire", 20, 0,
			  Newt::NEWT_ENTRY_SCROLL());
    $ents{'L'} = AddField($subp, 2, "Locality Name (e.g. city)", "Newbury", 20, 0, 
			  Newt::NEWT_ENTRY_SCROLL());
    $ents{'O'} = AddField($subp, 3, 
			  "Organization Name (eg, company)", "My Company Ltd", 30, 0,
			  Newt::NEWT_ENTRY_SCROLL());
    $ents{'OU'} = AddField($subp, 4, "Organizational Unit Name (eg, section)", "", 30, 0,
			   Newt::NEWT_ENTRY_SCROLL());
    $ents{'CN'} = AddField($subp, 5, 
			   "Common Name (fully qualified domain name)", $fqdn, 30, 1, 
			   Newt::NEWT_ENTRY_SCROLL());

    if ($iscsr) {
#      TODO: difficult to fit this message in and keep the form <25 rows
#	$subp->Add(0, 6, Newt::Label("Please enter the following 'extra' ".
#				     "attributes\nto be sent with your ".
#				     "certificate request."));

	my $msg = "Extra attributes for certificate request:";

	$subp->Add(0, 6, Newt::Textbox(length($msg), 1, 0, $msg),
		   Newt::NEWT_ANCHOR_RIGHT());

	$ents{'Challenge'} = AddField($subp, 7, "Optional challenge password",
				      "", 20, 0);
	$ents{'CompanyName'} = AddField($subp, 8, "Optional company name", "", 30, 0,
			  Newt::NEWT_ENTRY_SCROLL());
    }

    $panel->Add(0, 1, $subp, 0, 0, 1);

    $panel->Add(0, 2, NextBackCancelButton(), 0, 0, 0, 0, -1);

    while (1) {
	
	# Pass "Ignore" to make enter go to next widget.
	$ret = &RunForm($panel, "Ignore");

	if ($ret eq "Next" && $iscsr) {
	    my $pass = $ents{'Challenge'}->Get();
	    if (length($pass) > 0 && length($pass) < 4) {
		Newt::newtWinMessage("Error", "Retry",
				     "The challenge password must be at least four characters in length");
		# Move focus to challenge password field
		$panel->Focus($ents{'Challenge'});
		# and go again.
		next;
	    }
	}
	last;
    }

    if ($ret eq "Cancel" or $ret eq "Back") {
	$panel->Hide();
	undef $subp;
	undef $panel;
	return $ret;
    }

    $cert{'C'} = $ents{'C'}->Get();
    $cert{'ST'} = $ents{'ST'}->Get();
    $cert{'L'} = $ents{'L'}->Get();
    $cert{'O'} = $ents{'O'}->Get();
    $cert{'OU'} = $ents{'OU'}->Get();
    $cert{'CN'} = $ents{'CN'}->Get();
    
    if ($iscsr) {
	$cert{'CompanyName'} = $ents{'CompanyName'}->Get();
	$cert{'Challenge'} = $ents{'Challenge'}->Get();
    }

    $panel->Hide();

    undef $subp;
    undef $panel;

    $cadetails = $cert;
	
    return "Next";
}

sub whichCAWindow {
    return "Skip" unless $useca;

    my $title = <<EOT;
Please choose the Certificate Authority you wish to send
your certificate request to
EOT
    my $panel = Newt::Panel(1, 3, "Choose Certificate Authority");
    my $listbox = Newt::Listbox(4, 0);
    my $text = Newt::Textbox(60, 2, 0, $title);
    my @listitems = ("Equifax","Thawte","VeriSign","Other");
    undef $myca;

    $listbox->Append(@listitems);
    
    $panel->Add(0, 0, $text);
    $panel->Add(0, 1, $listbox, 0, 0, 1);
    if ($genreq_mode) {
	$panel->Add(0, 2, DoubleButton("Next","Cancel"));
    } else {
	$panel->Add(0, 2, NextBackCancelButton());
    }

    Newt::newtListboxSetCurrent($listbox->{co}, 0);

    $panel->Draw();
    $ret = &RunForm($panel);

    $myca = $listbox->Get();

    $panel->Hide();
    undef $panel;
    Newt::Refresh();
    return $ret;
}

sub genReqWindow
{
    return "Skip" unless $useca;

    $keyfile = $ssltop."/private/".$servername.".key";
    $certfile = $ssltop."/certs/".$servername.".cert";
    
    $num = 0;
    while (-f $ssltop."/certs/".$servername.".$num.csr") {
	$num++;
    }
    $csrfile = $ssltop."/certs/".$servername.".$num.csr";
    
    my $msg = "You are about to be asked to enter information that will be ".
	"incorporated into your certificate request to $myca. What you are about to ".
	 "enter is what is called a Distinguished Name or a DN.  There are ".
	 "quite a few fields but you can leave some blank.";

    my $ret = getCertDetails($servername,$msg, 1);
    return $ret unless ($ret eq "Next");

    makeCert($keyfile,$csrfile,$cadetails,"");
    
# Now make a temporary cert

    if (!$genreq_mode) {
	if (!-f $certfile) {
	    makeCert($keyfile,$certfile,$cadetails,"-days $cert_days -x509");
	}
    }
    
    undef $csrtext;
    open(CSR,"<$csrfile");
    while(<CSR>) {
	$csrtext .= $_;
    }
    close(CSR);

    Newt::Suspend();
    
    # Clear the screen
    system("clear");

    if ($myca eq "VeriSign") {
	
	print <<EOT;
You now need to connect to the VeriSign site and submit your CSR. The
page at https://digitalid.verisign.com/server/help/hlpEnrollServer.htm
explains how to do this, and what additional documention will be
required before VeriSign can sign your certificate.

Your CSR is given below. To submit it to VeriSign, go through the
enrollment process starting at
https://digitalid.verisign.com/server/enrollIntro.htm. Paste the CSR,
including the BEGIN and END lines, when prompted in step 4.

$csrtext
EOT
}

    if ($myca eq "Thawte") {
	print <<EOT;
You now need to connect to the Thawte site and submit your CSR. The
page at https://www.thawte.com/certs/server/request.html explains how
to do this, and what additional documention will be required before
Thawte can sign your certificate.

Your CSR is given below. To submit it to Thawte, go to
https://www.thawte.com/cgi/server/step1.exe and select "Web Server
Certificate". Paste the CSR, including the BEGIN and END lines, when
prompted.

$csrtext
EOT
}

    if ($myca eq "Equifax") {
	print <<EOT;
You now need to connect to the Equifax site and submit your CSR. The
page at http://www.equifaxsecure.com/ebusinessid/c2net/ explains how
to do this, and what additional documention will be required before
Equifax can sign your certificate.

Your CSR is given below. To submit it to Equifax, go to
http://www.equifaxsecure.com/ebusinessid/c2net/
Paste the CSR, including the BEGIN and END lines, when prompted.

$csrtext
EOT
}

    if ($myca eq "Other") {
	print <<EOT;
You now need to submit your CSR and documentation to your certificate
authority. Submitting your CSR may involve pasting it into an online
web form, or mailing it to a specific address. In either case, you
should include the BEGIN and END lines.

$csrtext
EOT
}

    print <<EOT;
    
A copy of this CSR has been saved in the file
$csrfile

Press return when ready to continue
EOT
    $_=<STDIN>;
    Newt::Resume();
    return "Next";
}


sub genCertWindow
{
    return "Skip" if $useca;

    $keyfile = $ssltop."/private/".$servername.".key";
    $certfile = $ssltop."/certs/".$servername.".cert";
    
    my $msg = "You are about to be asked to enter information that will be ".
	"made into a self-signed certificate for your server. What you are ".
	"about to ".
	"enter is what is called a Distinguished Name or a DN.  There are ".
	"quite a few fields but you can leave some blank";

    my $ret = getCertDetails($servername,$msg, 0);
    return $ret unless ($ret eq "Next");

    makeCert($keyfile,$certfile,$cadetails,"-days $cert_days -x509");

    return "Next";
}

sub genCACertWindow
{
    return "Skip" if $useca;

    $keyfile = $cadir."/private/".$servername;
    $certfile = $cadir."/".$servername;
    
    my $msg = "You are about to be asked to enter information that will be ".
	"made into a certificate for your CA key. What you are ".
	"about to ".
	"enter is what is called a Distinguished Name or a DN.  There are ".
	"quite a few fields but you can leave some blank";

    my $ret = getCertDetails("",$msg, 0);
    return $ret unless ($ret eq "Next");

    makeCert($keyfile,$certfile,$cadetails,"-days 730 -x509");

    return "Next";
}

sub getRandomDataWindow() 
{
    my $randbits = $bits * 2;

# Get some random data from truerand library
#
    if (!$skip_random) {
	FinishRoot();
	InitRoot(0);
	makerand($randbits,$randfile);
	FinishRoot();

# Get some random data from keystrokes
#
      Newt::Suspend();

      system("$bindir/keyrand $randbits $randfile");
    } else {
      Newt::Suspend();
    }
    return "Next";
}

sub generateKey()
{
    print STDERR "\nPlease wait - generating the key (this may take some time)\n\n";

    # Actually generate the key
    #
    system("$bindir/openssl genrsa -rand $randfile $bits > $keyfile");
    unlink($randfile);
    Newt::Resume();

    if (chmod(0400, $keyfile) != 1) {
        Newt::newtWinMessage("Error", "Close",
                             "Could not set permissions of private key file.\n".
                             "$1 - $keyfile");
        Newt::Finished();
        exit 1;
    }

    return "Skip";
}
