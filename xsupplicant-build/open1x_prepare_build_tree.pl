#!/usr/bin/perl
# File: open1x_prepare_build_tree.pl
# Author: Terry Simons <galimorerpg@users.sourceforge.net>
# 
# Purpose:
# 
# This script attempts to merge SVN branches automatically so that the 
# resulting source tree can be used to build an Open1x release with arbitrary 
# feature branches.
#
# The script allows definition of a base (trunk) checkout directory and 
# unlimited "feature" branches which the script will attempt to merge into 
# the base tree.
#
# The script attempts to read a configuration file 
# (open1x_build.cfg by default) or the filename specified by the 
# --configuration-file option, if specified.  
#
# Configuration Options:
#
# svn_root    - The root of the SVN repository.
#
#    Example: svn_root=https://open1x.svn.sf.net/svnroot/open1x
#
# base_branch - The "trunk" branch which other branches will be merged to.
#
#    Example: base_branch=trunk
#
# branch_root - The root of the "branches" directory
# 
#    Example: branch_root=branches
#
# <Build> </Build> Directive - Defines a release group.
# 
#    Example: 
#        
#        <Build SeaAnt>
#        </Build>
#
# <AddBranch> Directive - Defines a branch to be added to a release group.
# 
#    Example: 
#
#        <Build SeaAnt>
#            <AddBranch SeaAnt-disconnect-at-logoff>
#              start_revision=43
#              end_revision=HEAD
#            </AddBranch>
#        </Build>
# start_revision - AddBranch suboption which specifies the merge start-point
# end_revision   - AddBranch suboption which specifies the merge end-point
#

use strict;
use warnings;
use Config::General;
use Getopt::Long;
use Data::Dumper;

sub GetReleaseNames;
sub GetBranchesForRelease;
sub CheckoutRelease;

my $config_file = "open1x_build.cfg";

my $result = GetOptions("config=s" => \$config_file);

if(!(-f $config_file)) {
    usage();
}

my $conf = new Config::General(
    -ConfigFile            => $config_file,
    -UseApacheInclude      => 1,
    -ExtendedAccess        => 1,
    -InterPolateEnv        => 1,
    -StrictVars            => 1,
    -StrictObjects         => 1,
    );

foreach my $release_name (GetReleaseNames()) {

    print "Release: $release_name\n";
    my $revision    = CheckoutRelease($release_name);

    my @branch_list = GetBranchListForRelease($release_name);

    # Process any branches that matched the criteria...
    foreach my $branch (@branch_list) {	

	if(AttemptMergeOfBranchWithDryRunForRelease($branch, $release_name) == 1) {

	    print("'$branch' dry-run succeeded...\n");

	    # Now attempt to do a real merge
	    if(MergeWithBranchForRelease($branch, $release_name) == 1) {
		print("'$branch' merge succeeded...\n");
	    } else {
		print("'$branch' merge failed... Aborting.\n");
		exit(-1);
	    }
	    
	} else {
	    # Since we know this branch won't merge cleanly into the trunk, we'll 
	    # skip it...
	    print("'$branch' dry-run failed... Skipping.\n");
	}
    }	 
}

sub CheckoutRelease {
    my ($release_name) = @_;

    my $build_obj   = $conf->obj("Build")->obj($release_name);

    my $base_branch = GetTrunkForRelease($release_name);

    # If it looks like the branch is already checked out
    # issue an svn revert so we can be sure to purge any 
    # local changes 
    if(-d $release_name) {
	print "Purging local changes for existing $release_name directory...\n";

	my $svn_output = `pushd $release_name; svn revert -R *; popd`;
	
	print $svn_output;
    }

    my $svn_command = "svn co $base_branch $release_name";

    print("Checking out branch: $base_branch ($svn_command)\n");

    print `$svn_command`;
}

sub GetStartRevisionForReleaseWithBranch {
    my ($release_name, $branch) = @_;

    return $conf->obj("Build")->obj("$release_name")->obj("AddBranch")->obj("$branch")->value("start_revision");
}

sub GetEndRevisionForReleaseWithBranch {
    my ($release_name, $branch) = @_;

    return $conf->obj("Build")->obj("$release_name")->obj("AddBranch")->obj("$branch")->value("end_revision");
}

sub AttemptMergeOfBranchWithDryRunForRelease {
    my ($branch, $release_name) = @_;

    my $branch_root = GetBranchRootForRelease($release_name);

    my $start_revision = GetStartRevisionForReleaseWithBranch($release_name, $branch);
    my $end_revision   = GetEndRevisionForReleaseWithBranch($release_name, $branch);

    my $svn_command = "cd $release_name; svn merge --dry-run -r${start_revision}:${end_revision} $branch_root/$branch";

    print "Attempting dry-run merge for branch '$branch' ($svn_command)\n";

    my @svn_output = `$svn_command`;

    print @svn_output;

    # Make sure there were no conflicts
    foreach my $line (@svn_output) {

	# If there was a conflict, the dry-run failed.
	if($line =~ /^C/) {
	    return 0;
	}	
    }

    return 1;
}

sub MergeWithBranchForRelease {
    my ($branch, $release_name) = @_;

    my $branch_root = GetBranchRootForRelease($release_name);

    my $start_revision = $conf->obj("Build")->obj($release_name)->obj("AddBranch")->obj($branch)->value("start_revision");
    my $end_revision = $conf->obj("Build")->obj($release_name)->obj("AddBranch")->obj($branch)->value("end_revision");

    my $svn_command = "cd $release_name; svn merge -r${start_revision}:${end_revision} $branch_root/$branch";

    print "Attempting merge for branch '$branch' ($svn_command)\n";
    my @svn_output = `$svn_command`;

    print @svn_output;

    # Make sure there were no conflicts
    foreach my $line (@svn_output) {
	
	# If there was a conflict, the dry-run failed.
	if($line =~ /^C/) {
	    return 0;
	}	
    }
    
    return 1;
}

sub GetTrunkForRelease {
    my ($release_name) = @_;

    # XXX Replace this with a more robust call which can
    # handle global/parameter substitution for vars which 
    # don't have a local-scope defined item.
    return $conf->value("svn_root")."/".$conf->value("base_branch");
}

sub MatchesApplyListForRelease {
    my ($branch, $release_name) = @_;
    
    my @filter_list = $conf->obj("Build")->obj($release_name)->keys("AddBranch");

    foreach my $filter (@filter_list) {
	if($branch =~ /$filter/) {
	    return 1;
	}
    }
    
    return 0;
}

sub GetBranchRootForRelease {
    my ($release_name) = @_;

    # XXX Replace this with a more robust call which can
    # handle global/parameter substitution for vars which 
    # don't have a local-scope defined item.
    return $conf->value("svn_root")."/".$conf->value("branch_root");
}

sub GetBranchListForRelease {
    my ($release_name) = @_;

    my @branch_list = ();

    my $branch_root = GetBranchRootForRelease($release_name);

    my $svn_command = "svn list $branch_root";

    print("Obtaining branch list for '$release_name': ($svn_command)\n");

    my @svn_output = `$svn_command`;

    foreach my $branch (@svn_output) {
	
	# Get rid of any end-line
	chomp $branch;
	
	# Remove the trailing /
	chop $branch;

	if(MatchesApplyListForRelease($branch, $release_name)) {
	    print "Added $branch\n";
	    push(@branch_list, $branch);
	} else {
	    print "Skipped $branch\n";
	}
    }    

    return @branch_list;
}

sub GetReleaseNames {
    return $conf->keys("Build");
}

sub usage {
    print <<EOUSAGE;
Usage: $0 --config-file <config file> 

# This script attempts to merge SVN branches automatically so that the 
# resulting source tree can be used to build an Open1x release with arbitrary 
# feature branches.
#
# The script allows definition of a base (trunk) checkout directory and 
# unlimited "feature" branches which the script will attempt to merge into 
# the base tree.
#
# The script attempts to read a configuration file 
# (open1x_build.cfg by default) or the filename specified by the 
# --configuration-file option, if specified.  
#
# Configuration Options:
#
# svn_root    - The root of the SVN repository.
#
#    Example: svn_root=https://open1x.svn.sf.net/svnroot/open1x
#
# base_branch - The "trunk" branch which other branches will be merged to.
#
#    Example: base_branch=trunk
#
# branch_root - The root of the "branches" directory
# 
#    Example: branch_root=branches
#
# <Build> </Build> Directive - Defines a release group.
# 
#    Example: 
#        
#        <Build SeaAnt>
#        </Build>
#
# <AddBranch> Directive - Defines a branch to be added to a release group.
# 
#    Example: 
#
#        <Build SeaAnt>
#            <AddBranch SeaAnt-disconnect-at-logoff>
#              start_revision=43
#              end_revision=HEAD
#            </AddBranch>
#        </Build>
# start_revision - AddBranch suboption which specifies the merge start-point
# end_revision   - AddBranch suboption which specifies the merge end-point

Author: Terry Simons <galimorerpg\@users.sourceforge.net>
EOUSAGE
}
