use ExtUtils::MakeMaker;

my %prereqs = (	
	'POE'=> '0.28_02',
	'POE::Filter::XML' => '0.2',
	'Digest::SHA1' => '2.01',
	'Net::SSLeay' => '1.25',
	'Authen::SASL' => '2.06',
	'MIME::Base64' => '3.01',
);

eval { require ExtUtils::AutoInstall };

if ($@ || $ExtUtils::AutoInstall::VERSION < 0.32) 
{
	warn( 
		"\n",
		"==================================================================\n",
		"\n",
		"PCJ's installer magic requires ExtUtils::AutoInstall. PCJ comes\n",
		"with an older version, but it will not be installed.  You should\n",
		"install the most recent ExtUtils::AutoInstall at your convenience.\n",
		"\n",
		"==================================================================\n",
		"\n",
	);
	
	require lib; lib->import('./install');
	require './install/ExtUtils/AutoInstall.pm';
}

ExtUtils::AutoInstall->import
(
	-version => '0.40',
	-core => [%prereqs],
);

WriteMakefile
(
	'NAME' => 'POE::Component::Jabber',
	'VERSION_FROM' => 'lib/POE/Component/Jabber.pm',
	'PREREQ_PM' => \%prereqs,
);
