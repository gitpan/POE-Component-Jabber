use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    'NAME'		=> 'POE::Component::Jabber',
    'VERSION_FROM'	=> 'lib/POE/Component/Jabber.pm', # finds $VERSION
    'PREREQ_PM'		=> {
			    XML::Parser		=> '2.29',
			    POE		        => 0,
			    Digest::SHA1	=> '1.03',
			    Jabber::Connection	=> '0.02',
			    }, # e.g., Module::Name => 1.1
);
