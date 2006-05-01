use Module::Build;
Module::Build->new
(
	'module_name' => 'POE::Component::Jabber',
	'license' => 'gpl',
	'create_makefile_pl' => 'passthrough',
	'create_readme' => 1,
	'requires' =>
	{
		'perl'	=>	'5.8.1',
		'POE'	=>	'0.34_01',
		'Filter::Template' => '1.01',
		'Digest::SHA1' => '2.11',
		'Authen::SASL' => '2.10',
		'MIME::Base64' => '3.07',
		'POE::Component::SSLify' => '0.04',
		'POE::Filter::XML' => '0.29',
	}
)->create_build_script();
