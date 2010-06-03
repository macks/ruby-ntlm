require 'mkmf'

$CFLAGS     = '-Wall -O2'
$LDFLAGS    = '-lntlm'

if have_library('ntlm')
  create_makefile('ntlm')
end

