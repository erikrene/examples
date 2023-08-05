# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected ([<<'EOF']);
(seek-beyond) begin
(seek-beyond) 0
(seek-beyond) end
seek-beyond: exit(0)
EOF
pass;
