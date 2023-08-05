# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected ([<<'EOF']);
(wait-not-child) begin
(child-simple) run
child-simple: exit(81)
child-more: exit(5)
(wait-not-child) wait(exec()) = -1
(wait-not-child) end
wait-not-child: exit(0)
EOF
pass;
