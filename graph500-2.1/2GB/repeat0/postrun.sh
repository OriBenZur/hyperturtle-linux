#! /bin/bash
# graph500 programs validate their results during the run phase.
# validation can be deactivated by specifying skip_validation=1 as an environment variable.
# we only check that the validation finished by looking at the output file.
grep "SCALE: 22" results.txt
