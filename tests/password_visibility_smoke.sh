#!/bin/sh
set -eu

# Login masks the password; reader credentials remain visible for editing.
grep -Fq "id='lp' type='password' name='p'" webif/pages/login.c
grep -Fq "id='rPassword' type='text' autocomplete='off'" webif/pages/readers.c
# Existing admin/user password inputs remain visible text inputs.
grep -Fq "id='cf_webif_pass' type='text'" webif/pages/config.c
grep -Fq "id='em_pass' type='text'" webif/pages/users.c
# Prevent either requested behavior from silently regressing.
if grep -Fq "id='lp' type='text' name='p'" webif/pages/login.c; then
    echo 'FAIL: login password input must be masked' >&2
    exit 1
fi
if grep -Fq "id='rPassword' type='password'" webif/pages/readers.c; then
    echo 'FAIL: reader password input must remain visible' >&2
    exit 1
fi
echo 'password visibility smoke: PASS'
