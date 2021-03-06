#! /usr/bin/env perl
# Copyright 2007-2019 The OpenSSL Project Authors. All Rights Reserved.
# Copyright Nokia 2007-2019
# Copyright Siemens AG 2015-2019
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html
#
# CMP tests by Martin Peylo, Tobias Pankert, and David von Oheimb.

use strict;
use OpenSSL::Test qw/:DEFAULT data_file/;
use OpenSSL::Test::Utils;

setup("test_cmp_lib");

plan skip_all => "This test is not supported in a no-cmp build"
    if disabled("cmp");

plan tests => 1;

ok(run(test(["cmp_lib_test",
             data_file("server.crt"),     data_file("server.pem"),
             data_file("EndEntity1.crt"), data_file("EndEntity2.crt"),
             data_file("Root_CA.crt"),    data_file("Intermediate_CA.crt"),
             data_file("IR_protected.der"),
             data_file("IR_unprotected.der"),
             data_file("IR_rmprotection.der")])));
