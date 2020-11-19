//
//  libsnappy.h
//  ios_7st_test
//
//  Created by bb on 1/20/20.
//  Copyright © 2020 bb. All rights reserved.
//

/* Copyright 2018 Sam Bingner All Rights Reserved
 */

#ifndef _SNAPPY_H
#define _SNAPPY_H

const char **snapshot_list(int dirfd);
bool snapshot_check(int dirfd, const char *name);
char *copySystemSnapshot(void);

#endif
