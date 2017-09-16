/*
 * Copyright (C) 2017 spreadtrum
 */
#pragma once

#include <stdio.h>
#include <string.h>

#define LOG_TAG "ss_unittest"
#define TLOGE(fmt, ...) \
    fprintf(stderr, "%s: %d: " fmt, LOG_TAG, __LINE__,  ## __VA_ARGS__)
#define TLOGI(fmt, ...) \
        fprintf(stdout, "%s: %d: " fmt, LOG_TAG, __LINE__,  ## __VA_ARGS__)
